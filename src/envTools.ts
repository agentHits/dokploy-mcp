import { z } from "zod";
import type { ToolDefinition } from "./types.js";

/** Fields that carry a whole env text and therefore replace every variable at once. */
export const FULL_ENV_FIELDS = [
  "env",
  "buildArgs",
  "buildSecrets",
  "previewEnv",
  "previewBuildArgs",
  "previewBuildSecrets",
] as const;

const SCOPES = [
  "application",
  "compose",
  "postgres",
  "mysql",
  "mariadb",
  "mongo",
  "redis",
  "libsql",
  "project",
  "environment",
] as const;
const FIELDS = ["env", "buildArgs", "buildSecrets"] as const;
const DEFAULT_FIELD = "env";

const scopeSchema = z.enum(SCOPES);
const fieldSchema = z.enum(FIELDS);
const nameSchema = z.string().regex(/^[A-Za-z_][A-Za-z0-9_]*$/);
const idSchema = z.string().min(1);

const targetShape = {
  scope: scopeSchema.describe(
    "What owns the variables: a service type, or 'project' / 'environment' for variables shared by their services.",
  ),
  id: idSchema.describe(
    "ID of that service, project or environment (applicationId, composeId, postgresId, projectId, environmentId and so on).",
  ),
  field: fieldSchema
    .optional()
    .describe(
      "Which variable list to use. Defaults to 'env'. 'buildArgs' and 'buildSecrets' exist only for scope 'application'.",
    ),
};

const envKeysSchema = z.object(targetShape);

const envApplySchema = z.object({
  ...targetShape,
  set: z
    .record(nameSchema, z.string())
    .optional()
    .describe(
      "Variables to create or overwrite, as name -> value. Only for values you already know; never ask the user to paste a secret into the chat.",
    ),
  remove: z.array(nameSchema).optional().describe("Names of variables to delete."),
  generate: z
    .record(
      nameSchema,
      z.object({
        length: z
          .number()
          .int()
          .min(16)
          .max(128)
          .optional()
          .describe("Length of the generated value, 16 to 128. Defaults to 48."),
        format: z.enum(["base64url", "hex", "alphanumeric"]).optional(),
      }),
    )
    .optional()
    .describe(
      "Variables to fill with a new random secret created on the server, as name -> options ({} for the defaults). The value is never returned.",
    ),
  copy: z
    .record(
      nameSchema,
      z.object({
        fromScope: scopeSchema,
        fromId: idSchema,
        fromField: fieldSchema.optional(),
        fromName: nameSchema,
      }),
    )
    .optional()
    .describe(
      "Variables to fill with the value of a variable that already exists elsewhere, as name -> source. The value is copied on the server and never returned.",
    ),
  dryRun: z.boolean().optional().describe("Preview the result without saving anything."),
  expectedRevision: z
    .string()
    .optional()
    .describe(
      "Revision returned by env-keys or a previous env-apply. The write is rejected if the variables changed since then.",
    ),
});

const envKeysOutputSchema = z.object({
  scope: scopeSchema,
  id: z.string(),
  field: fieldSchema,
  revision: z.string(),
  variables: z.array(z.object({ name: z.string(), secret: z.boolean(), empty: z.boolean() })),
});

const envApplyOutputSchema = z.object({
  scope: scopeSchema,
  id: z.string(),
  field: fieldSchema,
  changed: z.boolean(),
  revision: z.string(),
  dryRun: z.boolean(),
  variables: z.array(
    z.object({
      name: z.string(),
      action: z.enum(["created", "updated", "unchanged", "removed", "missing"]),
      source: z.enum(["set", "generate", "copy", "remove"]),
      secret: z.boolean(),
    }),
  ),
});

type EnvKeysInput = z.infer<typeof envKeysSchema>;
type EnvApplyInput = z.infer<typeof envApplySchema>;
type EnvToolKind = "env-keys" | "env-apply";

export const envKeysTool: ToolDefinition = {
  name: "env-keys",
  description:
    "List the env variable names of a Dokploy service, project or environment. Values are never returned: each variable has only its name, a 'secret' flag (the panel treats it as a credential) and an 'empty' flag. Use this instead of reading 'env' from other tools, where it is always redacted. 'field' selects 'env' (default) or, for applications only, 'buildArgs' or 'buildSecrets'. The returned 'revision' can be passed to env-apply as expectedRevision. To change variables use env-apply.",
  tag: "env",
  method: "GET",
  path: "/env.keys",
  schema: envKeysSchema,
  annotations: {
    title: "Env Keys",
    readOnlyHint: true,
    idempotentHint: true,
    openWorldHint: true,
  },
  execution: { kind: "env-keys", maxAttempts: 1 },
  outputSchema: envKeysOutputSchema,
};

export const envApplyTool: ToolDefinition = {
  name: "env-apply",
  description:
    "Change env variables of a Dokploy service, project or environment without seeing any value. Values are write-only and are never returned; call env-keys to see which variables exist. Every variable not named in the call is kept as it is. Operations, each keyed by variable name, and a name may appear in only one of them: 'set' writes a value you already know (non-secret settings); 'generate' creates a new random secret on the server (use it for new passwords, tokens and keys); 'copy' reuses the value of a variable from another service, project or environment without revealing it (use it to share an existing secret); 'remove' deletes variables. When a real secret must come from the user (an external API key, a third-party password), do not ask the user to paste it into the chat: ask them to enter it in the Dokploy panel UI on the Environment tab of the service, then confirm with env-keys. 'dryRun' previews the result, and 'expectedRevision' (from env-keys) rejects the write if the variables changed meanwhile. Changes take effect only after a redeploy: application-redeploy or application-deploy, compose-redeploy or compose-deploy, or postgres-deploy, mysql-deploy, mariadb-deploy, mongo-deploy, redis-deploy, libsql-deploy; for scope 'project' or 'environment' redeploy the services that use the variable.",
  tag: "env",
  method: "POST",
  path: "/env.apply",
  schema: envApplySchema,
  annotations: {
    title: "Env Apply",
    destructiveHint: true,
    openWorldHint: true,
  },
  execution: { kind: "env-apply", maxAttempts: 1 },
  outputSchema: envApplyOutputSchema,
};

export function isBlindEnvTool(
  tool: ToolDefinition,
): tool is ToolDefinition & { execution: { kind: EnvToolKind } } {
  return tool.execution?.kind === "env-keys" || tool.execution?.kind === "env-apply";
}

/**
 * A tool whose schema requires a full env text can never be called: the handler
 * rejects every input that carries one. Such tools are left out of the tool list.
 */
export function requiresFullEnvText(tool: ToolDefinition): boolean {
  return FULL_ENV_FIELDS.some((field) => {
    const schema = tool.schema.shape[field];
    return schema !== undefined && !schema.isOptional();
  });
}

export function findFullEnvField(input: Record<string, unknown>): string | undefined {
  return FULL_ENV_FIELDS.find((field) => input[field] !== undefined);
}

const INVALID_SHAPE =
  "The input does not match the tool schema. Variable names must match ^[A-Za-z_][A-Za-z0-9_]*$.";
const FIELD_NEEDS_APPLICATION =
  "field 'buildArgs' and 'buildSecrets' exist only for scope 'application'.";
const COPY_FIELD_NEEDS_APPLICATION =
  "copy fromField 'buildArgs' and 'buildSecrets' exist only for fromScope 'application'.";
const NO_OPERATION =
  "Provide at least one variable in set, remove, generate or copy. To only look at the variables, call env-keys.";

function isApplicationOnlyField(scope: string, field: string | undefined): boolean {
  return field !== undefined && field !== DEFAULT_FIELD && scope !== "application";
}

function findEnvApplyProblem(input: EnvApplyInput): string | null {
  if (isApplicationOnlyField(input.scope, input.field)) return FIELD_NEEDS_APPLICATION;

  const operations = [
    Object.keys(input.set ?? {}),
    input.remove ?? [],
    Object.keys(input.generate ?? {}),
    Object.keys(input.copy ?? {}),
  ];
  if (operations.every((names) => names.length === 0)) return NO_OPERATION;

  const seen = new Set<string>();
  const repeated = new Set<string>();
  for (const names of operations) {
    for (const name of new Set(names)) {
      if (seen.has(name)) repeated.add(name);
      seen.add(name);
    }
  }
  if (repeated.size > 0) {
    return `Each variable name may appear in only one of set, remove, generate and copy. Repeated: ${[...repeated].join(", ")}.`;
  }

  const copiesFromMissingField = Object.values(input.copy ?? {}).some((source) =>
    isApplicationOnlyField(source.fromScope, source.fromField),
  );
  return copiesFromMissingField ? COPY_FIELD_NEEDS_APPLICATION : null;
}

export type EnvInputCheck =
  | { ok: true; input: Record<string, unknown> }
  | { ok: false; problem: string };

/** Validates a blind env tool call. Problems are fixed texts that never quote a value. */
export function checkEnvToolInput(kind: EnvToolKind, rawInput: unknown): EnvInputCheck {
  if (kind === "env-keys") {
    const parsed = envKeysSchema.safeParse(rawInput);
    if (!parsed.success) return { ok: false, problem: INVALID_SHAPE };
    const input: EnvKeysInput = parsed.data;
    return isApplicationOnlyField(input.scope, input.field)
      ? { ok: false, problem: FIELD_NEEDS_APPLICATION }
      : { ok: true, input };
  }

  const parsed = envApplySchema.safeParse(rawInput);
  if (!parsed.success) return { ok: false, problem: INVALID_SHAPE };
  const problem = findEnvApplyProblem(parsed.data);
  return problem === null ? { ok: true, input: parsed.data } : { ok: false, problem };
}

/**
 * Keeps only the fields of the output schema and checks that the panel answered
 * for the target that was asked about.
 */
export function parseEnvToolOutput(
  tool: ToolDefinition,
  input: Record<string, unknown>,
  data: unknown,
): Record<string, unknown> {
  const schema = tool.execution?.kind === "env-keys" ? envKeysOutputSchema : envApplyOutputSchema;
  const parsed = schema.safeParse(data);
  if (!parsed.success) {
    throw new Error("invalid env response");
  }
  const output = parsed.data;
  if (
    output.scope !== input.scope ||
    output.id !== input.id ||
    output.field !== (input.field ?? DEFAULT_FIELD)
  ) {
    throw new Error("invalid env response identity");
  }
  return output;
}
