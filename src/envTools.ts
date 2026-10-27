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
// Zod checks .max() before it parses the elements, so an oversized list is
// rejected with one issue instead of one per element (GHSA-mrhx-c7xc-m3w5).
const MAX_INPUT_LIST_ITEMS = 1000;

/** Read with env-keys when layout=true, and before every env-apply layout. */
export const ENV_LAYOUT_PATH = "/env.layout";

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

const envKeysSchema = z.object({
  ...targetShape,
  layout: z
    .boolean()
    .optional()
    .describe(
      "Also return 'layout': the file order of variables, comments, blank lines and hidden lines, which env-apply 'layout' rewrites.",
    ),
});

// dotenv also reads names with dots and dashes, so a layout has to be able to
// place them even though env-apply cannot create them.
const layoutNameSchema = z.string().regex(/^[\w.-]+$/);
const commentRefSchema = z.string().regex(/^c[1-9][0-9]*$/);
const hiddenRefSchema = z.string().regex(/^h[1-9][0-9]*$/);
const commentTextSchema = z
  .string()
  .max(500)
  .regex(/^[^\n\r\u2028\u2029]*$/);

const layoutInputItemSchema = z.discriminatedUnion("type", [
  z.object({ type: z.literal("variable"), name: layoutNameSchema }),
  z.object({
    type: z.literal("comment"),
    ref: commentRefSchema
      .optional()
      .describe("Ref of an existing comment. Leave it out to add a new comment line."),
    text: commentTextSchema
      .optional()
      .describe(
        "Comment text without the leading '# '. With a ref it replaces that comment; without one it adds a line.",
      ),
  }),
  z.object({ type: z.literal("hidden"), ref: hiddenRefSchema }),
  z.object({ type: z.literal("blank") }),
]);

const layoutItemSchema = z.discriminatedUnion("type", [
  z.object({ type: z.literal("variable"), name: z.string() }),
  z.object({ type: z.literal("comment"), ref: z.string(), text: z.string() }),
  z.object({
    type: z.literal("hidden"),
    ref: z.string(),
    kind: z.enum(["comment", "overridden", "unreadable"]),
    variable: z.string().optional(),
  }),
  z.object({ type: z.literal("blank") }),
]);

const envApplySchema = z.object({
  ...targetShape,
  set: z
    .record(nameSchema, z.string())
    .optional()
    .describe(
      "Variables to create or overwrite, as name -> value. Only for values you already know; never ask the user to paste a secret into the chat.",
    ),
  remove: z
    .array(nameSchema)
    .max(MAX_INPUT_LIST_ITEMS)
    .optional()
    .describe("Names of variables to delete."),
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
  layout: z
    .array(layoutInputItemSchema)
    .max(MAX_INPUT_LIST_ITEMS)
    .optional()
    .describe(
      "The whole new order of the text, edited from the 'layout' of env-keys with layout=true: move items, add comments and blank lines. Values are not touched. Sent alone, with expectedRevision.",
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
  layout: z.array(layoutItemSchema).optional(),
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
  layout: z.array(layoutItemSchema).optional(),
});

type EnvKeysInput = z.infer<typeof envKeysSchema>;
type EnvApplyInput = z.infer<typeof envApplySchema>;
type LayoutItem = z.infer<typeof layoutItemSchema>;
type LayoutInputItem = z.infer<typeof layoutInputItemSchema>;
type EnvToolKind = "env-keys" | "env-apply";

export const envKeysTool: ToolDefinition = {
  name: "env-keys",
  description:
    "List the env variable names of a Dokploy service, project or environment. Values are never returned: each variable has only its name, a 'secret' flag (the panel treats it as a credential) and an 'empty' flag. Use this instead of reading 'env' from other tools, where it is always redacted. 'field' selects 'env' (default) or, for applications only, 'buildArgs' or 'buildSecrets'. The returned 'revision' can be passed to env-apply as expectedRevision. To change variables use env-apply. With layout=true the result also has 'layout', the text from top to bottom: {type:'variable', name}, {type:'comment', ref, text} (text without the leading '# '), {type:'blank'} and {type:'hidden', ref, kind} for a line whose text is withheld because it could hold a value: kind 'comment' (for example a commented-out assignment, named in 'variable'), 'overridden' (an earlier assignment of 'variable' that a later one overrides) or 'unreadable' (text dotenv cannot read). Inline comments after a value are part of the variable and are not shown.",
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
    "Change env variables of a Dokploy service, project or environment without seeing any value. Values are write-only and are never returned; call env-keys to see which variables exist. Every variable not named in the call is kept as it is. Operations, each keyed by variable name, and a name may appear in only one of them: 'set' writes a value you already know (non-secret settings); 'generate' creates a new random secret on the server (use it for new passwords, tokens and keys); 'copy' reuses the value of a variable from another service, project or environment without revealing it (use it to share an existing secret); 'remove' deletes variables. 'layout' adds comments and arranges the variables into sections without touching any value: call env-keys with layout=true, edit its 'layout' list and send the whole list back with that call's revision as expectedRevision, alone, without set, remove, generate or copy. Move 'variable' items; add {type:'comment', text} lines, for example a section header '=== Database ===' above its variables and a note right above a variable; change a comment by keeping its ref with a new text; drop a shown comment by leaving it out; add {type:'blank'} between sections. Every variable and every hidden line has to stay in the list exactly once (hidden lines can be moved but not dropped), and an 'overridden' hidden line has to stay above its variable. To add a new variable into a section, create it with 'set', 'generate' or 'copy' first, then rearrange. When a real secret must come from the user (an external API key, a third-party password), do not ask the user to paste it into the chat: ask them to enter it in the Dokploy panel UI on the Environment tab of the service, then confirm with env-keys. 'dryRun' previews the result, and 'expectedRevision' (from env-keys) rejects the write if the variables changed meanwhile. Changes take effect only after a redeploy: application-redeploy or application-deploy, compose-redeploy or compose-deploy, or postgres-deploy, mysql-deploy, mariadb-deploy, mongo-deploy, redis-deploy, libsql-deploy; for scope 'project' or 'environment' redeploy the services that use the variable.",
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
    return schema !== undefined && !schema.safeParse(undefined).success;
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
  "Provide at least one variable in set, remove, generate or copy, or a layout. To only look at the variables, call env-keys.";
const LAYOUT_ALONE =
  "Send layout alone: change variables with set, remove, generate or copy in one call, then call env-keys with layout=true and send the edited layout in the next call.";
const LAYOUT_NEEDS_REVISION =
  "A layout needs expectedRevision: pass the revision of the env-keys call (with layout=true) that the layout was edited from.";
const COMMENT_NEEDS_TEXT_OR_REF = "Each comment item of a layout needs a text, a ref or both.";

function findLayoutShapeProblem(input: EnvApplyInput, operations: string[][]): string | null {
  if (operations.some((names) => names.length > 0)) return LAYOUT_ALONE;
  if (!input.expectedRevision) return LAYOUT_NEEDS_REVISION;
  const emptyComment = input.layout?.some(
    (item) => item.type === "comment" && item.ref === undefined && item.text === undefined,
  );
  return emptyComment ? COMMENT_NEEDS_TEXT_OR_REF : null;
}

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
  if (input.layout !== undefined) return findLayoutShapeProblem(input, operations);
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

const listNames = (names: Iterable<string>) => [...names].join(", ");

function compareLayouts(current: LayoutItem[], layout: LayoutInputItem[]): string | null {
  const names = new Set<string>();
  const commentRefs = new Set<string>();
  const hidden = new Map<string, LayoutItem & { type: "hidden" }>();
  for (const item of current) {
    if (item.type === "variable") names.add(item.name);
    else if (item.type === "comment") commentRefs.add(item.ref);
    else if (item.type === "hidden") hidden.set(item.ref, item);
  }

  const namePositions = new Map<string, number>();
  const refPositions = new Map<string, number>();
  const unknownNames = new Set<string>();
  const repeatedNames = new Set<string>();
  const unknownRefs = new Set<string>();
  const repeatedRefs = new Set<string>();
  layout.forEach((item, index) => {
    if (item.type === "variable") {
      if (!names.has(item.name)) unknownNames.add(item.name);
      else if (namePositions.has(item.name)) repeatedNames.add(item.name);
      else namePositions.set(item.name, index);
      return;
    }
    const ref = item.type === "comment" || item.type === "hidden" ? item.ref : undefined;
    if (ref === undefined) return;
    const known = item.type === "comment" ? commentRefs.has(ref) : hidden.has(ref);
    if (!known) unknownRefs.add(ref);
    else if (refPositions.has(ref)) repeatedRefs.add(ref);
    else refPositions.set(ref, index);
  });

  const missingNames = [...names].filter((name) => !namePositions.has(name));
  const missingHidden = [...hidden.keys()].filter((ref) => !refPositions.has(ref));
  const misplaced = [...hidden.values()]
    .filter(
      (item) =>
        item.kind === "overridden" &&
        item.variable !== undefined &&
        (refPositions.get(item.ref) ?? -1) >
          (namePositions.get(item.variable) ?? Number.POSITIVE_INFINITY),
    )
    .map((item) => `${item.ref} (${item.variable})`);
  const problems = [
    unknownNames.size > 0 &&
      `The layout names variables that do not exist: ${listNames(unknownNames)}.`,
    repeatedNames.size > 0 &&
      `The layout places variables more than once: ${listNames(repeatedNames)}.`,
    missingNames.length > 0 &&
      `The layout leaves out variables: ${listNames(missingNames)}. Every variable has to be placed; delete one with remove instead.`,
    unknownRefs.size > 0 &&
      `The layout refers to lines that do not exist: ${listNames(unknownRefs)}.`,
    repeatedRefs.size > 0 && `The layout places lines more than once: ${listNames(repeatedRefs)}.`,
    missingHidden.length > 0 &&
      `The layout leaves out hidden lines: ${listNames(missingHidden)}. Their text is not shown, so they can be moved but not dropped.`,
    misplaced.length > 0 &&
      `These hidden lines are earlier assignments of a variable and have to stay above it: ${listNames(misplaced)}.`,
  ].filter((problem): problem is string => typeof problem === "string");
  return problems.length > 0 ? problems.join(" ") : null;
}

/**
 * Checks the layout of an env-apply input against the current layout from
 * GET /env.layout. The panel runs the same checks, but its error text is never
 * passed on, so the model would only learn that the request failed. Problems
 * name variables and refs, never a value.
 */
export function findLayoutProblem(
  input: Record<string, unknown>,
  currentData: unknown,
): string | null {
  const target = { scope: input.scope, id: input.id, field: input.field, layout: true };
  const current = envKeysOutputSchema.parse(parseEnvToolOutput(envKeysTool, target, currentData));
  // On a stale revision the panel answers 409, which tells the model to read
  // the layout again; problems found against a newer text would only confuse.
  if (current.revision !== input.expectedRevision) return null;
  return compareLayouts(current.layout ?? [], input.layout as LayoutInputItem[]);
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
  const layoutRequested = input.layout === true || Array.isArray(input.layout);
  if (layoutRequested && output.layout === undefined) {
    throw new Error("invalid env layout response");
  }
  return output;
}
