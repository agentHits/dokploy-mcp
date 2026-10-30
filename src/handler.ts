import {
  checkEnvToolInput,
  ENV_LAYOUT_PATH,
  findFullEnvField,
  findLayoutProblem,
  isBlindEnvTool,
  parseEnvToolOutput,
} from "./envTools.js";
import type { ToolDefinition } from "./types.js";
import apiClient from "./utils/apiClient.js";
import { getClientConfig } from "./utils/clientConfig.js";
import { createLogger } from "./utils/logger.js";
import { redactSensitive } from "./utils/redactSensitive.js";
import { type FormattedResponse, ResponseFormatter } from "./utils/responseFormatter.js";
import {
  PANEL_REDACTED,
  panelTokenAt,
  REDACTED,
  SECRET_PLACEHOLDERS,
} from "./utils/scrubSecrets.js";

const logger = createLogger("ToolHandler");
const RETRYABLE_STATUS_CODES = new Set([408, 429, 502, 503, 504]);
const FINAL_OPERATION_STATUSES = new Set(["running", "succeeded", "failed"]);
// The panel returns these file bodies base64-encoded with no encoding marker.
const BASE64_CONTENT_PATHS = new Set(["/docker.readContainerFile", "/dockerVolume.readVolumeFile"]);

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

// Request fields whose values must not reach the server log. They apply to the
// logged input only: in a tool result a compose file is scrubbed but stays
// readable, and "variables" or "set" name safe metadata.
const LOG_ONLY_REDACT_FIELDS = ["composeFile", "dockerCompose"];

// The only inputs whose text the panel restores on save: a token left where it
// was keeps the hidden value. Anywhere else a token would be stored literally.
const TOKEN_WRITE_BACK_FIELDS = new Map([
  ["compose-update", "composeFile"],
  ["mounts-update", "content"],
]);

function getLoggedInputRedactFields(tool: ToolDefinition): string[] {
  if (tool.execution?.kind === "compose-env-upsert" || tool.name === "application-env-upsert") {
    return [...LOG_ONLY_REDACT_FIELDS, "variables"];
  }
  if (tool.execution?.kind === "compose-deploy-exact") {
    return [...LOG_ONLY_REDACT_FIELDS, "idempotencyKey"];
  }
  if (tool.execution?.kind === "env-apply") {
    return [...LOG_ONLY_REDACT_FIELDS, "set"];
  }
  return LOG_ONLY_REDACT_FIELDS;
}

function invalidInput(tool: ToolDefinition): FormattedResponse {
  return ResponseFormatter.error(
    `Invalid input for ${tool.name}`,
    "The request did not satisfy the safe recovery contract",
  );
}

function redactedTextWriteBack(tool: ToolDefinition): FormattedResponse {
  return ResponseFormatter.error(
    `Invalid input for ${tool.name}`,
    "The input contains redacted text that cannot be written back. [REDACTED] and the bare __DOKPLOY_REDACTED_SECRET__ stand in for a secret this server never shows and can never be written back: leave the field out to keep the stored value. Tokens of the form __DOKPLOY_REDACTED_SECRET__XXXXXXXXXXXX__ may be sent back unchanged, each where it was, only in a compose file (compose-update, field composeFile) or a file mount (mounts-update, field content): the panel then keeps the hidden value. Never invent or alter a token. To change a secret in a compose file, replace the inline value with a variable reference and set that variable with env-apply.",
  );
}

function fullEnvWriteBlocked(tool: ToolDefinition): FormattedResponse {
  return ResponseFormatter.error(
    `${tool.name} cannot write env fields`,
    "The fields env, buildArgs, buildSecrets, previewEnv, previewBuildArgs and previewBuildSecrets replace a whole variable list that this server never shows, so this tool does not accept them, not even to clear them. Leave them out. Use env-keys to list variable names and env-apply to set, generate, copy or remove individual variables; preview deployment variables can only be edited in the Dokploy panel.",
  );
}

function containsSecretPlaceholder(value: unknown): boolean {
  if (typeof value === "string") {
    return SECRET_PLACEHOLDERS.some((placeholder) => value.includes(placeholder));
  }
  if (Array.isArray(value)) {
    return value.some(containsSecretPlaceholder);
  }
  return isRecord(value) && Object.values(value).some(containsSecretPlaceholder);
}

function hasOnlyRestorableTokens(text: string): boolean {
  if (text.includes(REDACTED)) return false;

  let tokenEnd = 0;
  for (
    let index = text.indexOf(PANEL_REDACTED);
    index !== -1;
    index = text.indexOf(PANEL_REDACTED, index + 1)
  ) {
    const token = panelTokenAt(text, index);
    // A placeholder that starts inside the previous token shares its closing
    // "__", so one of the two is not what the panel issued.
    if (token === undefined || index < tokenEnd) return false;
    tokenEnd = index + token.length;
  }
  return true;
}

function containsForbiddenPlaceholder(tool: ToolDefinition, input: Record<string, unknown>) {
  const restorableField = TOKEN_WRITE_BACK_FIELDS.get(tool.name);
  return Object.entries(input).some(([field, value]) =>
    field === restorableField && typeof value === "string"
      ? !hasOnlyRestorableTokens(value)
      : containsSecretPlaceholder(value),
  );
}

function getHttpStatus(error: unknown): number | undefined {
  if (!isRecord(error) || !isRecord(error.response)) {
    return undefined;
  }
  return typeof error.response.status === "number" ? error.response.status : undefined;
}

function isRetryableTransportError(error: unknown): boolean {
  const status = getHttpStatus(error);
  if (status !== undefined) {
    return RETRYABLE_STATUS_CODES.has(status);
  }
  if (!isRecord(error) || isRecord(error.response)) {
    return false;
  }

  const code = typeof error.code === "string" ? error.code : undefined;
  return "request" in error || code === "ECONNABORTED" || code === "ETIMEDOUT";
}

async function postWithBoundedRetry(
  path: string,
  body: Record<string, unknown>,
  maxAttempts: number,
) {
  let attempt = 0;
  while (attempt < maxAttempts) {
    attempt += 1;
    try {
      return await apiClient.post(path, body);
    } catch (error) {
      if (attempt >= maxAttempts || !isRetryableTransportError(error)) {
        throw error;
      }
    }
  }
  throw new Error("unreachable retry state");
}

function parseRecoveryResponse(tool: ToolDefinition, value: unknown): Record<string, unknown> {
  const parsed = tool.outputSchema?.safeParse(value);
  if (!parsed?.success || !isRecord(parsed.data)) {
    throw new Error("invalid recovery response");
  }
  return parsed.data;
}

async function executeComposeEnvUpsert(
  tool: ToolDefinition,
  input: Record<string, unknown>,
): Promise<Record<string, unknown>> {
  const composeId = input.composeId as string;
  const variables = input.variables as Record<string, string>;
  const dryRun = input.dryRun === true;
  const expectedRevision =
    typeof input.expectedRevision === "string" ? input.expectedRevision : undefined;

  if (dryRun) {
    const previewBody: Record<string, unknown> = {
      composeId,
      variables,
      dryRun: true,
      ...(expectedRevision === undefined ? {} : { expectedRevision }),
    };
    const response = await postWithBoundedRetry(
      tool.path,
      previewBody,
      tool.execution?.maxAttempts ?? 1,
    );
    return parseRecoveryResponse(tool, response.data);
  }

  const previewBody = {
    composeId,
    variables,
    dryRun: true,
    expectedRevision,
  };
  const previewResponse = await postWithBoundedRetry(
    tool.path,
    previewBody,
    tool.execution?.maxAttempts ?? 1,
  );
  const preview = parseRecoveryResponse(tool, previewResponse.data);

  if (
    preview.composeId !== composeId ||
    preview.dryRun !== true ||
    preview.revision !== expectedRevision
  ) {
    throw new Error("invalid conditional preview");
  }

  const writeBody = {
    composeId,
    variables,
    dryRun: false,
    expectedRevision: preview.revision,
  };
  const writeResponse = await apiClient.post(tool.path, writeBody);
  const result = parseRecoveryResponse(tool, writeResponse.data);
  if (result.composeId !== composeId) {
    throw new Error("invalid compose env response identity");
  }
  return result;
}

async function executeExactDeploy(
  tool: ToolDefinition,
  input: Record<string, unknown>,
): Promise<Record<string, unknown>> {
  const body = {
    composeId: input.composeId,
    expectedRevision: input.expectedRevision,
    idempotencyKey: input.idempotencyKey,
  };
  const response = await postWithBoundedRetry(tool.path, body, tool.execution?.maxAttempts ?? 1);
  const result = parseRecoveryResponse(tool, response.data);
  if (result.composeId !== input.composeId || result.sourceRevision !== input.expectedRevision) {
    throw new Error("invalid exact deploy response identity");
  }
  return result;
}

function canRepairReconcile(inspect: Record<string, unknown>): boolean {
  const queue = inspect.queue;
  return (
    isRecord(queue) &&
    queue.state === "queue-empty" &&
    typeof inspect.operationStatus === "string" &&
    !FINAL_OPERATION_STATUSES.has(inspect.operationStatus) &&
    inspect.deployment === null &&
    inspect.repairPerformed === false
  );
}

async function executeDeploymentReconcile(
  tool: ToolDefinition,
  input: Record<string, unknown>,
): Promise<Record<string, unknown>> {
  const inspectBody = {
    composeId: input.composeId,
    operationId: input.operationId,
    repair: false,
  };
  const inspectResponse = await postWithBoundedRetry(
    tool.path,
    inspectBody,
    tool.execution?.maxAttempts ?? 1,
  );
  const inspect = parseRecoveryResponse(tool, inspectResponse.data);

  if (inspect.composeId !== input.composeId || inspect.operationId !== input.operationId) {
    throw new Error("invalid reconcile response identity");
  }

  if (input.repair !== true || !canRepairReconcile(inspect)) {
    return inspect;
  }

  const repairBody = {
    composeId: input.composeId,
    operationId: input.operationId,
    repair: true,
  };
  const repairResponse = await apiClient.post(tool.path, repairBody);
  const repaired = parseRecoveryResponse(tool, repairResponse.data);
  if (repaired.composeId !== input.composeId || repaired.operationId !== input.operationId) {
    throw new Error("invalid reconcile repair response identity");
  }
  return repaired;
}

class EnvInputProblem extends Error {}

async function checkLayoutAgainstPanel(input: Record<string, unknown>) {
  const { scope, id, field } = input;
  const response = await apiClient.get(ENV_LAYOUT_PATH, { params: { scope, id, field } });
  const problem = findLayoutProblem(input, response.data);
  if (problem !== null) throw new EnvInputProblem(problem);
}

async function executeTool(tool: ToolDefinition, input: Record<string, unknown>) {
  switch (tool.execution?.kind) {
    case "compose-env-upsert":
      return executeComposeEnvUpsert(tool, input);
    case "compose-deploy-exact":
      return executeExactDeploy(tool, input);
    case "deployment-reconcile":
      return executeDeploymentReconcile(tool, input);
    case "env-keys": {
      const { layout, ...params } = input;
      const response = await apiClient.get(layout === true ? ENV_LAYOUT_PATH : tool.path, {
        params,
      });
      return parseEnvToolOutput(tool, input, response.data);
    }
    case "env-apply": {
      if (Array.isArray(input.layout)) {
        await checkLayoutAgainstPanel(input);
      }
      const response = await apiClient.post(tool.path, input);
      return parseEnvToolOutput(tool, input, response.data);
    }
    default: {
      const response =
        tool.method === "GET"
          ? await apiClient.get(tool.path, { params: input })
          : await apiClient.post(tool.path, input);
      return response.data;
    }
  }
}

function conflictDetails(tool: ToolDefinition): string {
  if (tool.execution?.kind === "compose-env-upsert") {
    return "The compose env revision is stale or changed concurrently. Call compose_env_upsert with dryRun=true and no expectedRevision to get the current revision, then retry with it.";
  }
  if (tool.execution?.kind === "env-apply") {
    return "The env revision is stale or the variables changed concurrently. Call env-keys to get the current revision, then retry with it.";
  }
  return "The operation state changed; inspect or preview again before retrying";
}

export function createHandler(tool: ToolDefinition) {
  return async (rawInput: Record<string, unknown>) => {
    if (containsForbiddenPlaceholder(tool, rawInput)) {
      return redactedTextWriteBack(tool);
    }

    let input = rawInput;
    if (isBlindEnvTool(tool)) {
      const checked = checkEnvToolInput(tool.execution.kind, rawInput);
      if (!checked.ok) {
        return ResponseFormatter.error(`Invalid input for ${tool.name}`, checked.problem);
      }
      input = checked.input;
    } else if (findFullEnvField(rawInput) !== undefined) {
      return fullEnvWriteBlocked(tool);
    } else if (tool.execution) {
      const parsedInput = tool.schema.safeParse(rawInput);
      if (!parsedInput.success || !isRecord(parsedInput.data)) {
        return invalidInput(tool);
      }
      input = parsedInput.data;

      if (
        tool.execution.kind === "compose-env-upsert" &&
        input.dryRun !== true &&
        (typeof input.expectedRevision !== "string" || input.expectedRevision.length === 0)
      ) {
        return invalidInput(tool);
      }
    }

    const { extraRedactFields } = getClientConfig();
    const loggedInputFields = [...extraRedactFields, ...getLoggedInputRedactFields(tool)];

    try {
      logger.info(`Executing tool: ${tool.name}`, {
        input: redactSensitive(input, loggedInputFields),
      });
      const data = await executeTool(tool, input);
      return ResponseFormatter.success(
        `${tool.name} completed successfully`,
        redactSensitive(data, extraRedactFields, {
          base64Content: BASE64_CONTENT_PATHS.has(tool.path),
        }),
      );
    } catch (error) {
      if (error instanceof EnvInputProblem) {
        return ResponseFormatter.error(`Invalid input for ${tool.name}`, error.message);
      }
      const status = getHttpStatus(error);
      logger.error(`Tool execution failed: ${tool.name}`, {
        ...(status === undefined ? {} : { status }),
      });

      if (status === 401) {
        return ResponseFormatter.error(
          `Authentication failed for ${tool.name}`,
          "Please check your DOKPLOY_API_KEY configuration",
        );
      }
      if (status === 404) {
        return ResponseFormatter.error(
          "Resource not found",
          isBlindEnvTool(tool)
            ? `The requested resource for ${tool.name} could not be found. Check scope and id; a Dokploy version without the blind env API also answers this way, and for a layout one without GET /env.layout.`
            : `The requested resource for ${tool.name} could not be found`,
        );
      }
      if (status === 409) {
        return ResponseFormatter.error(
          `Conflict while executing ${tool.name}`,
          conflictDetails(tool),
        );
      }

      if (status === 400 && tool.execution?.kind === "env-apply" && Array.isArray(input.layout)) {
        return ResponseFormatter.error(
          `Failed to execute ${tool.name}`,
          "The panel rejected the layout with status 400: in the new order dotenv would read a value differently, or the text cannot be rearranged safely. Nothing was changed. Ask the user to rearrange it in the Dokploy panel.",
        );
      }
      return ResponseFormatter.error(
        `Failed to execute ${tool.name}`,
        status === undefined
          ? "The Dokploy API request failed"
          : `The Dokploy API request failed with status ${status}`,
      );
    }
  };
}
