import { isSensitiveFlag, REDACTED, redactValue, scrubSecrets } from "./scrubSecrets.js";

export const BASELINE_REDACTED_FIELDS: readonly string[] = [
  "env",
  "buildArgs",
  "buildSecrets",
  "previewBuildSecrets",
  "previewEnv",
  "previewBuildArgs",
  "password",
  "currentPassword",
  "appPassword",
  "databasePassword",
  "databaseRootPassword",
  "redisPassword",
  "mariadbPassword",
  "mongoPassword",
  "mysqlPassword",
  "postgresPassword",
  "registryPassword",
  "token",
  "accessToken",
  "appToken",
  "apiToken",
  "botToken",
  "refreshToken",
  "metricsToken",
  "secret",
  "clientSecret",
  "webhookSecret",
  "githubClientSecret",
  "githubWebhookSecret",
  "apiKey",
  "secretKey",
  "secretAccessKey",
  "accessKey",
  "applicationKey",
  "consumerKey",
  "licenseKey",
  "userKey",
  "privateKey",
  "privateKeyPass",
  "encPrivateKey",
  "encPrivateKeyPass",
  "githubPrivateKey",
  "sshKey",
  "sshPrivateKey",
  "customGitSSHKey",
  "dockerAuth",
  "authorization",
  "cookie",
  "credentials",
  "connectionString",
  "dsn",
  "webhookUrl",
];

// Only these fields hold variable lists, so only they may keep the variable
// names. Under any other sensitive field a "NAME=" prefix can be the secret
// itself: a base64 token ending in "=" has exactly that shape.
const ENV_SHAPED_FIELDS = ["env", "buildArgs", "buildSecrets"];

const BASELINE_SUFFIXES = BASELINE_REDACTED_FIELDS.map(normalizeName);
const ENV_SHAPED_SUFFIXES = ENV_SHAPED_FIELDS.map(normalizeName);

const ENV_ASSIGNMENT = /^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_.-]*)\s*=\s*(.*)$/;
const ENV_ITEM = /^([A-Za-z_][A-Za-z0-9_.-]*)=([\s\S]*)$/;
const BASE64 = /^[A-Za-z0-9+/]*={0,2}$/;
const BASE64_MARKER_KEYS = ["encoding", "contentEncoding", "content_encoding"];
const BASE64_FLAG_KEYS = ["isBase64", "base64", "base64Encoded"];
const TEXT_CONTROL_CODES = new Set([9, 10, 11, 12, 13, 27]);

export interface RedactOptions {
  /** The response root is `{ content }` holding a base64 file body with no encoding marker. */
  base64Content?: boolean;
}

interface WalkContext {
  suffixes: string[];
  copies: Map<object, unknown>;
}

/**
 * Removes secret values from a tool response or a logged tool input. The
 * baseline field list always applies; `extraFields` can only add to it.
 */
export function redactSensitive<T>(
  data: T,
  extraFields: readonly string[] = [],
  options: RedactOptions = {},
): T {
  const context: WalkContext = {
    suffixes: [...BASELINE_SUFFIXES, ...extraFields.map(normalizeName)],
    copies: new Map(),
  };
  if (options.base64Content === true && isPlainObject(data)) {
    return redactObject(data, context, true) as T;
  }
  return walk(data, context) as T;
}

// api_key, API-KEY and apiKey are the same field in different conventions.
function normalizeName(name: string): string {
  return name.toLowerCase().replace(/[_-]/g, "");
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  if (value === null || typeof value !== "object") return false;
  const proto = Object.getPrototypeOf(value);
  return proto === Object.prototype || proto === null;
}

function isUnsafeKey(key: string): boolean {
  return key === "__proto__" || key === "constructor" || key === "prototype";
}

function endsWithAny(key: string, suffixes: string[]): boolean {
  return suffixes.some((suffix) => key.endsWith(suffix));
}

function closesQuote(text: string, from: number, quote: string): boolean {
  for (let i = from; i < text.length; i++) {
    if (text[i] === "\\" && quote === '"') {
      i++;
    } else if (text[i] === quote) {
      return true;
    }
  }
  return false;
}

function redactEnvText(text: string): string {
  const lines = text.split(/\r?\n/);
  const variables: string[] = [];

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i] ?? "";
    const trimmed = line.trim();
    if (trimmed === "" || trimmed.startsWith("#")) continue;

    const match = ENV_ASSIGNMENT.exec(line);
    if (!match) return REDACTED;
    const [, name, value = ""] = match;
    variables.push(value === "" ? `${name}=` : `${name}=${REDACTED}`);

    const quote = value[0];
    if ((quote === '"' || quote === "'" || quote === "`") && !closesQuote(value, 1, quote)) {
      do {
        i++;
      } while (i < lines.length && !closesQuote(lines[i] ?? "", 0, quote));
    }
  }

  return variables.length === 0 ? REDACTED : variables.join("\n");
}

function redactEnvItems(items: unknown[]): unknown {
  const redacted: string[] = [];
  for (const item of items) {
    const match = typeof item === "string" ? ENV_ITEM.exec(item) : null;
    if (!match) return REDACTED;
    redacted.push(match[2] === "" ? `${match[1]}=` : `${match[1]}=${REDACTED}`);
  }
  return redacted;
}

function redactMapValues(map: Record<string, unknown>): Record<string, unknown> {
  const out: Record<string, unknown> = Object.create(null);
  for (const [key, value] of Object.entries(map)) {
    if (isUnsafeKey(key)) continue;
    out[key] = value === null || value === undefined || value === "" ? value : REDACTED;
  }
  return out;
}

function redactUnderSensitiveKey(value: unknown, keepsNames: boolean): unknown {
  if (typeof value === "string") {
    if (value === "") return value;
    return keepsNames ? redactEnvText(value) : REDACTED;
  }
  if (Array.isArray(value)) {
    if (value.length === 0) return value;
    return keepsNames ? redactEnvItems(value) : REDACTED;
  }
  if (isPlainObject(value)) return redactMapValues(value);
  if (value !== null && typeof value === "object") return REDACTED;
  return value;
}

function hasBase64Marker(record: Record<string, unknown>): boolean {
  return (
    BASE64_MARKER_KEYS.some((key) => {
      const marker = record[key];
      return typeof marker === "string" && marker.trim().toLowerCase() === "base64";
    }) || BASE64_FLAG_KEYS.some((key) => record[key] === true)
  );
}

function looksBinary(text: string): boolean {
  for (let i = 0; i < text.length; i++) {
    const code = text.charCodeAt(i);
    if (code < 32 && !TEXT_CONTROL_CODES.has(code)) return true;
  }
  return false;
}

function decodeBase64Text(value: string): string | null {
  const compact = value.replace(/\s+/g, "");
  if (compact.length % 4 !== 0 || !BASE64.test(compact)) return null;

  let text: string;
  try {
    // `stream` tolerates a multi-byte character cut in half by the panel's
    // size limit; any other invalid sequence still throws.
    text = new TextDecoder("utf-8", { fatal: true }).decode(Buffer.from(compact, "base64"), {
      stream: true,
    });
  } catch {
    return null;
  }
  return looksBinary(text) ? null : text;
}

function scrubBase64Content(value: string): string {
  if (value === "") return value;
  const text = decodeBase64Text(value);
  return text === null ? REDACTED : Buffer.from(scrubSecrets(text), "utf8").toString("base64");
}

function redactObject(
  value: Record<string, unknown>,
  context: WalkContext,
  base64Content: boolean,
): unknown {
  const out: Record<string, unknown> = Object.create(null);
  context.copies.set(value, out);
  const contentIsBase64 = base64Content || hasBase64Marker(value);

  for (const [key, val] of Object.entries(value)) {
    if (isUnsafeKey(key)) continue;
    const name = normalizeName(key);
    if (endsWithAny(name, context.suffixes)) {
      out[key] = redactUnderSensitiveKey(val, endsWithAny(name, ENV_SHAPED_SUFFIXES));
    } else if (contentIsBase64 && key === "content" && typeof val === "string") {
      out[key] = scrubBase64Content(val);
    } else {
      out[key] = walk(val, context);
    }
  }
  return out;
}

function redactArray(value: unknown[], context: WalkContext): unknown {
  const out: unknown[] = [];
  context.copies.set(value, out);
  for (const item of value) {
    out.push(walk(item, context));
  }

  // A secret passed as its own argv element ("--password", "value") has no
  // flag next to it in the same string, so the text rules cannot see it.
  for (let i = 0; i + 1 < value.length; i++) {
    const flag = value[i];
    const argument = value[i + 1];
    if (
      typeof flag === "string" &&
      typeof argument === "string" &&
      isSensitiveFlag(flag) &&
      !argument.startsWith("-")
    ) {
      out[i + 1] = redactValue(argument);
    }
  }
  return out;
}

function walk(value: unknown, context: WalkContext): unknown {
  if (typeof value === "string") return scrubSecrets(value);
  if (value === null || typeof value !== "object") return value;

  const copy = context.copies.get(value);
  if (copy !== undefined) return copy;
  if (Array.isArray(value)) return redactArray(value, context);
  if (isPlainObject(value)) return redactObject(value, context, false);
  return value;
}
