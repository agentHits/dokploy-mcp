import { redactSensitive } from "../src/utils/redactSensitive.js";
import { isSecretPlaceholder, REDACTED, scrubSecrets } from "../src/utils/scrubSecrets.js";

const ENV_DUMP_MIN_LINES = 3;
const ENV_LINE =
  /^([ \t]*(?:export[ \t]+|declare[ \t]+-[A-Za-z-]+[ \t]+)?[A-Za-z_][A-Za-z0-9_]*=)(.*?)(\r?)$/;
// A logfmt line (time="..." level=info msg="...") starts like an assignment but
// is a log record: without this exception every log line would lose its text.
const LOGFMT_LINE = /^[ \t]*[a-z][a-z0-9_]*=(?:"(?:[^"\\]|\\.)*"|\S*)[ \t]+[A-Za-z_][\w.]*=/;
const ENV_ITEM = /^([A-Za-z_][A-Za-z0-9_.-]*)=([\s\S]*)$/;
const ENV_KEY = /"Env"\s*:\s*/g;
const JSON_INDENTS = [0, 2, 4, "\t"] as const;

function hideValue(value: string): string {
  if (value === "" || isSecretPlaceholder(value)) return value;
  const quote = value[0];
  if (value.length >= 2 && (quote === '"' || quote === "'") && value.endsWith(quote)) {
    const inner = value.slice(1, -1);
    return inner === "" || isSecretPlaceholder(inner) ? value : `${quote}${REDACTED}${quote}`;
  }
  return REDACTED;
}

/**
 * Output of `printenv`, `env`, `export -p` or a `.env` file: the names say
 * nothing about which values are secret, so every value goes.
 */
function scrubEnvDump(text: string): string {
  const lines = text.split("\n");
  const matches = lines.map((line) => (LOGFMT_LINE.test(line) ? null : ENV_LINE.exec(line)));
  if (matches.filter(Boolean).length < ENV_DUMP_MIN_LINES) return text;

  return lines
    .map((line, index) => {
      const match = matches[index];
      return match ? `${match[1]}${hideValue(match[2] ?? "")}${match[3]}` : line;
    })
    .join("\n");
}

function hideEnvItem(item: string): string {
  const match = ENV_ITEM.exec(item);
  if (match) return `${match[1]}=${hideValue(match[2] ?? "")}`;
  return hideValue(item);
}

function stringLiteralEnd(text: string, open: number): number {
  for (let i = open + 1; i < text.length; i++) {
    if (text[i] === "\\") {
      i++;
    } else if (text[i] === '"') {
      return i;
    }
  }
  return -1;
}

/**
 * `docker inspect` prints the container environment as a JSON list under
 * "Env". The text is edited in place, so output that was cut off or is not
 * valid JSON as a whole is still covered and keeps its formatting.
 */
function scrubEnvKeys(text: string): string {
  let output = "";
  let copied = 0;
  const hideLiteral = (open: number, close: number, hide: (inner: string) => string) => {
    output += `${text.slice(copied, open + 1)}${hide(text.slice(open + 1, close))}`;
    copied = close;
  };

  ENV_KEY.lastIndex = 0;
  for (let key = ENV_KEY.exec(text); key !== null; key = ENV_KEY.exec(text)) {
    let i = key.index + key[0].length;
    if (text[i] === '"') {
      const close = stringLiteralEnd(text, i);
      if (close === -1) break;
      hideLiteral(i, close, (inner) => inner.split("\\n").map(hideEnvItem).join("\\n"));
      ENV_KEY.lastIndex = close + 1;
      continue;
    }
    if (text[i] !== "[") continue;

    for (i++; i < text.length; i++) {
      const char = text[i];
      if (char === '"') {
        const close = stringLiteralEnd(text, i);
        if (close === -1) break;
        hideLiteral(i, close, hideEnvItem);
        i = close;
      } else if (char !== "," && char !== " " && char !== "\n" && char !== "\r" && char !== "\t") {
        break;
      }
    }
    ENV_KEY.lastIndex = Math.max(i, ENV_KEY.lastIndex);
  }
  return copied === 0 ? text : output + text.slice(copied);
}

function scrubDumps(text: string): string {
  return scrubEnvKeys(scrubEnvDump(text));
}

/** Removes secret values from text a command printed. Running it twice changes nothing more. */
export function scrubOutputText(text: string): string {
  return scrubSecrets(scrubDumps(text));
}

function mapStrings(value: unknown, transform: (text: string) => string): unknown {
  if (typeof value === "string") return transform(value);
  if (Array.isArray(value)) return value.map((item) => mapStrings(item, transform));
  if (value !== null && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value).map(([key, item]) => [key, mapStrings(item, transform)]),
    );
  }
  return value;
}

interface JsonContainer {
  value: unknown;
  indent: (typeof JSON_INDENTS)[number];
  before: string;
  after: string;
}

/**
 * The SSH tools wrap command output in a JSON document. It is taken apart only
 * when writing it back gives the same bytes, so no number or key can change.
 */
function parseJsonContainer(text: string): JsonContainer | undefined {
  const body = text.trim();
  if (!body.startsWith("{") && !body.startsWith("[")) return undefined;

  let value: unknown;
  try {
    value = JSON.parse(body);
  } catch {
    return undefined;
  }
  const indent = JSON_INDENTS.find((candidate) => JSON.stringify(value, null, candidate) === body);
  if (indent === undefined) return undefined;

  const start = text.indexOf(body);
  return { value, indent, before: text.slice(0, start), after: text.slice(start + body.length) };
}

function scrubString(text: string): string {
  const container = parseJsonContainer(text);
  if (container === undefined) return scrubOutputText(text);

  const scrubbed = redactSensitive(mapStrings(container.value, scrubDumps));
  return `${container.before}${JSON.stringify(scrubbed, null, container.indent)}${container.after}`;
}

function isBinaryPayload(parent: Record<string, unknown>, key: string): boolean {
  return (key === "data" || key === "blob") && typeof parent.mimeType === "string";
}

export interface ScrubbedResponse {
  value: unknown;
  changed: boolean;
}

/**
 * Scrubs every text of an MCP tool result and keeps its shape, whether the
 * client passes a string, a list of content blocks or an object around them.
 */
export function scrubToolResponse(response: unknown): ScrubbedResponse {
  let changed = false;
  const walk = (value: unknown): unknown => {
    if (typeof value === "string") {
      const scrubbed = scrubString(value);
      changed ||= scrubbed !== value;
      return scrubbed;
    }
    if (Array.isArray(value)) return value.map(walk);
    if (value !== null && typeof value === "object") {
      const record = value as Record<string, unknown>;
      return Object.fromEntries(
        Object.entries(record).map(([key, item]) => [
          key,
          isBinaryPayload(record, key) ? item : walk(item),
        ]),
      );
    }
    return value;
  };
  return { value: walk(response), changed };
}
