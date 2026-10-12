export const REDACTED = "[REDACTED]";
export const PANEL_REDACTED = "__DOKPLOY_REDACTED_SECRET__";
export const SECRET_PLACEHOLDERS = [PANEL_REDACTED, REDACTED] as const;

const SENSITIVE_NAME =
  /access[_-]?key|api[_-]?key|auth|credential|private[_-]?key|token|secret|password|passwd|pwd|pass|dsn|cookie|session|signature|salt|webhook|license|encryption|jwt/i;
// "key" counts only as a whole word (APP_KEY, signingKey, ?key=) so that
// names like "monkey" or "keyboard" stay readable.
const KEY_WORD = /(?:^|[_.-])keys?(?:$|[_.-])/i;
const CAMEL_KEY_WORD = /(?:[a-z0-9]K|^k)eys?(?:$|[A-Z_.-])/;

const NON_SECRET_LITERAL = /^(?:true|false|null)$/i;
const AUTH_SCHEME_VALUE = /^(Bearer|Basic)([ \t]+)(\S+)$/i;
const SIMPLE_REFERENCE = /^\$[A-Za-z_][A-Za-z0-9_]*$/;
const TEMPLATE_REFERENCE = /^\$\{\{\s*[A-Za-z_][A-Za-z0-9_.-]*\s*\}\}$/;
const BRACED_REFERENCE = /^\$\{([A-Za-z_][A-Za-z0-9_]*)(?:(:?[-+?])([\s\S]*))?\}$/;
const MAX_REFERENCE_DEPTH = 4;

const PEM_BEGIN = /-----BEGIN [A-Z0-9 ]{0,40}PRIVATE KEY(?: BLOCK)?-----/g;
const PEM_END = /-----END [A-Z0-9 ]{0,40}PRIVATE KEY(?: BLOCK)?-----/g;
const PEM_BODY = /[A-Za-z0-9+/=\s\\]*/y;

// Every pattern below that consumes a run of name characters is anchored with
// a lookbehind on the same character class. Without it the engine retries the
// run from each of its characters and a long token-like line goes quadratic.
const TOKEN_SHAPES =
  /(?<![A-Za-z0-9_-])(?:gh[pousr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,}|glpat-[A-Za-z0-9_-]{20,}|xox[abprs]-[A-Za-z0-9-]{10,}|sk-[A-Za-z0-9_-]{20,}|eyJ[A-Za-z0-9_-]{4,}\.eyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]*)|(?<![A-Z0-9])AKIA[0-9A-Z]{16}(?![0-9A-Z])/g;
const URL_USERINFO = /(?<=[A-Za-z0-9+.-]:\/\/)([^\s/?#"'<>\\]*)@/g;
const AUTH_SCHEME = /\b(Authorization[ \t]*:[ \t]*Basic[ \t]+|Bearer[ \t]+)([A-Za-z0-9._~+/=-]+)/gi;
const ASSIGNMENT = /(?<![A-Za-z0-9_.-])([A-Za-z_][A-Za-z0-9_.-]*)[ \t]*=/g;
const KEY_VALUE = /(?<![A-Za-z0-9_.-])(\\?["'])?([A-Za-z_][A-Za-z0-9_.-]*)(\\?["'])?[ \t]*:/g;
const CLI_FLAG =
  /(?<![A-Za-z0-9_-])--?([A-Za-z][A-Za-z0-9_-]*)(=|[ \t]+|\\?["'][ \t]*,[ \t]*(?=\\?["']))/g;
const NEGATED_FLAG = /^no-/i;
const FLAG_ARGUMENT = /^--?([A-Za-z][A-Za-z0-9_-]*)$/;

interface Span {
  start: number;
  end: number;
  replacement: string;
}

export function isSensitiveName(name: string): boolean {
  return SENSITIVE_NAME.test(name) || KEY_WORD.test(name) || CAMEL_KEY_WORD.test(name);
}

export function isSensitiveFlag(argument: string): boolean {
  const name = FLAG_ARGUMENT.exec(argument)?.[1];
  return name !== undefined && !NEGATED_FLAG.test(name) && isSensitiveName(name);
}

function closesAtEnd(value: string): boolean {
  let depth = 0;
  for (let i = 0; i < value.length; i++) {
    if (value[i] === "$" && value[i + 1] === "{") {
      depth++;
      i++;
    } else if (value[i] === "}") {
      depth--;
      if (depth === 0) return i === value.length - 1;
    }
  }
  return false;
}

function redactReference(value: string, depth: number): string | null {
  if (SIMPLE_REFERENCE.test(value) || TEMPLATE_REFERENCE.test(value)) return value;
  if (!value.startsWith("${") || !closesAtEnd(value)) return null;

  const match = BRACED_REFERENCE.exec(value);
  if (!match) return null;
  const [, name, operator, operand = ""] = match;
  if (operator === undefined || operator.endsWith("?")) return value;

  const fallback = depth < MAX_REFERENCE_DEPTH ? redactValue(operand, depth + 1) : REDACTED;
  return `\${${name}${operator}${fallback}}`;
}

/**
 * Redacts one isolated value. Variable references, booleans, null and existing
 * placeholders are not secrets and are returned unchanged.
 */
export function redactValue(value: string, depth = 0): string {
  if (
    value === "" ||
    value === REDACTED ||
    value === PANEL_REDACTED ||
    NON_SECRET_LITERAL.test(value)
  ) {
    return value;
  }

  const scheme = AUTH_SCHEME_VALUE.exec(value);
  if (scheme) {
    return `${scheme[1]}${scheme[2]}${redactValue(scheme[3] ?? "", depth + 1)}`;
  }

  return redactReference(value, depth) ?? REDACTED;
}

function isBlank(char: string | undefined): boolean {
  return char === " " || char === "\t";
}

function isQuote(char: string | undefined): char is '"' | "'" {
  return char === '"' || char === "'";
}

function skipBlanks(text: string, from: number): number {
  let i = from;
  while (isBlank(text[i])) i++;
  return i;
}

function endsLine(text: string, index: number): boolean {
  const char = text[index];
  return char === undefined || char === "\n" || char === "\r";
}

function placeholderAt(text: string, index: number): string | undefined {
  return SECRET_PLACEHOLDERS.find((placeholder) => text.startsWith(placeholder, index));
}

function trimmedLineEnd(text: string, from: number): number {
  const newline = text.indexOf("\n", from);
  let end = newline === -1 ? text.length : newline;
  while (end > from && (isBlank(text[end - 1]) || text[end - 1] === "\r")) end--;
  return end;
}

function tokenEnd(text: string, from: number, stopAtJsonPunctuation: boolean): number {
  let i = from;
  while (i < text.length) {
    const char = text[i];
    if (char === " " || char === "\t" || char === "\n" || char === "\r") break;
    if (char === '"' || char === "'") break;
    if (stopAtJsonPunctuation && (char === "," || char === "}" || char === "]")) break;
    if (char === "\\" && i + 1 < text.length && text[i + 1] !== "\n" && text[i + 1] !== "\r") {
      i += 2;
    } else {
      i++;
    }
  }
  return i;
}

function blankRunStart(text: string, end: number): number {
  let i = end;
  while (i > 0 && isBlank(text[i - 1])) i--;
  return i;
}

function startsLine(text: string, nameStart: number): boolean {
  let i = blankRunStart(text, nameStart);
  if (i === 0 || text[i - 1] === "\n") return true;
  if (i === nameStart) return false;

  if (text[i - 1] === "-") {
    i -= 1;
  } else if (i >= 6 && text.startsWith("export", i - 6)) {
    i -= 6;
  } else {
    return false;
  }
  i = blankRunStart(text, i);
  return i === 0 || text[i - 1] === "\n";
}

/**
 * Index of the delimiter that closes a quoted value starting at `from`, or -1
 * when the line ends first. A search can only fail once per delimiter and line
 * (a later quoted value would itself be the missing delimiter), so the scans
 * stay linear without any bookkeeping.
 */
function closingIndex(text: string, from: number, delimiter: string): number {
  const quote = delimiter[delimiter.length - 1];
  const escapedDelimiter = delimiter.length === 2;
  let i = from;
  while (i < text.length) {
    const char = text[i];
    if (char === "\n") return -1;
    if (escapedDelimiter) {
      if (char === "\\" && text[i + 1] === quote) return i;
      i++;
    } else if (char === "\\" && quote === '"') {
      i += 2;
    } else if (char === quote) {
      // YAML and SQL write a literal single quote as two of them.
      if (quote !== "'" || text[i + 1] !== "'") return i;
      i += 2;
    } else {
      i++;
    }
  }
  return -1;
}

function opensQuote(text: string, index: number): boolean {
  return isQuote(text[index]) || (text[index] === "\\" && isQuote(text[index + 1]));
}

function quotedSpan(text: string, start: number): (Span & { after: number }) | null {
  const delimiter = text[start] === "\\" ? text.slice(start, start + 2) : (text[start] ?? "");
  const innerStart = start + delimiter.length;
  const close = closingIndex(text, innerStart, delimiter);
  if (close === -1) return null;
  return {
    start: innerStart,
    end: close,
    replacement: redactValue(text.slice(innerStart, close)),
    after: close + delimiter.length,
  };
}

function bareSpan(text: string, start: number, end: number): Span {
  return { start, end, replacement: redactValue(text.slice(start, end)) };
}

function keepPlaceholder(start: number, placeholder: string): Span {
  return { start, end: start + placeholder.length, replacement: placeholder };
}

function assignmentSpan(text: string, match: RegExpExecArray): Span | null {
  if (!isSensitiveName(match[1] ?? "")) return null;

  const afterEquals = match.index + match[0].length;
  const next = text[afterEquals];
  if (next === "=" || next === ">" || next === "~") return null;

  const start = skipBlanks(text, afterEquals);
  if (endsLine(text, start)) return null;
  const placeholder = placeholderAt(text, start);
  if (placeholder) return keepPlaceholder(start, placeholder);

  const opener = text[match.index - 1];
  if (isQuote(opener)) {
    const delimiter = text[match.index - 2] === "\\" ? `\\${opener}` : opener;
    const close = closingIndex(text, start, delimiter);
    if (close !== -1) return bareSpan(text, start, close);
  }

  if (startsLine(text, match.index)) {
    const end = trimmedLineEnd(text, start);
    const quoted = opensQuote(text, start) ? quotedSpan(text, start) : null;
    return quoted?.after === end ? quoted : bareSpan(text, start, end);
  }

  if (opensQuote(text, start)) {
    const quoted = quotedSpan(text, start);
    if (quoted) return quoted;
  }
  return bareSpan(text, start, tokenEnd(text, start, false));
}

function keyValueSpan(text: string, match: RegExpExecArray): Span | null {
  if (!isSensitiveName(match[2] ?? "")) return null;

  const afterColon = match.index + match[0].length;
  const start = skipBlanks(text, afterColon);
  if (endsLine(text, start)) return null;
  const placeholder = placeholderAt(text, start);
  if (placeholder) return keepPlaceholder(start, placeholder);

  if (opensQuote(text, start)) {
    const quoted = quotedSpan(text, start);
    if (quoted) return quoted;
  }

  const keyIsQuoted = match[3] !== undefined;
  if (keyIsQuoted) return bareSpan(text, start, tokenEnd(text, start, true));

  // "name:value" without a space is an image tag, a port or a volume mapping,
  // not a YAML pair.
  if (start === afterColon) return null;

  const opener = match[1];
  if (opener !== undefined) {
    const close = closingIndex(text, start, opener);
    if (close !== -1) return bareSpan(text, start, close);
  }
  return bareSpan(text, start, trimmedLineEnd(text, start));
}

function flagSpan(text: string, match: RegExpExecArray): Span | null {
  const name = match[1] ?? "";
  if (NEGATED_FLAG.test(name) || !isSensitiveName(name)) return null;

  const start = match.index + match[0].length;
  if (endsLine(text, start)) return null;
  const placeholder = placeholderAt(text, start);
  if (placeholder) return keepPlaceholder(start, placeholder);

  if (opensQuote(text, start)) {
    const quoted = quotedSpan(text, start);
    if (quoted) return quoted;
  }

  const followedByFlag =
    isBlank(match[2]?.[0]) && text[start] === "-" && /[A-Za-z-]/.test(text[start + 1] ?? "");
  if (followedByFlag) return null;
  return bareSpan(text, start, tokenEnd(text, start, false));
}

function rewrite(
  text: string,
  pattern: RegExp,
  locate: (text: string, match: RegExpExecArray) => Span | null,
): string {
  let output = "";
  let copied = 0;
  pattern.lastIndex = 0;

  for (let match = pattern.exec(text); match !== null; match = pattern.exec(text)) {
    const span = locate(text, match);
    if (span === null) continue;
    if (span.replacement !== text.slice(span.start, span.end)) {
      output += text.slice(copied, span.start) + span.replacement;
      copied = span.end;
    }
    pattern.lastIndex = Math.max(span.end, pattern.lastIndex);
  }

  return copied === 0 ? text : output + text.slice(copied);
}

function scrubPrivateKeys(text: string): string {
  if (!text.includes("PRIVATE KEY")) return text;

  let output = "";
  let copied = 0;
  let noFurtherEnd = false;
  PEM_BEGIN.lastIndex = 0;

  for (let begin = PEM_BEGIN.exec(text); begin !== null; begin = PEM_BEGIN.exec(text)) {
    const bodyStart = begin.index + begin[0].length;
    let end = -1;
    if (!noFurtherEnd) {
      PEM_END.lastIndex = bodyStart;
      const close = PEM_END.exec(text);
      if (close) {
        end = close.index + close[0].length;
      } else {
        noFurtherEnd = true;
      }
    }
    if (end === -1) {
      PEM_BODY.lastIndex = bodyStart;
      PEM_BODY.exec(text);
      end = Math.max(PEM_BODY.lastIndex, bodyStart);
    }
    output += text.slice(copied, begin.index) + REDACTED;
    copied = end;
    PEM_BEGIN.lastIndex = end;
  }

  return copied === 0 ? text : output + text.slice(copied);
}

function passwordSeparator(userinfo: string): number {
  let depth = 0;
  for (let i = 0; i < userinfo.length; i++) {
    const char = userinfo[i];
    if (char === "$" && userinfo[i + 1] === "{") {
      depth++;
      i++;
    } else if (char === "}" && depth > 0) {
      depth--;
    } else if (char === ":" && depth === 0) {
      return i;
    }
  }
  return -1;
}

function redactUserinfo(userinfo: string): string {
  const separator = passwordSeparator(userinfo);
  if (separator === -1) return redactValue(userinfo);

  const user = userinfo.slice(0, separator);
  const password = userinfo.slice(separator + 1);
  // Git hosts accept the token as the user name with an empty or dummy password.
  if (password === "" || password === "x-oauth-basic") {
    return `${redactValue(user)}:${password}`;
  }
  return `${user}:${redactValue(password)}`;
}

/**
 * Replaces the secret part of credentials found in free text (logs, config
 * files, compose files) with a placeholder. Running it on its own output
 * changes nothing.
 */
export function scrubSecrets(text: string): string {
  if (text === "") return text;

  let result = scrubPrivateKeys(text);
  result = result.replace(TOKEN_SHAPES, REDACTED);
  result = result.replace(
    URL_USERINFO,
    (_match, userinfo: string) => `${redactUserinfo(userinfo)}@`,
  );
  result = result.replace(
    AUTH_SCHEME,
    (_match, prefix: string, token: string) => `${prefix}${redactValue(token)}`,
  );
  result = rewrite(result, ASSIGNMENT, assignmentSpan);
  result = rewrite(result, KEY_VALUE, keyValueSpan);
  result = rewrite(result, CLI_FLAG, flagSpan);
  return result;
}
