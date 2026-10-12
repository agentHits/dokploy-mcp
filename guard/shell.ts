export interface Redirect {
  kind: "in" | "out";
  /** File descriptor on the left of the operator; "&" stands for stdout and stderr together. */
  fd: number | "&";
  target: string;
}

export interface SimpleCommand {
  words: string[];
  redirects: Redirect[];
  /** Body of a heredoc or text of a here-string attached to the command. */
  stdin?: string;
}

export interface ParsedScript {
  /** Commands joined by `|` form one pipeline; every other operator starts a new one. */
  pipelines: SimpleCommand[][];
  /** Command text found inside `$(...)`, backticks and `<(...)`. */
  substitutions: string[];
}

interface PendingRedirect {
  kind: "in" | "out" | "heredoc" | "herestring";
  fd: number | "&";
  stripTabs: boolean;
}

interface PendingHeredoc {
  command: SimpleCommand;
  delimiter: string;
  stripTabs: boolean;
}

const ANSI_C_ESCAPES: Record<string, string> = { n: "\n", t: "\t", r: "\r", "0": "\0" };

function isDigits(text: string): boolean {
  return text !== "" && /^\d+$/.test(text);
}

/** Index of the `)` that closes the `(` at `open`, or the end of the text. */
function closingParen(source: string, open: number): number {
  let depth = 0;
  for (let i = open; i < source.length; i++) {
    const char = source[i];
    if (char === "\\") {
      i++;
    } else if (char === "'") {
      const end = source.indexOf("'", i + 1);
      if (end === -1) return source.length;
      i = end;
    } else if (char === '"') {
      i = closingDoubleQuote(source, i);
    } else if (char === "(") {
      depth++;
    } else if (char === ")") {
      depth--;
      if (depth === 0) return i;
    }
  }
  return source.length;
}

function closingDoubleQuote(source: string, open: number): number {
  for (let i = open + 1; i < source.length; i++) {
    if (source[i] === "\\") {
      i++;
    } else if (source[i] === '"') {
      return i;
    }
  }
  return source.length;
}

function closingBacktick(source: string, open: number): number {
  for (let i = open + 1; i < source.length; i++) {
    if (source[i] === "\\") {
      i++;
    } else if (source[i] === "`") {
      return i;
    }
  }
  return source.length;
}

function closingBrace(source: string, open: number): number {
  let depth = 0;
  for (let i = open; i < source.length; i++) {
    const char = source[i];
    if (char === "\\") {
      i++;
    } else if (char === "{") {
      depth++;
    } else if (char === "}") {
      depth--;
      if (depth === 0) return i;
    }
  }
  return source.length;
}

/**
 * Splits shell text into simple commands the way a POSIX shell would read it:
 * quotes are removed, operators separate commands, redirections and heredocs
 * are attached to their command. Subshells and groups are flattened, because
 * the caller only needs to see every command that would run.
 */
export function parseShell(source: string): ParsedScript {
  const pipelines: SimpleCommand[][] = [];
  const substitutions: string[] = [];
  const heredocs: PendingHeredoc[] = [];

  let pipeline: SimpleCommand[] = [];
  let command: SimpleCommand = { words: [], redirects: [] };
  let word: string | null = null;
  let pending: PendingRedirect | null = null;
  let i = 0;

  const append = (text: string) => {
    word = (word ?? "") + text;
  };

  const endWord = () => {
    if (word === null) return;
    const value = word;
    word = null;
    if (pending === null) {
      command.words.push(value);
      return;
    }
    const redirect = pending;
    pending = null;
    if (redirect.kind === "heredoc") {
      heredocs.push({ command, delimiter: value, stripTabs: redirect.stripTabs });
    } else if (redirect.kind === "herestring") {
      command.stdin = value;
    } else {
      command.redirects.push({ kind: redirect.kind, fd: redirect.fd, target: value });
    }
  };

  const endCommand = () => {
    endWord();
    pending = null;
    if (command.words.length > 0 || command.redirects.length > 0 || command.stdin !== undefined) {
      pipeline.push(command);
    }
    command = { words: [], redirects: [] };
  };

  const endPipeline = () => {
    endCommand();
    if (pipeline.length > 0) pipelines.push(pipeline);
    pipeline = [];
  };

  const substitute = (open: number, close: number, raw: string) => {
    substitutions.push(source.slice(open + 1, close));
    append(raw);
    i = close + 1;
  };

  const readHeredocs = () => {
    for (const heredoc of heredocs) {
      const lines: string[] = [];
      while (i < source.length) {
        const newline = source.indexOf("\n", i);
        const end = newline === -1 ? source.length : newline;
        const raw = source.slice(i, end);
        const line = heredoc.stripTabs ? raw.replace(/^\t+/, "") : raw;
        i = newline === -1 ? source.length : newline + 1;
        if (line.trimEnd() === heredoc.delimiter) break;
        lines.push(line);
      }
      heredoc.command.stdin = lines.join("\n");
    }
    heredocs.length = 0;
  };

  const readDoubleQuoted = () => {
    append("");
    i++;
    while (i < source.length && source[i] !== '"') {
      const char = source[i] ?? "";
      const next = source[i + 1];
      if (char === "\\" && next !== undefined && '$`"\\\n'.includes(next)) {
        if (next !== "\n") append(next);
        i += 2;
      } else if (char === "$" && next === "(" && source[i + 2] !== "(") {
        const close = closingParen(source, i + 1);
        substitute(i + 1, close, source.slice(i, close + 1));
      } else if (char === "`") {
        const close = closingBacktick(source, i);
        substitute(i, close, source.slice(i, close + 1));
      } else {
        append(char);
        i++;
      }
    }
    i++;
  };

  const readAnsiCQuoted = () => {
    append("");
    i += 2;
    while (i < source.length && source[i] !== "'") {
      const char = source[i] ?? "";
      const next = source[i + 1];
      if (char === "\\" && next !== undefined) {
        append(ANSI_C_ESCAPES[next] ?? next);
        i += 2;
      } else {
        append(char);
        i++;
      }
    }
    i++;
  };

  const readDollar = () => {
    const next = source[i + 1];
    if (next === "(" && source[i + 2] === "(") {
      const close = source.indexOf("))", i);
      const end = close === -1 ? source.length : close + 2;
      append(source.slice(i, end));
      i = end;
    } else if (next === "(") {
      const close = closingParen(source, i + 1);
      substitute(i + 1, close, source.slice(i, close + 1));
    } else if (next === "{") {
      const close = closingBrace(source, i + 1);
      append(source.slice(i, close + 1));
      i = close + 1;
    } else if (next === "'") {
      readAnsiCQuoted();
    } else if (next === '"') {
      i++;
      readDoubleQuoted();
    } else {
      append("$");
      i++;
    }
  };

  const readRedirect = () => {
    const operator = source[i];
    let fd: number | "&" = operator === "<" ? 0 : 1;
    if (word !== null && isDigits(word)) {
      fd = Number(word);
      word = null;
    } else {
      endWord();
    }

    if (source[i + 1] === "(") {
      const close = closingParen(source, i + 1);
      substitute(i + 1, close, source.slice(i, close + 1));
      return;
    }

    if (operator === "<" && source.startsWith("<<<", i)) {
      pending = { kind: "herestring", fd, stripTabs: false };
      i += 3;
    } else if (operator === "<" && source.startsWith("<<", i)) {
      const stripTabs = source[i + 2] === "-";
      pending = { kind: "heredoc", fd, stripTabs };
      i += stripTabs ? 3 : 2;
    } else if (source[i + 1] === "&") {
      i += 2;
      let end = i;
      while (end < source.length && /[\d-]/.test(source[end] ?? "")) end++;
      const followedByWord = end < source.length && !/[\s;|&<>()]/.test(source[end] ?? "");
      if (end > i && !followedByWord) {
        i = end;
      } else {
        pending = { kind: operator === "<" ? "in" : "out", fd: "&", stripTabs: false };
      }
    } else {
      pending = { kind: operator === "<" ? "in" : "out", fd, stripTabs: false };
      i += 1;
      if (source[i] === ">" || source[i] === "|") i++;
    }
  };

  while (i < source.length) {
    const char = source[i] ?? "";
    const next = source[i + 1];

    if (char === " " || char === "\t" || char === "\r") {
      endWord();
      i++;
    } else if (char === "\n") {
      endPipeline();
      i++;
      if (heredocs.length > 0) readHeredocs();
    } else if (char === "#" && word === null) {
      const newline = source.indexOf("\n", i);
      i = newline === -1 ? source.length : newline;
    } else if (char === "\\") {
      if (next === "\n") {
        i += 2;
      } else {
        append(next ?? "");
        i += 2;
      }
    } else if (char === "'") {
      const close = source.indexOf("'", i + 1);
      const end = close === -1 ? source.length : close;
      append(source.slice(i + 1, end));
      i = end + 1;
    } else if (char === '"') {
      readDoubleQuoted();
    } else if (char === "$") {
      readDollar();
    } else if (char === "`") {
      const close = closingBacktick(source, i);
      substitute(i, close, source.slice(i, close + 1));
    } else if (char === "<" || char === ">") {
      readRedirect();
    } else if (char === "&") {
      if (next === ">") {
        endWord();
        pending = { kind: "out", fd: "&", stripTabs: false };
        i += source[i + 2] === ">" ? 3 : 2;
      } else {
        endPipeline();
        i += next === "&" ? 2 : 1;
      }
    } else if (char === "|") {
      if (next === "|") {
        endPipeline();
        i += 2;
      } else {
        endCommand();
        i += next === "&" ? 2 : 1;
      }
    } else if (char === ";" || char === "(" || char === ")") {
      endPipeline();
      i++;
    } else {
      append(char);
      i++;
    }
  }

  endPipeline();
  if (heredocs.length > 0) readHeredocs();
  return { pipelines, substitutions };
}
