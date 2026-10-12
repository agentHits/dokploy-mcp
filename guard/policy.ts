import { isSensitiveName } from "../src/utils/scrubSecrets.js";
import { parseShell, type SimpleCommand } from "./shell.js";

export interface Verdict {
  decision: "allow" | "deny";
  rule?: string;
  reason?: string;
  alternative?: string;
}

export interface RemoteContext {
  /** Directory the command starts in, when the tool sets one. */
  cwd?: string;
  /** Text piped into the command: a heredoc, a here-string or an echoed string. */
  stdin?: string;
}

export interface RemoteInvocation {
  tool: "ssh" | "scp" | "sftp" | "rsync";
  /** Shell text the remote side runs; absent for an interactive session or a file transfer. */
  command?: string;
  stdin?: string;
  /** Remote paths a transfer copies from. */
  sources: string[];
}

const PANEL_TOOLS =
  "Variable names are listed by `env-keys` and changed by `env-apply` of the Dokploy MCP server.";

export const RULES = {
  "env-dump": {
    reason: "prints every environment variable of the server or container, secrets included.",
    alternative: `Print one non-secret variable with \`printenv NAME\`, or check that a secret is set with \`[ -n "$NAME" ] && echo set\`. ${PANEL_TOOLS}`,
  },
  "secret-variable": {
    reason: "prints the value of a variable that holds a secret.",
    alternative: `Check that it is set with \`[ -n "$NAME" ] && echo set\` or print only its length with \`echo \${#NAME}\`. ${PANEL_TOOLS}`,
  },
  "docker-inspect": {
    reason: "returns the container environment, arguments and labels, which carry secrets.",
    alternative:
      "Ask for the one field you need with a Go template that leaves out Env, Args, Labels and whole Config or Spec objects, for example `--format '{{.State.Status}}'`, `'{{.Config.Image}}'` or `'{{json .NetworkSettings.Networks}}'`.",
  },
  "docker-config": {
    reason: "prints a compose file, stack file or swarm config with every secret value filled in.",
    alternative:
      "Use `docker compose config --services` (or `--volumes`, `--images`, `--quiet` to validate) and `docker config ls`; read the compose file through the Dokploy MCP server, which hides the secret values.",
  },
  "docker-export": {
    reason: "writes out a whole container or image, including the files and environment in it.",
    alternative:
      "Look at what you need in place: `docker image ls`, `docker exec CONTAINER ls -l PATH` or `docker exec CONTAINER wc -l PATH`.",
  },
  "docker-cp": {
    reason: "copies files out of a container, where env files and keys can come along unnoticed.",
    alternative:
      "List the file with `docker exec CONTAINER ls -l PATH`. Copying into a container (`docker cp FILE CONTAINER:PATH`) is not blocked.",
  },
  "secret-file": {
    reason: "holds secrets, and reading or copying it would bring them into the conversation.",
    alternative: `Look at it without its content: \`ls -l\`, \`stat\`, \`wc -l\`, \`grep -c PATTERN\` or \`test -f\`. ${PANEL_TOOLS}`,
  },
  "db-dump": {
    reason:
      "sends a database dump to the terminal, so every stored row would reach the conversation.",
    alternative:
      "Write the dump to a file on the server (`pg_dump ... -f /path/dump.sql`, `mysqldump ... > /path/dump.sql`, `... | gzip > /path/dump.sql.gz`) and check it with `ls -l`.",
  },
  "db-query": {
    reason: "returns table rows, which can hold credentials and personal data.",
    alternative:
      "Use metadata queries: `\\dt`, `\\d NAME`, `\\l`, `SELECT count(*) FROM ...`, `SELECT version()`, `SHOW ...`, or queries on `pg_stat_*` and `information_schema`. Ask the user to run a row query and share what is safe.",
  },
  "redis-read": {
    reason: "reads keys or values out of Redis, where sessions and tokens are stored.",
    alternative:
      "Use commands that return no stored values: `PING`, `INFO`, `DBSIZE`, `TYPE key`, `TTL key`, `EXISTS key`, `MEMORY USAGE key`.",
  },
  "private-key": {
    reason: "would show private key material.",
    alternative:
      "Work with fingerprints and public keys only: `ssh-keygen -lf KEY.pub`, or the verify, check and list actions of ssh_key_manage.",
  },
} as const;

export type RuleId = keyof typeof RULES;

const ALLOW: Verdict = { decision: "allow" };
const words = (list: string) => list.split(" ");
const MAX_DEPTH = 8;
const MAX_VARIABLE_VALUES = 8;

function deny(rule: RuleId, subject: string): Verdict {
  const { reason, alternative } = RULES[rule];
  return { decision: "deny", rule, reason: `${subject} ${reason}`, alternative };
}

function quote(text: string): string {
  const flat = text.replace(/\s+/g, " ").trim();
  return `\`${flat.length > 80 ? `${flat.slice(0, 77)}...` : flat}\``;
}

interface OptionSpec {
  /** Short options that take a value. */
  short?: string;
  /** Long options that take their value from the next word. */
  long?: readonly string[];
  /** Short options whose value is only ever attached (`mysql -pVALUE`). */
  attachedOnly?: string;
}

interface ParsedOptions {
  values: Map<string, string[]>;
  flags: Set<string>;
  positionals: string[];
}

function parseOptions(
  args: readonly string[],
  spec: OptionSpec,
  stopAtPositional = false,
): ParsedOptions {
  const values = new Map<string, string[]>();
  const flags = new Set<string>();
  const positionals: string[] = [];
  const addValue = (name: string, value: string) => {
    values.set(name, [...(values.get(name) ?? []), value]);
  };

  for (let i = 0; i < args.length; i++) {
    const arg = args[i] ?? "";
    if (arg === "--") {
      positionals.push(...args.slice(i + 1));
      break;
    }
    if (arg.startsWith("--")) {
      const equals = arg.indexOf("=");
      const name = equals === -1 ? arg.slice(2) : arg.slice(2, equals);
      if (equals !== -1) {
        addValue(name, arg.slice(equals + 1));
      } else if (spec.long?.includes(name) && i + 1 < args.length) {
        addValue(name, args[++i] ?? "");
      } else {
        flags.add(name);
      }
    } else if (arg.length > 1 && arg.startsWith("-")) {
      for (let j = 1; j < arg.length; j++) {
        const letter = arg[j] ?? "";
        const attached = arg.slice(j + 1);
        if (spec.attachedOnly?.includes(letter)) {
          addValue(letter, attached);
          break;
        }
        if (spec.short?.includes(letter)) {
          if (attached !== "") {
            addValue(letter, attached.startsWith("=") ? attached.slice(1) : attached);
          } else if (i + 1 < args.length) {
            addValue(letter, args[++i] ?? "");
          }
          break;
        }
        flags.add(letter);
      }
    } else if (stopAtPositional) {
      positionals.push(...args.slice(i));
      break;
    } else {
      positionals.push(arg);
    }
  }
  return { values, flags, positionals };
}

function optionValues(options: ParsedOptions, names: readonly string[]): string[] {
  return names.flatMap((name) => options.values.get(name) ?? []);
}

function commandName(word: string): string {
  return word.slice(word.lastIndexOf("/") + 1);
}

const ASSIGNMENT = /^([A-Za-z_][A-Za-z0-9_]*)=([\s\S]*)$/;
const PROC_ENVIRON = /(?:^|\/)proc\/[^/]+\/(?:task\/[^/]+\/)?environ$/;
const TERMINAL_TARGET = /^(?:-|\/dev\/(?:stdout|stderr|tty|fd\/[12])|\/proc\/self\/fd\/[12])$/;

const SECRET_BASENAMES = new Set(
  words(".env .envrc acme.json .netrc .pgpass .my.cnf .git-credentials .npmrc"),
);
const SECRET_PREFIXES = ["/etc/dokploy", "/run/secrets", "/var/run/secrets", "/var/lib/docker"];
const READABLE_PREFIXES = ["/etc/dokploy/logs"];
const SECRET_FILES = new Set(["/etc/shadow", "/etc/shadow-", "/etc/gshadow", "/etc/gshadow-"]);

function isUnder(path: string, prefix: string): boolean {
  return path === prefix || path.startsWith(`${prefix}/`);
}

function normalizePath(raw: string, cwd: string | undefined): string {
  const anchored = /^[/~$]/.test(raw) || cwd === undefined ? raw : `${cwd}/${raw}`;
  const absolute = anchored.startsWith("/");
  const segments: string[] = [];
  for (const segment of anchored.split("/")) {
    if (segment === "" || segment === ".") continue;
    if (segment === ".." && segments.length > 0 && segments[segments.length - 1] !== "..") {
      segments.pop();
    } else if (segment !== ".." || !absolute) {
      segments.push(segment);
    }
  }
  return `${absolute ? "/" : ""}${segments.join("/")}`;
}

/** True when the path names a file or directory that holds secrets on a server. */
export function isSecretPath(raw: string, cwd?: string): boolean {
  const path = normalizePath(raw.trim(), cwd);
  if (path === "" || path === "/") return false;
  if (PROC_ENVIRON.test(path) || SECRET_FILES.has(path)) return true;
  if (READABLE_PREFIXES.some((prefix) => isUnder(path, prefix))) return false;
  if (SECRET_PREFIXES.some((prefix) => isUnder(path, prefix))) return true;

  const segments = path.split("/");
  if (segments.includes(".ssh") || segments.includes(".aws")) return true;
  if (path.endsWith(".docker/config.json")) return true;

  // A glob stands for the files it would match: ".env*" reads ".env".
  const base = (segments[segments.length - 1] ?? "").replace(/[*?]+/g, "");
  return (
    SECRET_BASENAMES.has(base) ||
    base.startsWith(".env.") ||
    base.endsWith(".env") ||
    /^id_(?:rsa|ed25519|ecdsa|dsa)/.test(base) ||
    /\.(?:pem|key|p12|pfx)$/.test(base) ||
    /^\..*history$/.test(base)
  );
}

const CONNECTION_NAME =
  /(?:DATABASE|DB|REDIS|MONGO(?:DB)?|POSTGRES(?:QL)?|PG|MYSQL|MARIADB|AMQP|RABBIT(?:MQ)?|KAFKA|BROKER|CELERY|ELASTIC(?:SEARCH)?|CLICKHOUSE|SMTP|MAIL|CONNECTION|CONN)_?(?:URL|URI|DSN|STRING|STR)/i;
const SHELL_STATE_NAMES = new Set(["PWD", "OLDPWD"]);

function holdsSecret(name: string): boolean {
  if (SHELL_STATE_NAMES.has(name)) return false;
  return isSensitiveName(name) || CONNECTION_NAME.test(name);
}

interface Scope {
  remote: boolean;
  depth: number;
  cwd: string | undefined;
  vars: Map<string, string[]>;
  /** Text the first command of each pipeline reads when it has no stdin of its own. */
  stdin: string | undefined;
  /** Where output goes when a command does not redirect it itself. */
  toFile: boolean;
  toSink: boolean;
  implied: readonly string[];
  found: RemoteInvocation[];
}

interface Frame {
  /** Stdout ends in a file on the server. */
  toFile: boolean;
  /** Stdout is consumed by a command that does not print it. */
  toSink: boolean;
  stdin: string | undefined;
  /** Paths the command is handed at run time: xargs input or find matches. */
  implied: readonly string[];
  /** Words of the commands earlier in the pipeline, which is what xargs turns into arguments. */
  upstream: () => string[];
}

function redirectsToFile(command: SimpleCommand): boolean {
  let toFile = false;
  for (const redirect of command.redirects) {
    if (redirect.kind === "out" && (redirect.fd === 1 || redirect.fd === "&")) {
      toFile = !TERMINAL_TARGET.test(redirect.target);
    }
  }
  return toFile;
}

const SINKS = new Set(
  words(
    "psql mysql mariadb pg_restore mongorestore wc md5sum sha1sum sha256sum sha512sum cksum aws rclone s3cmd mc gsutil restic split",
  ),
);
const SINK_WRAPPERS = new Set(
  words("sudo docker docker-compose podman kubectl env nice ionice timeout nohup"),
);

function withoutAssignments(words: readonly string[]): string[] {
  let start = 0;
  while (start < words.length && ASSIGNMENT.test(words[start] ?? "")) start++;
  return words.slice(start);
}

/** True when the command takes its input in without printing it. */
function isSink(command: SimpleCommand): boolean {
  const words = withoutAssignments(command.words);
  const name = commandName(words[0] ?? "");
  if (SINKS.has(name)) return true;
  if (name === "dd") return words.some((word) => word.startsWith("of="));
  if (name === "docker" && words[1] === "login") return true;
  if (name === "ssh") {
    const remote = sshInvocation(words.slice(1), undefined).command;
    if (remote === undefined) return false;
    const pipelines = parseShell(remote).pipelines;
    const pipeline = pipelines[pipelines.length - 1];
    const last = pipeline?.[pipeline.length - 1];
    return last !== undefined && (redirectsToFile(last) || isSink(last));
  }
  return SINK_WRAPPERS.has(name) && words.slice(1).some((word) => SINKS.has(word));
}

function echoedText(command: SimpleCommand | undefined): string | undefined {
  if (command === undefined) return undefined;
  const words = withoutAssignments(command.words);
  const name = commandName(words[0] ?? "");
  if (name === "echo" || name === "printf") {
    return words
      .slice(1)
      .filter((word) => !/^-[neE]+$/.test(word))
      .join(" ");
  }
  if (name === "cat" && words.length === 1) return command.stdin;
  return undefined;
}

function expandBraces(text: string): string[] {
  const match = /\{([^{}]*,[^{}]*)\}/.exec(text);
  if (!match) return [text];
  const before = text.slice(0, match.index);
  const after = text.slice(match.index + match[0].length);
  return (match[1] ?? "").split(",").map((option) => `${before}${option}${after}`);
}

const VARIABLE = /\$(?:\{([A-Za-z_][A-Za-z0-9_]*)\}|([A-Za-z_][A-Za-z0-9_]*))/g;

function expandVariables(text: string, vars: Map<string, string[]>): string[] {
  const expanded = [text];
  for (const match of text.matchAll(VARIABLE)) {
    for (const value of vars.get(match[1] ?? match[2] ?? "") ?? []) {
      expanded.push(text.split(match[0]).join(value));
    }
  }
  return expanded;
}

/** Fills in variables the same command line assigned, so `ssh host "$CMD"` shows its command. */
function withKnownVariables(text: string, vars: Map<string, string[]>): string {
  return text.replace(VARIABLE, (reference, braced?: string, bare?: string) => {
    const values = vars.get(braced ?? bare ?? "");
    return values?.[values.length - 1] ?? reference;
  });
}

function findSecretPath(candidates: readonly string[], scope: Scope): string | undefined {
  for (const candidate of candidates) {
    for (const expanded of expandVariables(candidate, scope.vars).flatMap(expandBraces)) {
      if (isSecretPath(expanded, scope.cwd)) return expanded;
    }
  }
  return undefined;
}

function denyPath(path: string): Verdict {
  return PROC_ENVIRON.test(path) ? deny("env-dump", quote(path)) : deny("secret-file", quote(path));
}

const SSH_VALUED = "BbcDEeFIiJLlmOoPpQRSWw";
const SCP_OPTIONS: OptionSpec = { short: "cDFiJloPSX" };
const SFTP_OPTIONS: OptionSpec = { short: "BbcDFiJloPRSsX" };
const RSYNC_OPTIONS: OptionSpec = {
  short: "efTBM",
  long: words(
    "rsh exclude include exclude-from include-from files-from filter temp-dir compare-dest copy-dest link-dest bwlimit port log-file partial-dir timeout contimeout max-size min-size chmod chown info debug out-format password-file rsync-path backup-dir suffix block-size iconv max-delete modify-window address remote-option usermap groupmap compress-level",
  ),
};
const REMOTE_SPEC = /^(?:[A-Za-z][A-Za-z0-9+.-]*:\/\/[^/]+|(?:[^/:@\s]+@)?[^/:\s]+::?)(.*)$/;

function sshInvocation(args: readonly string[], stdin: string | undefined): RemoteInvocation {
  let host: string | undefined;
  let i = 0;
  for (; i < args.length; i++) {
    const arg = args[i] ?? "";
    if (arg === "--") {
      i++;
      if (host === undefined) {
        host = args[i];
        i++;
      }
      break;
    }
    if (arg.length > 1 && arg.startsWith("-")) {
      for (let j = 1; j < arg.length; j++) {
        if (SSH_VALUED.includes(arg[j] ?? "")) {
          if (j === arg.length - 1) i++;
          break;
        }
      }
    } else if (host === undefined) {
      host = arg;
    } else {
      break;
    }
  }

  const command = args.slice(i).join(" ").trim();
  return {
    tool: "ssh",
    sources: [],
    ...(command === "" ? {} : { command }),
    ...(stdin === undefined ? {} : { stdin }),
  };
}

function remotePath(spec: string): string | undefined {
  return REMOTE_SPEC.exec(spec)?.[1];
}

interface TransferSources {
  remote: string[];
  local: string[];
}

function transferSources(tool: "scp" | "rsync", args: readonly string[]): TransferSources {
  const { positionals } = parseOptions(args, tool === "scp" ? SCP_OPTIONS : RSYNC_OPTIONS);
  const sources: TransferSources = { remote: [], local: [] };
  for (const source of positionals.slice(0, -1)) {
    const path = remotePath(source);
    if (path === undefined) {
      sources.local.push(source);
    } else {
      sources.remote.push(path);
    }
  }
  return sources;
}

function sftpSources(args: readonly string[], stdin: string | undefined): string[] {
  const { positionals } = parseOptions(args, SFTP_OPTIONS);
  const sources: string[] = [];
  const path = remotePath(positionals[0] ?? "");
  if (path) sources.push(path);
  for (const line of (stdin ?? "").split("\n")) {
    const fetched = /^\s*(?:get|mget|reget)\s+(?:-\S+\s+)*(\S+)/.exec(line)?.[1];
    if (fetched) sources.push(fetched);
  }
  return sources;
}

function classifyInvocation(invocation: RemoteInvocation, depth: number): Verdict {
  if (invocation.tool !== "ssh") {
    const secret = invocation.sources.find((source) => isSecretPath(source));
    return secret === undefined ? ALLOW : deny("secret-file", quote(secret));
  }
  if (invocation.command !== undefined) {
    return walkScript(invocation.command, remoteScope(depth, { stdin: invocation.stdin }));
  }
  return invocation.stdin === undefined
    ? ALLOW
    : walkScript(invocation.stdin, remoteScope(depth, {}));
}

function remoteScope(
  depth: number,
  context: { cwd?: string | undefined; stdin?: string | undefined },
): Scope {
  return {
    remote: true,
    depth,
    cwd: context.cwd,
    vars: new Map(),
    stdin: context.stdin,
    toFile: false,
    toSink: false,
    implied: [],
    found: [],
  };
}

function walkTransport(
  name: string,
  args: readonly string[],
  frame: Frame,
  scope: Scope,
): Verdict | undefined {
  let invocation: RemoteInvocation;
  let localSources: string[] = [];
  if (name === "ssh" || name === "autossh") {
    invocation = sshInvocation(
      args.map((arg) => withKnownVariables(arg, scope.vars)),
      frame.stdin,
    );
  } else if (name === "scp" || name === "rsync") {
    const sources = transferSources(name, args);
    invocation = { tool: name, sources: sources.remote };
    localSources = sources.local;
  } else if (name === "sftp") {
    invocation = { tool: "sftp", sources: sftpSources(args, frame.stdin) };
  } else {
    return undefined;
  }

  if (!scope.remote) {
    scope.found.push(invocation);
    return ALLOW;
  }
  const local = findSecretPath([...localSources, ...frame.implied], scope);
  return local === undefined ? classifyInvocation(invocation, scope.depth + 1) : denyPath(local);
}

const SHELLS = new Set(["bash", "sh", "zsh", "dash", "ash", "ksh", "fish"]);
const KEYWORDS = new Set(words("if then elif else fi do done while until esac function ! { }"));

const PREFIX_WRAPPERS = new Map<string, OptionSpec & { skip?: number }>(
  Object.entries({
    sudo: {
      short: "ugpCDhrtTUR",
      long: ["user", "group", "prompt", "chdir", "host", "role", "type", "other-user", "chroot"],
    },
    doas: { short: "uC" },
    nohup: {},
    time: { short: "fo" },
    exec: { short: "a" },
    command: {},
    builtin: {},
    setsid: {},
    chronic: {},
    unbuffer: {},
    nice: { short: "n", long: ["adjustment"] },
    ionice: { short: "cnp", long: ["class", "classdata", "pid"] },
    stdbuf: { short: "ioe", long: ["input", "output", "error"] },
    timeout: { short: "sk", long: ["signal", "kill-after"], skip: 1 },
    chroot: { long: ["userspec", "groups"], skip: 1 },
    sshpass: { short: "pfdP" },
  }),
);

const ENV_OPTIONS: OptionSpec = { short: "uCS", long: ["unset", "chdir", "split-string"] };
const XARGS_OPTIONS: OptionSpec = {
  short: "IiLlnPsEeda",
  long: ["replace", "max-lines", "max-args", "max-procs", "max-chars", "delimiter", "arg-file"],
};
const SU_OPTIONS: OptionSpec = {
  short: "cgGsuw",
  long: ["command", "group", "supp-group", "shell", "user", "whitelist-environment"],
};

function nested(scope: Scope, frame: Frame): Scope {
  return {
    ...scope,
    depth: scope.depth + 1,
    stdin: undefined,
    toFile: frame.toFile,
    toSink: frame.toSink,
    implied: frame.implied,
  };
}

function walkPipedScript(frame: Frame, scope: Scope): Verdict {
  return frame.stdin === undefined ? ALLOW : walkScript(frame.stdin, nested(scope, frame));
}

function walkShell(args: readonly string[], frame: Frame, scope: Scope): Verdict {
  let takesCommand = false;
  let readsStdin = false;
  for (let i = 0; i < args.length; i++) {
    const arg = args[i] ?? "";
    if (arg === "--rcfile" || arg === "--init-file") {
      i++;
    } else if (/^[-+][A-Za-z]+$/.test(arg)) {
      takesCommand ||= arg.includes("c");
      readsStdin ||= arg.includes("s");
      if (arg.endsWith("o")) i++;
    } else if (!arg.startsWith("--")) {
      if (takesCommand) return walkScript(arg, nested(scope, frame));
      if (!readsStdin) return ALLOW;
    }
  }
  return walkPipedScript(frame, scope);
}

function walkEnv(args: readonly string[], frame: Frame, scope: Scope): Verdict {
  const options = parseOptions(args, ENV_OPTIONS, true);
  const split = optionValues(options, ["S", "split-string"])[0];
  if (split !== undefined) return walkScript(split, nested(scope, frame));

  const command = withoutAssignments(options.positionals.filter((word) => word !== "-"));
  if (command.length > 0) return walkWords(command, frame, scope);
  return scope.remote && !frame.toSink ? deny("env-dump", "`env`") : ALLOW;
}

function walkFind(args: readonly string[], frame: Frame, scope: Scope): Verdict {
  const firstTest = args.findIndex((arg) => /^[-(!]/.test(arg));
  const roots = (firstTest === -1 ? args : args.slice(0, firstTest)).filter(Boolean);
  const patterns: string[] = [];
  const actions: string[][] = [];

  for (let i = Math.max(firstTest, 0); i < args.length; i++) {
    const arg = args[i] ?? "";
    if (/^-(?:i?name|i?path|i?wholename|i?regex)$/.test(arg)) {
      patterns.push(args[++i] ?? "");
    } else if (/^-(?:exec|execdir|ok|okdir)$/.test(arg)) {
      const action: string[] = [];
      for (i++; i < args.length && args[i] !== ";" && args[i] !== "+"; i++) {
        if (args[i] !== "{}") action.push(args[i] ?? "");
      }
      actions.push(action);
    }
  }

  const matches = [
    ...roots,
    ...patterns,
    ...roots.flatMap((root) => patterns.map((pattern) => `${root}/${pattern}`)),
  ];
  for (const action of actions) {
    const verdict = walkWords(action, { ...frame, implied: matches }, scope);
    if (verdict.decision === "deny") return verdict;
  }
  return ALLOW;
}

/**
 * `docker run` and `kubectl exec` put the command behind options this guard
 * does not model, so every position that could start it is tried.
 */
function walkContainerCommand(args: readonly string[], frame: Frame, scope: Scope): Verdict {
  const separator = args.indexOf("--");
  if (separator !== -1) return walkWords(args.slice(separator + 1), frame, scope);

  for (let i = 0; i < args.length; i++) {
    if ((args[i] ?? "").startsWith("-")) continue;
    const verdict = walkWords(args.slice(i), frame, scope);
    if (verdict.decision === "deny") return verdict;
  }
  return ALLOW;
}

const SECRET_TEMPLATE_FIELDS = /\b(?:Env|Args|Labels)\b/;
const WHOLE_OBJECTS = new Set(
  words("Config Spec PreviousSpec TaskTemplate ContainerSpec ContainerConfig"),
);
const TEMPLATE_FIELD = /\.[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*/g;

/** True when a `docker inspect` Go template cannot print the environment, arguments or labels. */
export function isSafeInspectTemplate(template: string): boolean {
  if (!template.includes("{{") || SECRET_TEMPLATE_FIELDS.test(template)) return false;
  for (const field of template.match(TEMPLATE_FIELD) ?? []) {
    if (WHOLE_OBJECTS.has(field.slice(field.lastIndexOf(".") + 1))) return false;
  }
  // What is left after the field paths can only name the whole object: "." or "$".
  const rest = template
    .replace(/"(?:[^"\\]|\\.)*"|`[^`]*`/g, "")
    .replace(TEMPLATE_FIELD, "")
    .replace(/\$[A-Za-z_][A-Za-z0-9_]*/g, "");
  return !/[.$]/.test(rest);
}

const DOCKER_GLOBAL: OptionSpec = {
  short: "Hcl",
  long: ["host", "context", "config", "log-level", "tlscacert", "tlscert", "tlskey"],
};
const COMPOSE_GLOBAL: OptionSpec = {
  short: "fp",
  long: words("file project-name project-directory env-file profile ansi progress parallel"),
};
const INSPECT_OPTIONS: OptionSpec = { short: "f", long: ["format", "type"] };
const EXEC_OPTIONS: OptionSpec = {
  short: "euw",
  long: ["env", "env-file", "user", "workdir", "detach-keys", "index"],
};
const COMPOSE_CONFIG_NAMES_ONLY = ["services", "volumes", "profiles", "images", "quiet", "q"];
const INSPECTED_OBJECTS = new Set(["container", "service", "image"]);

function walkInspect(subject: string, args: readonly string[]): Verdict {
  const options = parseOptions(args, INSPECT_OPTIONS);
  const templates = optionValues(options, ["f", "format"]);
  return templates.length > 0 && templates.every(isSafeInspectTemplate)
    ? ALLOW
    : deny("docker-inspect", `\`${subject}\``);
}

function copiesOutOfContainer(args: readonly string[]): boolean {
  const { positionals } = parseOptions(args, {});
  return (positionals[0] ?? "").includes(":");
}

function walkExec(args: readonly string[], frame: Frame, scope: Scope): Verdict {
  const [, ...command] = parseOptions(args, EXEC_OPTIONS, true).positionals;
  return walkWords(command, frame, scope);
}

function walkCompose(args: readonly string[], frame: Frame, scope: Scope): Verdict {
  const [sub, ...rest] = parseOptions(args, COMPOSE_GLOBAL, true).positionals;
  if (sub === "config") {
    const { flags } = parseOptions(rest, {});
    return COMPOSE_CONFIG_NAMES_ONLY.some((flag) => flags.has(flag))
      ? ALLOW
      : deny("docker-config", "`docker compose config`");
  }
  if (sub === "exec") return walkExec(rest, frame, scope);
  if (sub === "run") return walkContainerCommand(rest, frame, scope);
  if (sub === "cp" && copiesOutOfContainer(rest)) return deny("docker-cp", "`docker compose cp`");
  return ALLOW;
}

function walkDocker(args: readonly string[], frame: Frame, scope: Scope): Verdict {
  const [first, second, ...others] = parseOptions(args, DOCKER_GLOBAL, true).positionals;
  if (first === undefined) return ALLOW;
  if (first === "compose")
    return walkCompose([second ?? "", ...others].filter(Boolean), frame, scope);

  const grouped = second !== undefined && INSPECTED_OBJECTS.has(first);
  const sub = grouped ? second : first;
  const rest = grouped ? others : [second ?? "", ...others].filter(Boolean);
  const subject = grouped ? `docker ${first} ${sub}` : `docker ${sub}`;

  if (first === "config" && second === "inspect")
    return deny("docker-config", "`docker config inspect`");
  if (first === "stack" && second === "config")
    return deny("docker-config", "`docker stack config`");
  if (sub === "inspect" && (grouped || first === "inspect")) return walkInspect(subject, rest);
  if (sub === "export" || sub === "save") return deny("docker-export", `\`${subject}\``);
  if (sub === "cp" && copiesOutOfContainer(rest)) return deny("docker-cp", `\`${subject}\``);
  if (sub === "exec") return walkExec(rest, frame, scope);
  if (sub === "run") return walkContainerCommand(rest, frame, scope);
  return ALLOW;
}

interface ReaderSpec extends OptionSpec {
  /** The first positional is a pattern or program unless one of these options supplied it. */
  program?: readonly string[];
  /** Only the sources of a copy are read; the last positional is where it goes. */
  copies?: boolean;
  /** Its output is not what it read, so a pipe into a sink does not excuse it. */
  keepsOutput?: boolean;
}

const PLAIN: ReaderSpec = {};
const GREP: ReaderSpec = {
  short: "efmABCdD",
  long: words(
    "regexp file max-count after-context before-context context include exclude exclude-dir",
  ),
  program: ["e", "f", "regexp", "file"],
};
const RIPGREP: ReaderSpec = {
  short: "efmABCgtTjM",
  long: words("regexp file max-count after-context before-context context glob type"),
  program: ["e", "f", "regexp", "file"],
};
const AWK: ReaderSpec = {
  short: "Fvf",
  long: ["field-separator", "assign", "file"],
  program: ["f", "file"],
};
const IN_PLACE: ReaderSpec = { keepsOutput: true };
const COPY: ReaderSpec = {
  short: "tS",
  long: ["target-directory", "suffix"],
  copies: true,
  keepsOutput: true,
};

const READERS = new Map<string, ReaderSpec>(
  Object.entries({
    cat: PLAIN,
    tac: PLAIN,
    nl: PLAIN,
    less: PLAIN,
    more: PLAIN,
    bat: PLAIN,
    batcat: PLAIN,
    diff: PLAIN,
    gzip: PLAIN,
    gunzip: PLAIN,
    zcat: PLAIN,
    bzip2: PLAIN,
    bzcat: PLAIN,
    xz: PLAIN,
    xzcat: PLAIN,
    zstd: PLAIN,
    zstdcat: PLAIN,
    strings: { short: "nte" },
    xxd: { short: "clsgo" },
    od: { short: "AjNtwS" },
    hexdump: { short: "nsef" },
    base64: { short: "w" },
    base32: { short: "w" },
    head: { short: "nc", long: ["lines", "bytes"] },
    tail: { short: "ncs", long: ["lines", "bytes", "pid", "sleep-interval"] },
    cut: {
      short: "dfcb",
      long: ["delimiter", "fields", "characters", "bytes", "output-delimiter"],
    },
    sort: {
      short: "ktSTo",
      long: ["key", "field-separator", "buffer-size", "temporary-directory", "output", "parallel"],
    },
    uniq: { short: "fsw" },
    grep: GREP,
    egrep: GREP,
    fgrep: GREP,
    zgrep: GREP,
    rg: RIPGREP,
    ag: RIPGREP,
    awk: AWK,
    gawk: AWK,
    mawk: AWK,
    sed: {
      short: "efl",
      long: ["expression", "file", "line-length"],
      program: ["e", "f", "expression", "file"],
    },
    jq: {
      short: "fL",
      long: ["from-file", "indent", "arg", "argjson", "slurpfile", "rawfile"],
      program: ["f", "from-file"],
    },
    yq: { program: [] },
    tee: IN_PLACE,
    zip: IN_PLACE,
    vi: IN_PLACE,
    vim: IN_PLACE,
    nvim: IN_PLACE,
    nano: IN_PLACE,
    view: IN_PLACE,
    cp: COPY,
    mv: COPY,
  }),
);

const GREP_NAMES = new Set(["grep", "egrep", "fgrep", "zgrep", "rg", "ag"]);
const GREP_SILENT_FLAGS = [
  "c",
  "q",
  "l",
  "L",
  "count",
  "quiet",
  "silent",
  "files-with-matches",
  "files-without-match",
];

interface Interpreter extends OptionSpec {
  names: RegExp;
  code: readonly string[];
  /** Expression that stands for the whole environment. */
  wholeEnvironment: RegExp;
}

const INTERPRETERS: Interpreter[] = [
  {
    names: /^(?:python|pypy)[\d.]*$/,
    short: "cmWXQ",
    code: ["c"],
    wholeEnvironment: /\bos\.environ\b(?!\s*(?:\[|\.get\b))/,
  },
  {
    names: /^(?:node|nodejs|bun|deno)$/,
    short: "epr",
    long: ["eval", "print", "require"],
    code: ["e", "p", "eval", "print"],
    wholeEnvironment: /\bprocess\.env\b(?!\s*(?:\.[A-Za-z_]|\[))/,
  },
  {
    names: /^perl[\d.]*$/,
    short: "eEIM",
    code: ["e", "E"],
    wholeEnvironment: /%ENV\b/,
  },
  {
    names: /^ruby[\d.]*$/,
    short: "eIr",
    code: ["e"],
    wholeEnvironment: /\bENV\b(?!\s*(?:\[|\.fetch\b))/,
  },
  {
    names: /^php[\d.]*$/,
    short: "rfdc",
    code: ["r"],
    wholeEnvironment: /\$_(?:ENV|SERVER)\b(?!\s*\[)|\bgetenv\(\s*\)/,
  },
];

const ENVIRONMENT_ACCESS = [
  /process\.env\.([A-Za-z_][A-Za-z0-9_]*)/g,
  /process\.env\[\s*['"]([^'"]+)['"]\s*\]/g,
  /os\.environ(?:\.get)?\s*[[(]\s*['"]([^'"]+)['"]/g,
  /os\.getenv\(\s*['"]([^'"]+)['"]/g,
  /\bENV(?:\.fetch)?\s*[[(]\s*['"]([^'"]+)['"]/g,
  /\$ENV\{\s*['"]?([A-Za-z_][A-Za-z0-9_]*)['"]?\s*\}/g,
  /\bgetenv\(\s*['"]([^'"]+)['"]/g,
  /\$_(?:ENV|SERVER)\[\s*['"]([^'"]+)['"]\s*\]/g,
];
const PRINT_CALL =
  /\b(?:console\.\w+|process\.std(?:out|err)\.write|print|println|printf|puts|echo|say|var_dump|print_r)\b/;

function walkInterpreter(
  interpreter: Interpreter,
  name: string,
  args: readonly string[],
  frame: Frame,
  scope: Scope,
): Verdict {
  const options = parseOptions(args, interpreter, true);
  for (const code of optionValues(options, interpreter.code)) {
    if (interpreter.wholeEnvironment.test(code)) return deny("env-dump", quote(`${name} ${code}`));

    for (const pattern of ENVIRONMENT_ACCESS) {
      for (const match of code.matchAll(pattern)) {
        const statementStart = Math.max(
          code.lastIndexOf(";", match.index),
          code.lastIndexOf("\n", match.index),
        );
        const printed = PRINT_CALL.test(code.slice(statementStart + 1, match.index));
        if (printed && holdsSecret(match[1] ?? "")) {
          return deny("secret-variable", quote(match[0]));
        }
      }
    }

    const literals = [...code.matchAll(/(['"`])((?:(?!\1)[^\\\n]|\\.)*)\1/g)].map(
      (match) => match[2] ?? "",
    );
    const secret = findSecretPath(literals, scope);
    if (secret !== undefined) return denyPath(secret);
  }

  if (frame.toSink) return ALLOW;
  const secret = findSecretPath([...options.positionals, ...frame.implied], scope);
  return secret === undefined ? ALLOW : denyPath(secret);
}

function tarPaths(args: readonly string[]): string[] {
  const paths: string[] = [];
  let creates = false;
  let lists = false;
  for (let i = 0; i < args.length; i++) {
    const arg = args[i] ?? "";
    const cluster = /^-?([A-Za-z]+)$/.exec(arg)?.[1];
    if (arg === "--list") {
      lists = true;
    } else if (arg === "--create" || arg === "--append" || arg === "--update") {
      creates = true;
    } else if (arg === "-C" || arg === "--directory" || arg === "--exclude") {
      i++;
    } else if (arg === "--file") {
      const archive = args[++i] ?? "";
      if (!creates) paths.push(archive);
    } else if (arg.startsWith("--file=")) {
      if (!creates) paths.push(arg.slice("--file=".length));
    } else if (cluster !== undefined && (arg.startsWith("-") || i === 0)) {
      creates ||= /[cru]/.test(cluster);
      lists ||= cluster.includes("t");
      if (cluster.includes("f")) {
        const archive = args[++i] ?? "";
        if (!creates) paths.push(archive);
      }
    } else if (!arg.startsWith("-")) {
      paths.push(arg);
    }
  }
  // Listing an archive prints member names only.
  return lists ? [] : paths;
}

function readerPaths(name: string, args: readonly string[]): string[] | undefined {
  if (name === "tar") return tarPaths(args);
  if (name === "dd") {
    return args.filter((arg) => arg.startsWith("if=")).map((arg) => arg.slice("if=".length));
  }

  const spec = READERS.get(name);
  if (spec === undefined) return undefined;
  const options = parseOptions(args, spec);
  if (GREP_NAMES.has(name) && GREP_SILENT_FLAGS.some((flag) => options.flags.has(flag))) {
    return undefined;
  }

  let paths = options.positionals;
  const programGiven = spec.program?.some((option) => options.values.has(option));
  if (spec.program !== undefined && !programGiven) paths = paths.slice(1);
  if (spec.copies && optionValues(options, ["t", "target-directory"]).length === 0) {
    paths = paths.slice(0, -1);
  }
  return paths;
}

function walkReader(name: string, args: readonly string[], frame: Frame, scope: Scope): Verdict {
  const paths = readerPaths(name, args);
  if (paths === undefined) return ALLOW;

  const keepsOutput = READERS.get(name)?.keepsOutput === true;
  if (frame.toSink && !keepsOutput) return ALLOW;
  const secret = findSecretPath([...paths, ...frame.implied], scope);
  return secret === undefined ? ALLOW : denyPath(secret);
}

const SQL_FUNCTIONS = new Set(
  words(
    "count sum max min avg round coalesce cast extract now age date_trunc version current_database database pg_size_pretty pg_database_size pg_total_relation_size pg_relation_size pg_table_size pg_indexes_size pg_is_in_recovery pg_postmaster_start_time",
  ),
);
const SQL_KEYWORDS_BEFORE_PAREN = new Set(
  words("in and or not on as over any all interval numeric varchar char decimal"),
);
const METADATA_RELATION =
  /^(?:(?:pg_catalog\.)?(?:pg_stat\w*|pg_database|pg_tables|pg_indexes|pg_class|pg_namespace|pg_extension)|information_schema\.\w+)$/;
const PSQL_META_COMMAND = /^\\(?:d[A-Za-z]*\+?|l\+?|conninfo|x)(?:\s+[\w.*"$-]+)*$/;
const COUNT_ONLY = /^select\s+count\(\s*(?:\*|1)\s*\)(?:\s+(?:as\s+)?[a-z_]\w*)?\s+from\b/;
const WRITE_STATEMENT =
  /^(?:insert|update|delete|create|alter|drop|truncate|grant|revoke|vacuum|analyze|reindex|refresh|comment|set|reset|begin|start|commit|rollback|end|use|cluster|checkpoint|discard|lock|savepoint|release|flush|optimize|rename|kill)\b/;

function selectRelations(statement: string): string[] {
  const from = /\bfrom\b/.exec(statement);
  if (!from) return [];
  const clause =
    statement
      .slice(from.index + "from".length)
      .split(/\b(?:where|group\s+by|order\s+by|limit|having|offset|window|fetch)\b/)[0] ?? "";
  return clause
    .split(/,|\b(?:(?:left|right|full|inner|cross|natural|outer)\s+)*join\b/)
    .map((part) => (part.trim().split(/\s+/)[0] ?? "").replace(/["`]/g, ""));
}

function isMetadataSelect(statement: string): boolean {
  if (/\b(?:union|intersect|except|into|returning)\b/.test(statement)) return false;
  if ((statement.match(/\bselect\b/g) ?? []).length !== 1) return false;
  if (COUNT_ONLY.test(statement)) return true;

  for (const match of statement.matchAll(/([a-z_][a-z0-9_.]*)\s*\(/g)) {
    const called = (match[1] ?? "").replace(/^pg_catalog\./, "");
    if (!SQL_FUNCTIONS.has(called) && !SQL_KEYWORDS_BEFORE_PAREN.has(called)) return false;
  }
  return selectRelations(statement).every((relation) => METADATA_RELATION.test(relation));
}

function sqlStatements(sql: string): string[] {
  return sql
    .replace(/\/\*[\s\S]*?\*\//g, " ")
    .replace(/--[^\n]*/g, " ")
    .split(/;|\n(?=\s*\\)/)
    .map((statement) => statement.replace(/\s+/g, " ").trim())
    .filter(Boolean);
}

/** True when no statement of the SQL text can return rows of user data. */
export function isHarmlessSql(sql: string, allowWrites = true): boolean {
  const statements = sqlStatements(sql);
  return (
    statements.length > 0 &&
    statements.every((statement) => {
      const lower = statement.toLowerCase();
      if (PSQL_META_COMMAND.test(statement)) return true;
      if (/^show\b/.test(lower) || /^(?:describe|desc)\s+[\w.`"]+$/.test(lower)) return true;
      if (/^explain\b/.test(lower)) return !/\bselect\b[\s\S]*\bselect\b/.test(lower);
      if (/^select\b/.test(lower)) return isMetadataSelect(lower);
      return allowWrites && WRITE_STATEMENT.test(lower) && !/\breturning\b/.test(lower);
    })
  );
}

const MONGO_DATABASE = String.raw`db(?:\.getSiblingDB\(\s*['"][\w-]+['"]\s*\))?`;
const MONGO_HARMLESS = [
  /^show\s+(?:dbs|databases|collections|tables)$/,
  new RegExp(
    `^${MONGO_DATABASE}\\.(?:stats|getCollectionNames|getCollectionInfos|getName|version|serverStatus|hostInfo)\\(\\s*\\)$`,
  ),
  new RegExp(
    `^${MONGO_DATABASE}\\.(?:getCollection\\(\\s*['"][\\w.-]+['"]\\s*\\)|[\\w-]+)\\.(?:countDocuments|estimatedDocumentCount|count|stats|getIndexes|totalSize|dataSize|storageSize|totalIndexSize)\\([^()]*\\)$`,
  ),
  /^rs\.status\(\s*\)$/,
  /^db\.adminCommand\(\s*\{\s*(?:ping|listDatabases)\s*:\s*1\s*\}\s*\)$/,
];

function isHarmlessMongo(script: string): boolean {
  const statements = script
    .split(/;|\n/)
    .map((statement) => statement.trim())
    .filter(Boolean);
  return (
    statements.length > 0 &&
    statements.every((statement) => {
      const inner = /^(?:printjson|print|JSON\.stringify)\(([\s\S]*)\)$/.exec(statement)?.[1];
      const expression = (inner ?? statement).trim();
      return MONGO_HARMLESS.some((pattern) => pattern.test(expression));
    })
  );
}

const SQL_CLIENTS = new Map<string, OptionSpec & { query: readonly string[] }>(
  Object.entries({
    psql: {
      short: "cdfhpUvoFRPLT",
      long: ["command", "dbname", "file", "host", "port", "username", "set", "variable", "output"],
      query: ["c", "command"],
    },
    mysql: {
      short: "euhPDS",
      attachedOnly: "p",
      long: ["execute", "user", "host", "port", "database", "socket", "password"],
      query: ["e", "execute"],
    },
  }),
);
const MONGO_OPTIONS: OptionSpec = {
  short: "up",
  long: ["eval", "host", "port", "username", "password", "authenticationDatabase", "file"],
};
const REDIS_OPTIONS: OptionSpec = {
  short: "hpsaurindDt",
  long: ["user", "pass", "sni", "cacert", "cacertdir", "cert", "key", "pattern", "count", "rdb"],
};
const REDIS_READS = new Set(
  words(
    "KEYS SCAN GET MGET GETRANGE GETEX GETDEL HGET HGETALL HMGET HVALS LRANGE SMEMBERS ZRANGE XRANGE XREAD DUMP MONITOR",
  ),
);
const REDIS_READ_PAIRS = new Set(["CONFIG GET", "ACL LIST", "ACL GETUSER", "ACL USERS"]);

function readsRedis(words: readonly string[]): boolean {
  const [first = "", second = ""] = words.map((word) => word.toUpperCase());
  return REDIS_READS.has(first) || REDIS_READ_PAIRS.has(`${first} ${second}`);
}

function hasOption(args: readonly string[], short: string, long: string): boolean {
  return args.some(
    (arg) => arg === long || arg.startsWith(`${long}=`) || new RegExp(`^-${short}`).test(arg),
  );
}

function walkDatabase(name: string, args: readonly string[], frame: Frame): Verdict | undefined {
  const shown = quote([name, ...args].join(" "));
  const hidden = frame.toFile || frame.toSink;

  if (name === "pg_dump" || name === "pg_dumpall") {
    return hidden || hasOption(args, "f", "--file") ? ALLOW : deny("db-dump", shown);
  }
  if (name === "mysqldump" || name === "mariadb-dump") {
    return hidden || hasOption(args, "r", "--result-file") ? ALLOW : deny("db-dump", shown);
  }
  if (name === "mongodump") {
    const toStdout = args.some(
      (arg) => arg === "--archive" || /^(?:--archive|--out|-o)=?-$/.test(arg),
    );
    return toStdout && !hidden ? deny("db-dump", shown) : ALLOW;
  }

  const client = SQL_CLIENTS.get(name === "mariadb" ? "mysql" : name);
  if (client !== undefined) {
    const inline = optionValues(parseOptions(args, client), client.query);
    const queries = inline.length > 0 || frame.stdin === undefined ? inline : [frame.stdin];
    return hidden || queries.every((query) => isHarmlessSql(query))
      ? ALLOW
      : deny("db-query", shown);
  }

  if (name === "mongosh" || name === "mongo") {
    const inline = optionValues(parseOptions(args, MONGO_OPTIONS), ["eval"]);
    const scripts = inline.length > 0 || frame.stdin === undefined ? inline : [frame.stdin];
    return hidden || scripts.every(isHarmlessMongo) ? ALLOW : deny("db-query", shown);
  }

  if (name === "redis-cli") {
    const options = parseOptions(args, REDIS_OPTIONS, true);
    const piped = (frame.stdin ?? "").split("\n").map((line) => line.trim().split(/\s+/));
    const reads =
      options.flags.has("scan") ||
      (options.positionals.length > 0 ? readsRedis(options.positionals) : piped.some(readsRedis));
    return reads && !hidden ? deny("redis-read", shown) : ALLOW;
  }
  return undefined;
}

const PS_VALUED = "oOpCuUgGtqk";
const PS_LONG_VALUED =
  /^--(?:pid|ppid|user|User|group|Group|sid|tty|sort|format|cols|columns|rows|lines|width)$/;

function showsProcessEnvironment(args: readonly string[]): boolean {
  for (let i = 0; i < args.length; i++) {
    const arg = args[i] ?? "";
    if (arg.startsWith("--")) {
      if (PS_LONG_VALUED.test(arg)) i++;
    } else if (arg.startsWith("-")) {
      if (arg.includes("E")) return true;
      if (PS_VALUED.includes(arg[arg.length - 1] ?? "")) i++;
    } else if (/^[A-Za-z]+$/.test(arg)) {
      if (arg.includes("e")) return true;
      if (/[oOpUt]$/.test(arg)) i++;
    }
  }
  return false;
}

const VARIABLE_REFERENCE =
  /\$(?:\{([#!]?)([A-Za-z_][A-Za-z0-9_]*)([^}]*)\}|([A-Za-z_][A-Za-z0-9_]*))/g;

function printedSecretVariable(args: readonly string[]): string | undefined {
  for (const arg of args) {
    for (const match of arg.matchAll(VARIABLE_REFERENCE)) {
      const [, prefix, braced, operator = "", bare] = match;
      // "${#NAME}" is a length and "${NAME:+text}" prints text, not the value.
      if (prefix === "#" || /^:?\+/.test(operator)) continue;
      const name = braced ?? bare ?? "";
      if (holdsSecret(name)) return name;
    }
  }
  return undefined;
}

function walkEnvironmentBuiltins(
  name: string,
  args: readonly string[],
  frame: Frame,
): Verdict | undefined {
  const shown = quote([name, ...args].join(" "));
  const positionals = args.filter((arg) => !arg.startsWith("-"));

  switch (name) {
    case "printenv": {
      if (frame.toSink) return ALLOW;
      if (positionals.length === 0) return deny("env-dump", shown);
      const secret = positionals.find(holdsSecret);
      return secret === undefined ? ALLOW : deny("secret-variable", `\`printenv ${secret}\``);
    }
    case "export":
      return args.length === 0 || args.includes("-p") ? deny("env-dump", shown) : ALLOW;
    case "set":
      return args.length === 0 ? deny("env-dump", "`set`") : ALLOW;
    case "declare":
    case "typeset": {
      const flags = args.filter((arg) => /^-[A-Za-z]+$/.test(arg)).join("");
      const dumps = flags.includes("p") || positionals.length === 0;
      return dumps ? deny("env-dump", shown) : ALLOW;
    }
    case "compgen": {
      const lists = args.some(
        (arg, index) =>
          /^-[A-Za-z]*[ev]/.test(arg) ||
          (arg === "-A" && /^(?:export|variable)$/.test(args[index + 1] ?? "")),
      );
      return lists ? deny("env-dump", shown) : ALLOW;
    }
    case "ps":
      return showsProcessEnvironment(args) ? deny("env-dump", shown) : ALLOW;
    case "echo":
    case "printf": {
      if (frame.toFile || frame.toSink) return ALLOW;
      const secret = printedSecretVariable(args);
      return secret === undefined ? ALLOW : deny("secret-variable", `\`${name} $${secret}\``);
    }
    default:
      return undefined;
  }
}

function recordVariable(scope: Scope, word: string): boolean {
  const match = ASSIGNMENT.exec(word);
  if (!match) return false;
  const name = match[1] ?? "";
  const earlier = (scope.vars.get(name) ?? []).slice(1 - MAX_VARIABLE_VALUES);
  scope.vars.set(name, [...earlier, match[2] ?? ""]);
  return true;
}

function walkWords(input: readonly string[], frame: Frame, scope: Scope): Verdict {
  let start = 0;
  while (start < input.length) {
    const word = input[start] ?? "";
    if (!KEYWORDS.has(word) && !recordVariable(scope, word)) break;
    start++;
  }
  const [first, ...args] = input.slice(start);
  if (first === undefined) return ALLOW;
  const name = commandName(first);

  if (name === "for" && args[1] === "in") {
    scope.vars.set(args[0] ?? "", args.slice(2));
    return ALLOW;
  }
  if (name === "cd") {
    const target = args.find((arg) => !arg.startsWith("-"));
    scope.cwd = target === undefined ? undefined : normalizePath(target, scope.cwd);
    return ALLOW;
  }
  if (name === "export" || name === "declare" || name === "typeset" || name === "local") {
    for (const arg of args) recordVariable(scope, arg);
  }

  const wrapper = PREFIX_WRAPPERS.get(name);
  if (wrapper !== undefined) {
    const rest = parseOptions(args, wrapper, true).positionals.slice(wrapper.skip ?? 0);
    // "sudo -i" with nothing after it starts a shell that reads the piped text.
    return rest.length === 0 ? walkPipedScript(frame, scope) : walkWords(rest, frame, scope);
  }
  if (name === "env") return walkEnv(args, frame, scope);
  if (SHELLS.has(name)) return walkShell(args, frame, scope);
  if (name === "eval" || name === "watch") {
    const words = name === "watch" ? parseOptions(args, { short: "n" }, true).positionals : args;
    return walkScript(words.join(" "), nested(scope, frame));
  }
  if (name === "su" || name === "runuser") {
    const options = parseOptions(args, SU_OPTIONS);
    const command = optionValues(options, ["c", "command"])[0];
    if (command !== undefined) return walkScript(command, nested(scope, frame));
    return name === "runuser" && options.positionals.length > 0
      ? walkWords(options.positionals, frame, scope)
      : walkPipedScript(frame, scope);
  }
  if (name === "xargs") {
    const rest = parseOptions(args, XARGS_OPTIONS, true).positionals;
    return walkWords(rest, { ...frame, implied: [...frame.implied, ...frame.upstream()] }, scope);
  }
  if (name === "find") return scope.remote ? walkFind(args, frame, scope) : ALLOW;

  const transported = walkTransport(name, args, frame, scope);
  if (transported !== undefined) return transported;
  if (!scope.remote) return ALLOW;

  if (name === "docker" || name === "podman" || name === "nerdctl") {
    return walkDocker(args, frame, scope);
  }
  if (name === "docker-compose") return walkCompose(args, frame, scope);
  if (name === "kubectl" && args.includes("exec")) {
    return walkContainerCommand(args.slice(args.indexOf("exec") + 1), frame, scope);
  }

  const environment = findSecretPath(
    args.filter((arg) => PROC_ENVIRON.test(arg)),
    scope,
  );
  if (environment !== undefined && !frame.toSink) return denyPath(environment);

  const builtin = walkEnvironmentBuiltins(name, args, frame);
  if (builtin !== undefined) return builtin;
  const database = walkDatabase(name, args, frame);
  if (database !== undefined) return database;

  const interpreter = INTERPRETERS.find((candidate) => candidate.names.test(name));
  if (interpreter !== undefined) return walkInterpreter(interpreter, name, args, frame, scope);
  return walkReader(name, args, frame, scope);
}

function printsNothing(command: SimpleCommand): boolean {
  const [first = "", ...args] = withoutAssignments(command.words);
  const name = commandName(first);
  return isSink(command) || (GREP_NAMES.has(name) && readerPaths(name, args) === undefined);
}

function walkCommand(pipeline: readonly SimpleCommand[], index: number, scope: Scope): Verdict {
  const command = pipeline[index];
  const last = pipeline[pipeline.length - 1];
  if (command === undefined || last === undefined) return ALLOW;

  const isLast = index === pipeline.length - 1;
  const ownFile = redirectsToFile(command);
  const frame: Frame = {
    toFile: ownFile || (isLast ? scope.toFile : redirectsToFile(last)),
    toSink: !ownFile && (isLast ? scope.toSink : isSink(last)),
    stdin: command.stdin ?? (index > 0 ? echoedText(pipeline[index - 1]) : scope.stdin),
    implied: scope.implied,
    upstream: () => pipeline.slice(0, index).flatMap((earlier) => earlier.words),
  };

  if (scope.remote && !printsNothing(command)) {
    const inputs = command.redirects.filter((redirect) => redirect.kind === "in");
    const secret = findSecretPath(
      inputs.map((redirect) => redirect.target),
      scope,
    );
    if (secret !== undefined) return denyPath(secret);
  }
  return walkWords(command.words, frame, scope);
}

function walkScript(source: string, scope: Scope): Verdict {
  if (scope.depth > MAX_DEPTH) return ALLOW;
  const script = parseShell(source);

  for (const substitution of script.substitutions) {
    const captured = { ...scope, depth: scope.depth + 1, stdin: undefined, toFile: false };
    const verdict = walkScript(substitution, { ...captured, toSink: false, implied: [] });
    if (verdict.decision === "deny") return verdict;
  }
  for (const pipeline of script.pipelines) {
    for (let index = 0; index < pipeline.length; index++) {
      const verdict = walkCommand(pipeline, index, scope);
      if (verdict.decision === "deny") return verdict;
    }
  }
  return ALLOW;
}

/** Decides whether shell text that runs on a server would put secret values on the terminal. */
export function classifyRemoteCommand(command: string, context: RemoteContext = {}): Verdict {
  return walkScript(command, remoteScope(0, context));
}

/** Every `ssh`, `scp`, `sftp` and `rsync` call a local command line makes, wrappers included. */
export function extractRemoteInvocations(command: string): RemoteInvocation[] {
  const scope: Scope = { ...remoteScope(0, {}), remote: false };
  walkScript(command, scope);
  return scope.found;
}

export function classifyBashCommand(command: string): Verdict {
  for (const invocation of extractRemoteInvocations(command)) {
    const verdict = classifyInvocation(invocation, 1);
    if (verdict.decision === "deny") return verdict;
  }
  return ALLOW;
}

const SSH_MCP_TOOL = /^mcp__.*ssh.*__/i;
const COMMAND_TOOLS = new Set([
  "ssh_execute",
  "ssh_execute_sudo",
  "ssh_execute_group",
  "ssh_session_send",
]);
const HOST_KEY_ACTIONS = new Set(["verify", "accept", "remove", "list", "check"]);
const GENERIC_COMMAND_FIELDS = ["command", "cmd", "script"];

export function isSshMcpTool(toolName: string): boolean {
  return SSH_MCP_TOOL.test(toolName);
}

function bareToolName(toolName: string): string {
  const separator = toolName.lastIndexOf("__");
  return separator === -1 ? toolName : toolName.slice(separator + 2);
}

function field(input: Record<string, unknown>, name: string): string | undefined {
  const value = input[name];
  return typeof value === "string" ? value : undefined;
}

/** The shell text an SSH MCP tool call would run on the server, if it carries one. */
export function extractToolCommand(
  toolName: string,
  toolInput: unknown,
): { command: string; cwd?: string } | undefined {
  if (toolInput === null || typeof toolInput !== "object") return undefined;
  const input = toolInput as Record<string, unknown>;
  const tool = bareToolName(toolName);
  if (tool === "ssh_command_alias" && field(input, "action") !== "add") return undefined;

  const names = COMMAND_TOOLS.has(tool) ? ["command"] : GENERIC_COMMAND_FIELDS;
  const command = names.map((name) => field(input, name)).find((value) => value !== undefined);
  if (command === undefined) return undefined;
  const cwd = field(input, "cwd");
  return { command, ...(cwd === undefined ? {} : { cwd }) };
}

function denySecretPath(path: string | undefined): Verdict {
  return path !== undefined && isSecretPath(path) ? denyPath(path) : ALLOW;
}

/** Decides one call of an SSH MCP tool from its name and input. */
export function classifyToolCall(toolName: string, toolInput: unknown): Verdict {
  if (toolInput === null || typeof toolInput !== "object") return ALLOW;
  const input = toolInput as Record<string, unknown>;
  const tool = bareToolName(toolName);

  switch (tool) {
    case "ssh_db_query": {
      const query = field(input, "query") ?? "";
      const metadataOnly = field(input, "type") !== "mongodb" && isHarmlessSql(query, false);
      return metadataOnly ? ALLOW : deny("db-query", quote(query));
    }
    case "ssh_db_dump": {
      const output = field(input, "outputFile") ?? "";
      return TERMINAL_TARGET.test(output)
        ? deny("db-dump", quote(`ssh_db_dump to ${output}`))
        : ALLOW;
    }
    case "ssh_download":
      return denySecretPath(field(input, "remotePath"));
    case "ssh_sync": {
      const source = field(input, "source") ?? "";
      return source.startsWith("remote:") ? denySecretPath(source.slice("remote:".length)) : ALLOW;
    }
    case "ssh_tail":
    case "ssh_monitor":
      return denySecretPath(field(input, "file") ?? field(input, "path"));
    case "ssh_key_manage": {
      const action = field(input, "action") ?? "";
      const showsPrivateKey = /private|show|export|read|print|cat|view|get/i.test(action);
      return showsPrivateKey && !HOST_KEY_ACTIONS.has(action)
        ? deny("private-key", quote(`ssh_key_manage ${action}`))
        : ALLOW;
    }
    default: {
      const extracted = extractToolCommand(toolName, toolInput);
      if (extracted === undefined) return ALLOW;
      const { command, ...context } = extracted;
      return classifyRemoteCommand(command, context);
    }
  }
}
