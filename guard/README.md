# SSH secret guard for Claude Code

The Dokploy MCP server hides secret values, but an agent that also has SSH access to a server can read the same values from a shell: `docker inspect`, `printenv`, `cat .env`. This guard is a pair of [Claude Code hooks](https://code.claude.com/docs/en/hooks) that stop the usual ways this happens **by accident**.

- **Before a call** (`PreToolUse`) it reads the command that is about to run on a server and denies the ones that would print secrets. The denial names the rule, the reason and a safe alternative, so the model can change course. It looks at the tools of an SSH MCP server (tool names matching `mcp__*ssh*__*`) and at `ssh`, `scp`, `sftp` and `rsync` in the local `Bash` tool.
- **After a call** (`PostToolUse`) it rewrites the output of the SSH MCP tools before the model sees it: values in environment dumps, `Env` lists of `docker inspect` output and everything the server's own scrubber recognises become `[REDACTED]`. Placeholders that are already there, including restorable `__DOKPLOY_REDACTED_SECRET__XXXXXXXXXXXX__` tokens, are kept as they are.

## What it is not

**This is not a security boundary.** It reads commands the way a shell would and blocks the forms an agent normally writes. An agent that deliberately encodes, splits or obfuscates a command, writes a script and runs it, or copies a file to a neutral name first is not stopped. The real boundary is the server account the agent logs in with: give it a restricted account that cannot read the secrets (no root, no membership in the `docker` group, no read access to `/etc/dokploy`).

Other limits to know about:

- **`Bash` output is not scrubbed, only blocked.** For `ssh` in the local shell the guard can deny a command before it runs, but what an allowed command prints reaches the model unchanged. The SSH MCP tools get both the check and the scrubbing, so prefer them.
- **Codex is not covered.** These are Claude Code hooks; other agents do not run them.
- **Failed calls are not scrubbed.** Claude Code lets a hook replace the output of a successful tool call only.
- **Scrubbing works from names and formats.** A secret printed on its own line with no name next to it is not recognised.
- **Environment-shaped output loses all its values.** Once an output has three or more `NAME=value` lines, every value is hidden, whatever the name. That also hits harmless output such as `/etc/os-release` or `systemctl show`; use `uname -a`, `lsb_release -ds` or `systemctl is-active` instead. Log lines in logfmt (`time=... level=info msg=...`) are left alone.
- **Only the command text is checked.** The content of a script on the server, a command alias stored in the SSH MCP server, an interactive `ssh` session, an SSH tunnel used by a local client, and tools that open their own SSH connection (`docker -H ssh://...`, `git`, `ansible`) are out of reach.
- **It fails open.** If the hook crashes, times out or cannot parse its input, it makes no decision and the call goes through the normal permission flow. It never reports output as scrubbed that it did not scrub.
- **Telemetry sees the original output.** Claude Code records tool output for OpenTelemetry spans before hooks run.

## Rules

Every rule applies to each command of a pipeline or list (`|`, `;`, `&&`, `||`), to `$(...)`, backticks, `xargs` and `find -exec`, and to the command inside `sudo`, `env NAME=value`, `nohup`, `timeout`, `bash -c`, `sh -c`, `docker exec`, `docker run`, `docker compose exec`, `docker compose run` and `kubectl exec`.

| Rule | Denied | Still allowed |
| --- | --- | --- |
| `env-dump` | `printenv`, bare `env`, `export -p`, bare `set`, `declare -p`, `declare -x`, `compgen -e`, `/proc/<pid>/environ`, `ps e` / `ps auxe`, `console.log(process.env)`, `print(os.environ)` | `env NAME=value command`, `printenv NODE_ENV`, `ps aux`, `ps -ef`, `set -e`, `export NAME=value` |
| `secret-variable` | printing a variable with a secret-looking name: `echo $DB_PASSWORD`, `printenv DATABASE_URL`, `console.log(process.env.API_KEY)` | `[ -n "$NAME" ] && echo set`, `echo ${#NAME}`, `echo ${NAME:+set}`, writing the value to a file or piping it into `docker login` |
| `docker-inspect` | `docker inspect`, `docker container\|service\|image inspect` without a format, or with a template that reaches `Env`, `Args`, `Labels`, the whole object (`json .`) or a whole `Config` / `Spec` / `TaskTemplate` / `ContainerSpec` | `--format '{{.State.Status}}'`, `'{{.RepoDigests}}'`, `'{{json .NetworkSettings.Networks}}'`, `'{{.Mounts}}'`, `'{{.Config.Image}}'`; `docker network\|volume\|node inspect` |
| `docker-config` | `docker compose config`, `docker stack config`, `docker config inspect` | `docker compose config --services\|--volumes\|--images\|--profiles\|--quiet`, `docker config ls` |
| `docker-export` | `docker export`, `docker save` | `docker image ls` |
| `docker-cp` | `docker cp CONTAINER:PATH LOCAL` | `docker cp LOCAL CONTAINER:PATH` |
| `secret-file` | reading or copying a secret file with `cat less more head tail grep rg awk sed cut sort strings xxd od hexdump base64 tee cp mv scp rsync tar zip gzip dd vi vim nano view bat jq yq python node perl ruby php` or `< file` | `ls`, `stat`, `du`, `wc -l`, `test -f`, `find ... -name`, `grep -c\|-q\|-l`, piping the file into a database client or `wc` |
| `db-dump` | `pg_dump`, `pg_dumpall`, `mysqldump`, `mongodump --archive` when the dump goes to the terminal | the same dump written on the server: `> file`, `-f file`, `--file`, `\| gzip > file`, or piped into another database or an upload tool |
| `db-query` | `psql -c`, `mysql -e`, `mongosh --eval`, a heredoc or piped query that returns rows; the `ssh_db_query` tool | `\dt`, `\l`, `\d NAME`, `SELECT count(*)`, `SELECT version()`, `SHOW ...`, `pg_size_pretty(...)`, queries on `pg_stat_*`, `information_schema` and a few catalog tables; statements that return no rows (`CREATE`, `ALTER`, `UPDATE` without `RETURNING`, `VACUUM`) |
| `redis-read` | `redis-cli KEYS\|SCAN\|GET\|MGET\|HGET\|HGETALL\|LRANGE\|SMEMBERS\|ZRANGE\|DUMP\|MONITOR\|CONFIG GET\|ACL LIST`, `--scan` | `PING`, `INFO`, `DBSIZE`, `TYPE`, `TTL`, `EXISTS` |
| `private-key` | an `ssh_key_manage` action that would show or export a private key | `verify`, `accept`, `remove`, `list`, `check` |

Secret files are: `.env`, `.env.*`, `*.env`, `.envrc`, everything under `/etc/dokploy` except `/etc/dokploy/logs`, `acme.json`, anything under a `.ssh` or `.aws` directory, `id_rsa*`, `id_ed25519*`, `*.pem`, `*.key`, `*.p12`, `*.pfx`, `/run/secrets`, `/var/lib/docker`, `.docker/config.json`, `.netrc`, `.pgpass`, `.my.cnf`, `.git-credentials`, `.npmrc`, shell history files and `/etc/shadow`. Backups in `/etc/dokploy/db-backups` can be listed and written, not read.

For the SSH MCP tools the same rules are applied to their input: `command` of `ssh_execute`, `ssh_execute_sudo`, `ssh_execute_group`, `ssh_session_send` and of `ssh_command_alias` when an alias is added (with `cwd` as the working directory); `query` of `ssh_db_query`; `outputFile` of `ssh_db_dump`; `remotePath` of `ssh_download`; a `remote:` source of `ssh_sync`; `file` of `ssh_tail`. These are the tool and field names of `mcp-ssh-manager` (checked against version 3.8.5); a tool with another name is checked when its input has a `command`, `cmd` or `script` field. Everything else is left to the normal permission flow.

## Install

The guard runs from a checkout of this repository with [Bun](https://bun.sh); it is not part of the published package. Add the hooks to `~/.claude/settings.json` (merge them with the `hooks` you already have) and replace `/ABSOLUTE/PATH/TO/dokploy-mcp` with the path of your checkout:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {
            "type": "command",
            "command": "bun /ABSOLUTE/PATH/TO/dokploy-mcp/guard/hook.ts",
            "timeout": 10
          }
        ]
      },
      {
        "matcher": "mcp__.*[sS][sS][hH].*__.*",
        "hooks": [
          {
            "type": "command",
            "command": "bun /ABSOLUTE/PATH/TO/dokploy-mcp/guard/hook.ts",
            "timeout": 10
          }
        ]
      }
    ],
    "PostToolUse": [
      {
        "matcher": "mcp__.*[sS][sS][hH].*__.*",
        "hooks": [
          {
            "type": "command",
            "command": "bun /ABSOLUTE/PATH/TO/dokploy-mcp/guard/hook.ts",
            "timeout": 10
          }
        ]
      }
    ]
  }
}
```

A matcher made only of letters is an exact tool name, so `Bash` matches the Bash tool. The other matcher is a regular expression for every tool of an MCP server whose name contains `ssh` in any letter case. If your SSH server is named differently, change it to `mcp__<server>__.*`. `bun` must be on the `PATH` Claude Code runs hooks with; otherwise write the full path of the binary. The hook prints nothing but its JSON, so check that your shell profile prints nothing either.

`updatedToolOutput` is the field Claude Code documents for replacing tool output. The hook also sends the same value as `updatedMCPToolOutput`, which older releases read for MCP tools.

## Test

Pipe a sample event into the script (`printf '%s'` keeps the `\n` inside the JSON as it is in every shell). A denied call prints the decision:

```bash
printf '%s' '{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"ssh app-1 \"docker inspect web\""}}' \
  | bun /ABSOLUTE/PATH/TO/dokploy-mcp/guard/hook.ts
```

```json
{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"ssh-secret-guard blocked this call (rule docker-inspect): `docker inspect` returns the container environment, arguments and labels, which carry secrets. Instead: Ask for the one field you need with a Go template ..."}}
```

An allowed call prints nothing and exits with 0:

```bash
printf '%s' '{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"ssh app-1 \"docker ps\""}}' \
  | bun /ABSOLUTE/PATH/TO/dokploy-mcp/guard/hook.ts
```

Scrubbing the result of an SSH MCP tool:

```bash
printf '%s' '{"hook_event_name":"PostToolUse","tool_name":"mcp__ssh_example__ssh_execute","tool_response":[{"type":"text","text":"PATH=/usr/bin\nNODE_ENV=production\nGREETING=hello"}]}' \
  | bun /ABSOLUTE/PATH/TO/dokploy-mcp/guard/hook.ts
```

```json
{"hookSpecificOutput":{"hookEventName":"PostToolUse","updatedToolOutput":[{"type":"text","text":"PATH=[REDACTED]\nNODE_ENV=[REDACTED]\nGREETING=[REDACTED]"}],"updatedMCPToolOutput":[{"type":"text","text":"PATH=[REDACTED]\nNODE_ENV=[REDACTED]\nGREETING=[REDACTED]"}],"additionalContext":"ssh-secret-guard replaced secret values in this output with [REDACTED]. ..."}}
```

The unit and end-to-end tests run with the rest of the suite: `bun test guard`.

## Files

- `shell.ts` splits shell text into commands, redirections and heredocs.
- `policy.ts` holds the rules: `classifyRemoteCommand` for shell text that runs on a server, `classifyBashCommand` for a local command line, `classifyToolCall` for an SSH MCP tool call.
- `scrub.ts` scrubs tool output and reuses the scrubber of the MCP server in `src/utils`.
- `hook.ts` is the entry Claude Code runs.
