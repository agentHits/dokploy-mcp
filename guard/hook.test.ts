import { describe, expect, it } from "bun:test";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { decide } from "./hook.js";

const HOOK = fileURLToPath(new URL("./hook.ts", import.meta.url));
const SECRET = "fake-value-7Qx";
const SSH_TOOL = "mcp__ssh_example__ssh_execute";

function runHook(stdin: string) {
  const result = spawnSync(process.execPath, [HOOK], { input: stdin, encoding: "utf8" });
  return { status: result.status, stdout: result.stdout, stderr: result.stderr };
}

function runEvent(event: Record<string, unknown>) {
  const result = runHook(JSON.stringify({ session_id: "s1", cwd: "/tmp", ...event }));
  return { ...result, json: result.stdout === "" ? undefined : JSON.parse(result.stdout) };
}

function sshResult(stdout: string) {
  const body = { server: "app-1", command: "printenv", stdout, stderr: "", code: 0, success: true };
  return [{ type: "text", text: JSON.stringify(body, null, 2) }];
}

describe("hook: PreToolUse", () => {
  it("denies a Bash command that dumps the environment of a server", () => {
    const { status, json, stderr } = runEvent({
      hook_event_name: "PreToolUse",
      tool_name: "Bash",
      tool_input: { command: "ssh app-1 'docker exec web printenv'", description: "check env" },
    });

    expect(status).toBe(0);
    expect(stderr).toBe("");
    expect(Object.keys(json)).toEqual(["hookSpecificOutput"]);
    expect(json.hookSpecificOutput.hookEventName).toBe("PreToolUse");
    expect(json.hookSpecificOutput.permissionDecision).toBe("deny");
    const reason: string = json.hookSpecificOutput.permissionDecisionReason;
    expect(reason).toStartWith(
      "ssh-secret-guard blocked this call (rule env-dump): `printenv` prints",
    );
    expect(reason).toContain("Instead: Print one non-secret variable with `printenv NAME`");
  });

  it("denies an SSH MCP call and names the rule, the reason and the alternative", () => {
    const { status, json } = runEvent({
      hook_event_name: "PreToolUse",
      tool_name: SSH_TOOL,
      tool_input: { server: "app-1", command: "docker inspect web" },
    });

    expect(status).toBe(0);
    expect(json).toEqual({
      hookSpecificOutput: {
        hookEventName: "PreToolUse",
        permissionDecision: "deny",
        permissionDecisionReason:
          "ssh-secret-guard blocked this call (rule docker-inspect): `docker inspect` returns the container environment, arguments and labels, which carry secrets. Instead: Ask for the one field you need with a Go template that leaves out Env, Args, Labels and whole Config or Spec objects, for example `--format '{{.State.Status}}'`, `'{{.Config.Image}}'` or `'{{json .NetworkSettings.Networks}}'`.",
      },
    });
  });

  it("denies the data tools of an SSH MCP server", () => {
    const calls: Array<[string, Record<string, unknown>, string]> = [
      [
        "ssh_download",
        { server: "app-1", remotePath: "/srv/app/.env", localPath: "./e" },
        "secret-file",
      ],
      ["ssh_tail", { server: "app-1", file: "/root/.ssh/id_ed25519" }, "secret-file"],
      [
        "ssh_db_query",
        { server: "app-1", type: "postgresql", database: "app", query: "select * from users" },
        "db-query",
      ],
      [
        "ssh_sync",
        { server: "app-1", source: "remote:/etc/dokploy", destination: "local:./d" },
        "secret-file",
      ],
    ];
    for (const [tool, input, rule] of calls) {
      const { json } = runEvent({
        hook_event_name: "PreToolUse",
        tool_name: `mcp__ssh_example__${tool}`,
        tool_input: input,
      });
      expect(json.hookSpecificOutput.permissionDecision, tool).toBe("deny");
      expect(json.hookSpecificOutput.permissionDecisionReason, tool).toContain(`(rule ${rule})`);
    }
  });

  it("stays silent so the normal permission flow continues", () => {
    const events = [
      { tool_name: "Bash", tool_input: { command: "ssh app-1 'docker ps'" } },
      { tool_name: "Bash", tool_input: { command: "ssh app-1" } },
      { tool_name: "Bash", tool_input: { command: "cat .env && printenv" } },
      { tool_name: "Bash", tool_input: { command: "git status" } },
      { tool_name: "Bash", tool_input: {} },
      { tool_name: SSH_TOOL, tool_input: { server: "app-1", command: "uptime" } },
      { tool_name: SSH_TOOL, tool_input: null },
      { tool_name: "mcp__ssh_example__ssh_list_servers", tool_input: {} },
      { tool_name: "mcp__dokploy__compose-one", tool_input: { composeId: "printenv" } },
      { tool_name: "Read", tool_input: { file_path: "/srv/app/.env" } },
    ];
    for (const event of events) {
      const { status, stdout, stderr } = runEvent({ hook_event_name: "PreToolUse", ...event });
      expect(status).toBe(0);
      expect(stdout).toBe("");
      expect(stderr).toBe("");
    }
  });
});

describe("hook: PostToolUse", () => {
  it("replaces the output of an SSH MCP tool with the scrubbed one", () => {
    const dump = `PATH=/usr/bin\nNODE_ENV=production\nDB_PASSWORD=${SECRET}`;
    const { status, stdout, json } = runEvent({
      hook_event_name: "PostToolUse",
      tool_name: SSH_TOOL,
      tool_input: { server: "app-1", command: "printenv" },
      tool_response: sshResult(dump),
    });
    const scrubbed = sshResult("PATH=[REDACTED]\nNODE_ENV=[REDACTED]\nDB_PASSWORD=[REDACTED]");

    expect(status).toBe(0);
    expect(stdout).not.toContain(SECRET);
    expect(stdout).not.toContain("production");
    expect(json.hookSpecificOutput.hookEventName).toBe("PostToolUse");
    expect(json.hookSpecificOutput.updatedToolOutput).toEqual(scrubbed);
    expect(json.hookSpecificOutput.updatedMCPToolOutput).toEqual(scrubbed);
    expect(json.hookSpecificOutput.additionalContext).toContain("replaced secret values");
    expect(Object.keys(json.hookSpecificOutput).sort()).toEqual([
      "additionalContext",
      "hookEventName",
      "updatedMCPToolOutput",
      "updatedToolOutput",
    ]);
  });

  it("keeps a string result a string", () => {
    const { json } = runEvent({
      hook_event_name: "PostToolUse",
      tool_name: "mcp__ssh_example__ssh_tail",
      tool_input: { server: "app-1", file: "/var/log/app.log" },
      tool_response: `login ok token=${SECRET}`,
    });

    expect(json.hookSpecificOutput.updatedToolOutput).toBe("login ok token=[REDACTED]");
  });

  it("returns nothing when there is nothing to scrub or the tool is not an SSH tool", () => {
    const events = [
      {
        tool_name: SSH_TOOL,
        tool_response: sshResult("CONTAINER ID   IMAGE\n0123456789ab   app:1"),
      },
      { tool_name: SSH_TOOL, tool_response: sshResult("A=[REDACTED]\nB=[REDACTED]\nC=[REDACTED]") },
      { tool_name: SSH_TOOL },
      { tool_name: "Bash", tool_response: { stdout: `API_TOKEN=${SECRET}`, stderr: "" } },
      {
        tool_name: "mcp__dokploy__compose-one",
        tool_response: [{ type: "text", text: `API_TOKEN=${SECRET}` }],
      },
    ];
    for (const event of events) {
      const { status, stdout, stderr } = runEvent({ hook_event_name: "PostToolUse", ...event });
      expect(status).toBe(0);
      expect(stdout).toBe("");
      expect(stderr).toBe("");
    }
  });
});

describe("hook: failures and other events", () => {
  it("fails open on input it cannot read and does not echo it", () => {
    for (const stdin of ["", "not json", `{"tool_input": "${SECRET}"`, "[1, 2"]) {
      const { status, stdout, stderr } = runHook(stdin);
      expect(status).toBe(0);
      expect(stdout).toBe("");
      expect(stderr).toBe("ssh-secret-guard: internal SyntaxError, no decision made\n");
    }
  });

  it("ignores events and shapes it does not handle", () => {
    const inputs = [
      "null",
      "[]",
      "42",
      "{}",
      JSON.stringify({ hook_event_name: "PreToolUse" }),
      JSON.stringify({
        hook_event_name: "PreToolUse",
        tool_name: 42,
        tool_input: { command: "printenv" },
      }),
      JSON.stringify({
        hook_event_name: "Stop",
        tool_name: SSH_TOOL,
        tool_input: { command: "printenv" },
      }),
      JSON.stringify({
        hook_event_name: "PostToolUseFailure",
        tool_name: SSH_TOOL,
        error: `x ${SECRET}`,
      }),
    ];
    for (const stdin of inputs) {
      const { status, stdout, stderr } = runHook(stdin);
      expect(status).toBe(0);
      expect(stdout).toBe("");
      expect(stderr).toBe("");
    }
  });

  it("decides the same way when called as a function", () => {
    expect(
      decide({ hook_event_name: "PreToolUse", tool_name: "Bash", tool_input: { command: "ls" } }),
    ).toBe(undefined);
    const denied = decide({
      hook_event_name: "PreToolUse",
      tool_name: "Bash",
      tool_input: { command: "scp app-1:/srv/app/.env ." },
    });
    expect(denied?.hookSpecificOutput.permissionDecision).toBe("deny");
    expect(denied?.hookSpecificOutput.permissionDecisionReason).toContain("(rule secret-file)");
  });
});
