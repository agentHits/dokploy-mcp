#!/usr/bin/env bun
import { realpathSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { classifyBashCommand, classifyToolCall, isSshMcpTool, type Verdict } from "./policy.js";
import { scrubToolResponse } from "./scrub.js";

export interface HookOutput {
  hookSpecificOutput: Record<string, unknown>;
}

const REMOTE_TOOL_IN_BASH = /ssh|scp|sftp|rsync/;
const SCRUB_NOTE =
  "ssh-secret-guard replaced secret values in this output with [REDACTED]. They are hidden on purpose: do not try to read them another way. Work with the names, or use env-keys and env-apply of the Dokploy MCP server.";

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function classify(toolName: string, toolInput: unknown): Verdict {
  if (isSshMcpTool(toolName)) return classifyToolCall(toolName, toolInput);
  if (toolName !== "Bash" || !isRecord(toolInput)) return { decision: "allow" };

  const command = toolInput.command;
  return typeof command === "string" && REMOTE_TOOL_IN_BASH.test(command)
    ? classifyBashCommand(command)
    : { decision: "allow" };
}

/** Turns one hook event into the JSON Claude Code expects, or nothing when the guard has no say. */
export function decide(event: unknown): HookOutput | undefined {
  if (!isRecord(event) || typeof event.tool_name !== "string") return undefined;

  if (event.hook_event_name === "PreToolUse") {
    const verdict = classify(event.tool_name, event.tool_input);
    if (verdict.decision !== "deny") return undefined;
    return {
      hookSpecificOutput: {
        hookEventName: "PreToolUse",
        permissionDecision: "deny",
        permissionDecisionReason: `ssh-secret-guard blocked this call (rule ${verdict.rule}): ${verdict.reason} Instead: ${verdict.alternative}`,
      },
    };
  }

  if (event.hook_event_name === "PostToolUse" && isSshMcpTool(event.tool_name)) {
    const { value, changed } = scrubToolResponse(event.tool_response);
    // Hooks of one event all see the original output and the last rewrite wins,
    // so returning unchanged output could undo the redaction of another hook.
    if (!changed) return undefined;
    return {
      hookSpecificOutput: {
        hookEventName: "PostToolUse",
        updatedToolOutput: value,
        // Claude Code releases from before updatedToolOutput read only this field.
        updatedMCPToolOutput: value,
        additionalContext: SCRUB_NOTE,
      },
    };
  }
  return undefined;
}

async function main(): Promise<void> {
  try {
    const chunks: Buffer[] = [];
    for await (const chunk of process.stdin) {
      chunks.push(typeof chunk === "string" ? Buffer.from(chunk) : chunk);
    }
    const output = decide(JSON.parse(Buffer.concat(chunks).toString("utf8")));
    if (output !== undefined) process.stdout.write(JSON.stringify(output));
  } catch (error) {
    // Failing open keeps the tools usable. The message stays fixed because an
    // error text can quote the command or the output that caused it.
    const kind = error instanceof Error ? error.name : "error";
    process.stderr.write(`ssh-secret-guard: internal ${kind}, no decision made\n`);
  }
}

function isEntryPoint(): boolean {
  try {
    return realpathSync(process.argv[1] ?? "") === realpathSync(fileURLToPath(import.meta.url));
  } catch {
    return false;
  }
}

if (isEntryPoint()) await main();
