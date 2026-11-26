import { describe, expect, it } from "bun:test";
import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync, symlinkSync, unlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const VALIDATOR_PATH = join(REPO_ROOT, ".github", "scripts", "validate-bun-lock.py");

interface LockEntrySpec {
  spec: string;
  meta?: Record<string, unknown>;
  integrity?: string;
}

function makeLockfile(packages: Record<string, LockEntrySpec>): string {
  const lines: string[] = [
    "{",
    '  "lockfileVersion": 2,',
    '  "configVersion": 1,',
    '  "workspaces": {',
    '    "": {',
    '      "name": "fixture",',
    "    },",
    "  },",
    '  "packages": {',
  ];
  for (const [key, entry] of Object.entries(packages)) {
    const meta = JSON.stringify(entry.meta ?? {});
    const tuple =
      entry.integrity !== undefined
        ? `[${JSON.stringify(entry.spec)}, "", ${meta}, ${JSON.stringify(entry.integrity)}]`
        : `[${JSON.stringify(entry.spec)}, "", ${meta}]`;
    lines.push(`    ${JSON.stringify(key)}: ${tuple},`);
  }
  lines.push("  },");
  lines.push("}");
  return `${lines.join("\n")}\n`;
}

function git(cwd: string, args: string[]): void {
  const res = spawnSync("git", args, { cwd, encoding: "utf8" });
  if (res.status !== 0) {
    throw new Error(`git ${args.join(" ")} failed: ${res.stderr}`);
  }
}

interface ValidationResult {
  status: number;
  stdout: string;
  stderr: string;
  output: string;
}

function runValidator(
  oldLock: string | null,
  newLock: string | Buffer | { symlinkTarget: string },
): ValidationResult {
  const dir = mkdtempSync(join(tmpdir(), "validate-bun-lock-"));
  try {
    git(dir, ["init", "-q", "-b", "main"]);
    git(dir, ["config", "user.name", "Test Bot"]);
    git(dir, ["config", "user.email", "test@example.com"]);
    git(dir, ["config", "commit.gpgsign", "false"]);

    if (oldLock !== null) {
      writeFileSync(join(dir, "bun.lock"), oldLock, "utf8");
      git(dir, ["add", "bun.lock"]);
    } else {
      writeFileSync(join(dir, "README.md"), "# fixture\n", "utf8");
      git(dir, ["add", "README.md"]);
    }
    git(dir, ["commit", "-q", "-m", "base"]);
    git(dir, ["update-ref", "refs/remotes/origin/main", "HEAD"]);

    const lockPath = join(dir, "bun.lock");
    if (typeof newLock === "object" && !Buffer.isBuffer(newLock) && "symlinkTarget" in newLock) {
      if (oldLock !== null) {
        unlinkSync(lockPath);
      }
      writeFileSync(join(dir, newLock.symlinkTarget), "{}\n", "utf8");
      symlinkSync(newLock.symlinkTarget, lockPath);
    } else {
      writeFileSync(lockPath, newLock);
    }

    const res = spawnSync("python3", ["-I", VALIDATOR_PATH, "main", "bun.lock"], {
      cwd: dir,
      encoding: "utf8",
    });
    const stdout = res.stdout ?? "";
    const stderr = res.stderr ?? "";
    return {
      status: res.status ?? 1,
      stdout,
      stderr,
      output: `${stdout}${stderr}`,
    };
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

describe("validate-bun-lock.py", () => {
  it("allows normal SemVer upgrades", () => {
    const oldLock = makeLockfile({
      hono: { spec: "hono@4.13.21", integrity: "sha512-old" },
    });
    const newLock = makeLockfile({
      hono: { spec: "hono@4.13.22", integrity: "sha512-new" },
    });
    const res = runValidator(oldLock, newLock);
    expect(res.status).toBe(0);
  });

  it("rejects single-copy SemVer downgrade", () => {
    const oldLock = makeLockfile({
      hono: { spec: "hono@4.13.21", integrity: "sha512-old" },
    });
    const newLock = makeLockfile({
      hono: { spec: "hono@4.13.19", integrity: "sha512-down" },
    });
    const res = runValidator(oldLock, newLock);
    expect(res.status).not.toBe(0);
    expect(res.output).toContain("::error::bun.lock:");
  });

  it("enforces SemVer 2.0.0 prerelease ordering", () => {
    const stable = makeLockfile({
      pkg: { spec: "pkg@1.0.0", integrity: "sha512-stable" },
    });
    const rc = makeLockfile({
      pkg: { spec: "pkg@1.0.0-rc.1", integrity: "sha512-rc1" },
    });
    const alpha10 = makeLockfile({
      pkg: { spec: "pkg@1.0.0-alpha.10", integrity: "sha512-a10" },
    });
    const alpha2 = makeLockfile({
      pkg: { spec: "pkg@1.0.0-alpha.2", integrity: "sha512-a2" },
    });

    expect(runValidator(stable, rc).status).not.toBe(0);
    expect(runValidator(rc, stable).status).toBe(0);
    expect(runValidator(alpha10, alpha2).status).not.toBe(0);
    expect(runValidator(alpha2, alpha10).status).toBe(0);
  });

  it("permits real @emnapi/runtime hoist when nested non-bundled copy vacates with matching sha512", () => {
    const oldLock = makeLockfile({
      "@emnapi/runtime": {
        spec: "@emnapi/runtime@2.0.0-beta.2",
        integrity: "sha512-v2beta",
      },
      "@img/sharp-wasm32/@emnapi/runtime": {
        spec: "@emnapi/runtime@1.11.3",
        integrity: "sha512-v1113",
      },
      "@tailwindcss/oxide-wasm32-wasi/@emnapi/runtime": {
        spec: "@emnapi/runtime@1.11.3",
        meta: { bundled: true },
      },
    });
    const newLock = makeLockfile({
      "@emnapi/runtime": {
        spec: "@emnapi/runtime@1.11.3",
        integrity: "sha512-v1113",
      },
      "@tailwindcss/oxide-wasm32-wasi/@emnapi/runtime": {
        spec: "@emnapi/runtime@1.11.3",
        meta: { bundled: true },
      },
    });
    const res = runValidator(oldLock, newLock);
    expect(res.status).toBe(0);
  });

  it("permits hoist combined with patch bump when nested source vacates", () => {
    const oldLock = makeLockfile({
      "@emnapi/runtime": {
        spec: "@emnapi/runtime@2.0.0-beta.2",
        integrity: "sha512-v2beta",
      },
      "@img/sharp-wasm32/@emnapi/runtime": {
        spec: "@emnapi/runtime@1.11.3",
        integrity: "sha512-v1113",
      },
    });
    const newLock = makeLockfile({
      "@emnapi/runtime": {
        spec: "@emnapi/runtime@1.11.4",
        integrity: "sha512-v1114",
      },
    });
    const res = runValidator(oldLock, newLock);
    expect(res.status).toBe(0);
  });

  it("rejects hoist combined with downgrade below vacated source", () => {
    const oldLock = makeLockfile({
      "@emnapi/runtime": {
        spec: "@emnapi/runtime@2.0.0-beta.2",
        integrity: "sha512-v2beta",
      },
      "@img/sharp-wasm32/@emnapi/runtime": {
        spec: "@emnapi/runtime@1.11.3",
        integrity: "sha512-v1113",
      },
    });
    const newLock = makeLockfile({
      "@emnapi/runtime": {
        spec: "@emnapi/runtime@1.11.2",
        integrity: "sha512-v1112",
      },
    });
    const res = runValidator(oldLock, newLock);
    expect(res.status).not.toBe(0);
    expect(res.output).toContain("::error::bun.lock:");
  });

  it("rejects sha512 integrity mismatch on exact hoist", () => {
    const oldLock = makeLockfile({
      "@emnapi/runtime": {
        spec: "@emnapi/runtime@2.0.0-beta.2",
        integrity: "sha512-v2beta",
      },
      "@img/sharp-wasm32/@emnapi/runtime": {
        spec: "@emnapi/runtime@1.11.3",
        integrity: "sha512-original",
      },
    });
    const newLock = makeLockfile({
      "@emnapi/runtime": {
        spec: "@emnapi/runtime@1.11.3",
        integrity: "sha512-tampered",
      },
    });
    const res = runValidator(oldLock, newLock);
    expect(res.status).not.toBe(0);
    expect(res.output).toContain("::error::bun.lock:");
  });

  it("rejects hoist justified only by a bundled copy (kept or removed)", () => {
    const oldLock = makeLockfile({
      "@emnapi/runtime": {
        spec: "@emnapi/runtime@2.0.0-beta.2",
        integrity: "sha512-v2beta",
      },
      "@tailwindcss/oxide-wasm32-wasi/@emnapi/runtime": {
        spec: "@emnapi/runtime@1.11.3",
        meta: { bundled: true },
        integrity: "sha512-v1113",
      },
    });
    const newLockBundledKept = makeLockfile({
      "@emnapi/runtime": {
        spec: "@emnapi/runtime@1.11.3",
        integrity: "sha512-v1113",
      },
      "@tailwindcss/oxide-wasm32-wasi/@emnapi/runtime": {
        spec: "@emnapi/runtime@1.11.3",
        meta: { bundled: true },
        integrity: "sha512-v1113",
      },
    });
    const newLockBundledRemoved = makeLockfile({
      "@emnapi/runtime": {
        spec: "@emnapi/runtime@1.11.3",
        integrity: "sha512-v1113",
      },
    });

    expect(runValidator(oldLock, newLockBundledKept).status).not.toBe(0);
    expect(runValidator(oldLock, newLockBundledRemoved).status).not.toBe(0);
  });

  it("rejects bump-nested plus downgrade-root attack", () => {
    const oldLock = makeLockfile({
      foo: { spec: "foo@1.5.0", integrity: "sha512-150" },
      "bar/foo": { spec: "foo@1.0.0", integrity: "sha512-100" },
    });
    const newLock = makeLockfile({
      foo: { spec: "foo@1.0.0", integrity: "sha512-100" },
      "bar/foo": { spec: "foo@1.0.1", integrity: "sha512-101" },
    });
    const res = runValidator(oldLock, newLock);
    expect(res.status).not.toBe(0);
  });

  it("rejects delete-nested plus downgrade-root attack inside same compat line", () => {
    const oldLock = makeLockfile({
      "@opentelemetry/api": { spec: "@opentelemetry/api@1.10.0", integrity: "sha512-110" },
      "a/@opentelemetry/api": { spec: "@opentelemetry/api@1.9.1", integrity: "sha512-191" },
    });
    const newLock = makeLockfile({
      "@opentelemetry/api": { spec: "@opentelemetry/api@1.9.1", integrity: "sha512-191" },
    });
    const res = runValidator(oldLock, newLock);
    expect(res.status).not.toBe(0);
  });

  it("rejects single-copy key relocation downgrade", () => {
    const oldLock = makeLockfile({
      hono: { spec: "hono@4.13.21", integrity: "sha512-41321" },
    });
    const newLock = makeLockfile({
      "apps/api/hono": { spec: "hono@4.13.0", integrity: "sha512-4130" },
    });
    const res = runValidator(oldLock, newLock);
    expect(res.status).not.toBe(0);
  });

  it("rejects cross-major key relocation downgrade (Layer 3)", () => {
    const oldLock = makeLockfile({
      hono: { spec: "hono@4.13.21", integrity: "sha512-41321" },
    });
    const newLock = makeLockfile({
      "apps/api/hono": { spec: "hono@3.0.0", integrity: "sha512-300" },
    });
    const res = runValidator(oldLock, newLock);
    expect(res.status).not.toBe(0);
  });

  it("rejects 0.x minor-jump downgrade into unseen compat line", () => {
    const oldLock = makeLockfile({
      foo: { spec: "foo@0.9.5", integrity: "sha512-095" },
      "a/foo": { spec: "foo@0.1.0", integrity: "sha512-010" },
    });
    const newLock = makeLockfile({
      foo: { spec: "foo@0.2.0", integrity: "sha512-020" },
    });
    const res = runValidator(oldLock, newLock);
    expect(res.status).not.toBe(0);
  });

  it("rejects 1 vacated slot excusing 2 downgrades (Layer 2 1-to-1 matching)", () => {
    const oldLock = makeLockfile({
      "a/foo": { spec: "foo@2.0.0", integrity: "sha512-200" },
      "b/foo": { spec: "foo@2.0.0", integrity: "sha512-200" },
      "c/foo": { spec: "foo@1.5.0", integrity: "sha512-150" },
    });
    const newLock = makeLockfile({
      "a/foo": { spec: "foo@1.5.0", integrity: "sha512-150" },
      "b/foo": { spec: "foo@1.5.0", integrity: "sha512-150" },
    });
    const res = runValidator(oldLock, newLock);
    expect(res.status).not.toBe(0);
  });

  it("rejects JSONC indentation smuggling, multiline smuggling, and duplicate keys", () => {
    const oldLock = makeLockfile({
      hono: { spec: "hono@4.13.21", integrity: "sha512-41321" },
    });
    const sixSpaceIndent = `{
  "lockfileVersion": 2,
  "packages": {
      "hono": ["hono@4.13.0", "", {}, "sha512-4130"],
  },
}
`;
    const multilineTuple = `{
  "lockfileVersion": 2,
  "packages": {
    "hono": [
      "hono@4.13.0",
      "",
      {},
      "sha512-4130",
    ],
  },
}
`;
    const duplicateKey = `{
  "lockfileVersion": 2,
  "packages": {
    "hono": ["hono@4.13.22", "", {}, "sha512-41322"],
    "hono": ["hono@4.13.0", "", {}, "sha512-4130"],
  },
}
`;
    expect(runValidator(oldLock, sixSpaceIndent).status).not.toBe(0);
    expect(runValidator(oldLock, multilineTuple).status).not.toBe(0);
    expect(runValidator(oldLock, duplicateKey).status).not.toBe(0);
  });

  it("rejects SemVer to non-SemVer tampering and canonical alias swaps", () => {
    const oldLock = makeLockfile({
      hono: { spec: "hono@4.13.21", integrity: "sha512-41321" },
    });
    const toLatest = makeLockfile({
      hono: { spec: "hono@latest", integrity: "sha512-latest" },
    });
    const toWorkspace = makeLockfile({
      hono: { spec: "hono@workspace:*" },
    });
    const toNpmAlias = makeLockfile({
      hono: { spec: "hono@npm:evil@1.0.0", integrity: "sha512-evil" },
    });
    const aliasSwap = makeLockfile({
      hono: { spec: "evil-hono@9.9.9", integrity: "sha512-evil" },
    });

    expect(runValidator(oldLock, toLatest).status).not.toBe(0);
    expect(runValidator(oldLock, toWorkspace).status).not.toBe(0);
    expect(runValidator(oldLock, toNpmAlias).status).not.toBe(0);
    expect(runValidator(oldLock, aliasSwap).status).not.toBe(0);
  });

  it("permits legitimate dedup into higher version and honest key swap", () => {
    const dedupOld = makeLockfile({
      foo: { spec: "foo@1.5.0", integrity: "sha512-150" },
      "a/foo": { spec: "foo@1.2.0", integrity: "sha512-120" },
    });
    const dedupNew = makeLockfile({
      foo: { spec: "foo@1.5.0", integrity: "sha512-150" },
    });
    expect(runValidator(dedupOld, dedupNew).status).toBe(0);

    const swapOld = makeLockfile({
      foo: { spec: "foo@1.5.0", integrity: "sha512-150" },
      "a/foo": { spec: "foo@1.0.0", integrity: "sha512-100" },
    });
    const swapNew = makeLockfile({
      foo: { spec: "foo@1.0.0", integrity: "sha512-100" },
      "a/foo": { spec: "foo@1.5.0", integrity: "sha512-150" },
    });
    expect(runValidator(swapOld, swapNew).status).toBe(0);
  });

  it("rejects URL injection, symlinks, NUL bytes, and bundled downgrade smuggling; permits brand-new lockfile", () => {
    const oldLock = makeLockfile({
      hono: { spec: "hono@4.13.21", integrity: "sha512-41321" },
    });

    const urlInjection = `{
  "lockfileVersion": 2,
  "packages": {
    "hono": ["hono@4.13.22", "https://evil.example/hono.tgz", {}, "sha512-41322"],
  },
}
`;
    const gitUrlInjection = `{
  "lockfileVersion": 2,
  "packages": {
    "hono": ["hono@4.13.22", "git+https://evil.example/repo.git", {}, "sha512-41322"],
  },
}
`;
    const bundledDowngrade = makeLockfile({
      hono: { spec: "hono@4.13.0", meta: { bundled: true }, integrity: "sha512-4130" },
    });
    const brandNewLock = makeLockfile({
      hono: { spec: "hono@4.13.22", integrity: "sha512-41322" },
    });

    expect(runValidator(oldLock, urlInjection).status).not.toBe(0);
    expect(runValidator(oldLock, gitUrlInjection).status).not.toBe(0);
    expect(runValidator(oldLock, { symlinkTarget: "target.lock" }).status).not.toBe(0);
    expect(runValidator(oldLock, Buffer.from(`${oldLock}\0`)).status).not.toBe(0);
    expect(runValidator(oldLock, bundledDowngrade).status).not.toBe(0);
    expect(runValidator(null, brandNewLock).status).toBe(0);
  });
});
