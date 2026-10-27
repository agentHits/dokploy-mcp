import { afterEach, beforeEach, describe, expect, it, mock, spyOn } from "bun:test";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";

// Mock apiClient before server.ts is imported — it calls getClientConfig() at
// module level which requires DOKPLOY_URL/DOKPLOY_API_KEY env vars.
mock.module("./utils/apiClient.js", () => ({
  default: { get: mock(), post: mock() },
  setAuthToken: mock(),
  clearAuthToken: mock(),
}));

// bun:test has no vi.mocked(): module mocks above are already mock fns,
// so this is a pass-through kept at old call sites.
const mocked = <T>(value: T): T => value;

const { default: apiClient } = await import("./utils/apiClient.js");
const { generatedTools } = await import("./generated/tools.js");
const { createServer } = await import("./server.js");
const { envApplyTool } = await import("./envTools.js");

// superPassword-status, env-keys and env-apply are loaded on top of every
// preset and tag filter.
const ALWAYS_LOADED_TOOLS = 3;

// Tools that need a whole env text are never listed.
const FULL_ENV_REPLACE_TOOLS = [
  "application-saveEnvironment",
  "compose-saveEnvironment",
  "libsql-saveEnvironment",
  "mariadb-saveEnvironment",
  "mongo-saveEnvironment",
  "mysql-saveEnvironment",
  "postgres-saveEnvironment",
  "redis-saveEnvironment",
  "settings-writeTraefikEnv",
];
const listableGeneratedTools = generatedTools.filter(
  (tool) => !FULL_ENV_REPLACE_TOOLS.includes(tool.name),
);

function countByTags(tags: string[]): number {
  const wanted = new Set(tags.map((tag) => tag.toLowerCase()));
  return (
    listableGeneratedTools.filter((tool) => wanted.has(tool.tag.toLowerCase())).length +
    ALWAYS_LOADED_TOOLS
  );
}

const SECRET = "fake-value-7Qx";
const PANEL_TOKEN = "__DOKPLOY_REDACTED_SECRET__K7F3K6Q2M4XA__";
const OTHER_PANEL_TOKEN = "__DOKPLOY_REDACTED_SECRET__AAAABBBB2345__";

const RECOVERY_PATHS = [
  "/compose/env/upsert",
  "/compose/deploy/exact",
  "/deployment/reconcile",
] as const;
const VERIFIED_RECOVERY_SUBTREE_SHA256 =
  "924bb49db03e133053276e890d8570af89b63940015044a374c612d8dd4e209d";

function responseText(result: { content: Array<{ type: string; text?: string }> }) {
  return result.content.map((item) => (item.type === "text" ? (item.text ?? "") : "")).join("\n");
}

describe("MCP server tools/list", () => {
  const originalDokployUrl = process.env.DOKPLOY_URL;
  const originalDokployApiKey = process.env.DOKPLOY_API_KEY;
  const originalDokployRedactEnv = process.env.DOKPLOY_REDACT_ENV;
  const originalDokployRedactFields = process.env.DOKPLOY_REDACT_FIELDS;

  beforeEach(() => {
    mock.clearAllMocks();
    process.env.DOKPLOY_URL = "https://dokploy.example";
    process.env.DOKPLOY_API_KEY = "test-api-key";
    process.env.DOKPLOY_REDACT_ENV = "false";
    delete process.env.DOKPLOY_REDACT_FIELDS;
    delete process.env.DOKPLOY_ENABLED_TAGS;
    delete process.env.DOKPLOY_DISABLED_TAGS;
    delete process.env.DOKPLOY_TOOL_PRESET;
  });

  afterEach(() => {
    if (originalDokployUrl === undefined) {
      delete process.env.DOKPLOY_URL;
    } else {
      process.env.DOKPLOY_URL = originalDokployUrl;
    }

    if (originalDokployApiKey === undefined) {
      delete process.env.DOKPLOY_API_KEY;
    } else {
      process.env.DOKPLOY_API_KEY = originalDokployApiKey;
    }

    if (originalDokployRedactEnv === undefined) {
      delete process.env.DOKPLOY_REDACT_ENV;
    } else {
      process.env.DOKPLOY_REDACT_ENV = originalDokployRedactEnv;
    }

    if (originalDokployRedactFields === undefined) {
      delete process.env.DOKPLOY_REDACT_FIELDS;
    } else {
      process.env.DOKPLOY_REDACT_FIELDS = originalDokployRedactFields;
    }

    delete process.env.DOKPLOY_ENABLED_TAGS;
    delete process.env.DOKPLOY_DISABLED_TAGS;
    delete process.env.DOKPLOY_TOOL_PRESET;
  });

  async function createConnectedClient() {
    const server = createServer();
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    await server.connect(serverTransport);
    const client = new Client({ name: "test-client", version: "1.0.0" });
    await client.connect(clientTransport);
    return client;
  }

  async function getToolList() {
    const client = await createConnectedClient();
    const { tools } = await client.listTools();
    await client.close();
    return tools;
  }

  it("returns tools", async () => {
    const tools = await getToolList();
    expect(tools.length).toBeGreaterThan(0);
  });

  it("returns all tools by default", async () => {
    const tools = await getToolList();
    expect(tools).toHaveLength(listableGeneratedTools.length + ALWAYS_LOADED_TOOLS);
  });

  it("supports DOKPLOY_TOOL_PRESET=minimal for clients sensitive to large toolsets", async () => {
    process.env.DOKPLOY_TOOL_PRESET = "minimal";

    const tools = await getToolList();
    const tags = new Set(tools.map((tool) => tool.name.split("-")[0]));

    expect(tools).toHaveLength(countByTags(["project", "application"]));
    expect(tags).toEqual(new Set(["application", "project", "superPassword", "env"]));
  });

  it("supports DOKPLOY_TOOL_PRESET=core for common application workflows", async () => {
    process.env.DOKPLOY_TOOL_PRESET = "core";

    const tools = await getToolList();
    const tags = new Set(tools.map((tool) => tool.name.split("-")[0]));

    expect(tools).toHaveLength(countByTags(["project", "server", "application"]));
    expect(tags).toEqual(new Set(["application", "project", "server", "superPassword", "env"]));
  });

  it("lets DOKPLOY_ENABLED_TAGS override presets", async () => {
    process.env.DOKPLOY_TOOL_PRESET = "core";
    process.env.DOKPLOY_ENABLED_TAGS = "project,application";

    const tools = await getToolList();
    const tags = new Set(tools.map((tool) => tool.name.split("-")[0]));

    expect(tools).toHaveLength(countByTags(["project", "application"]));
    expect(tags).toEqual(new Set(["application", "project", "superPassword", "env"]));
  });

  it("excludes DOKPLOY_DISABLED_TAGS after selecting tools", async () => {
    process.env.DOKPLOY_TOOL_PRESET = "deploy";
    process.env.DOKPLOY_DISABLED_TAGS = "domain,deployment";

    const tools = await getToolList();
    const tags = new Set(tools.map((tool) => tool.name.split("-")[0]));

    expect(tools).toHaveLength(
      countByTags(["project", "environment", "server", "application", "compose"]),
    );
    expect(tags.has("domain")).toBe(false);
    expect(tags.has("deployment")).toBe(false);
  });

  it("falls back to all tools for an unknown preset", async () => {
    process.env.DOKPLOY_TOOL_PRESET = "unknown";

    const tools = await getToolList();

    expect(tools).toHaveLength(listableGeneratedTools.length + ALWAYS_LOADED_TOOLS);
  });

  it("exposes deployment-readLogs for schedule deployment log inspection", async () => {
    const tools = await getToolList();
    const tool = tools.find(({ name }) => name === "deployment-readLogs");

    expect(tool).toBeDefined();
    expect(tool?.description).toBe("GET /deployment.readLogs");

    const schema = tool?.inputSchema as Record<string, unknown>;
    const properties = schema.properties as Record<string, Record<string, unknown>>;
    const required = schema.required as string[];

    expect(properties.deploymentId).toMatchObject({
      type: "string",
      minLength: 1,
    });
    expect(properties.tail).toMatchObject({
      type: "integer",
      minimum: 1,
      maximum: 10000,
      default: 100,
    });
    expect(required).toContain("deploymentId");
  });

  it("routes deployment-readLogs calls to the deployment log API endpoint", async () => {
    mocked(apiClient.get).mockResolvedValue({
      data: "schedule stdout\nschedule stderr",
    });

    const client = await createConnectedClient();
    const result = await client.callTool({
      name: "deployment-readLogs",
      arguments: {
        deploymentId: "dep_test",
        tail: 25,
      },
    });
    await client.close();

    expect(apiClient.get).toHaveBeenCalledWith("/deployment.readLogs", {
      params: {
        deploymentId: "dep_test",
        tail: 25,
      },
    });

    const content = result.content[0];
    expect(content.type).toBe("text");
    const parsed = JSON.parse(content.type === "text" ? content.text : "");

    expect(parsed).toEqual({
      success: true,
      message: "deployment-readLogs completed successfully",
      data: "schedule stdout\nschedule stderr",
    });
  });

  it("every tool inputSchema has $schema set to draft 2020-12", async () => {
    const tools = await getToolList();
    for (const tool of tools) {
      const schema = tool.inputSchema as Record<string, unknown>;
      expect(schema.$schema, `Tool "${tool.name}" is missing $schema or has wrong draft`).toBe(
        "https://json-schema.org/draft/2020-12/schema",
      );
    }
  });

  it("no tool inputSchema contains any $schema key at nested levels", async () => {
    const tools = await getToolList();

    function findNestedSchemaKeys(obj: unknown, path = ""): string[] {
      if (obj === null || typeof obj !== "object") return [];
      if (Array.isArray(obj)) {
        return obj.flatMap((item, i) => findNestedSchemaKeys(item, `${path}[${i}]`));
      }
      const record = obj as Record<string, unknown>;
      const found: string[] = [];
      for (const [key, value] of Object.entries(record)) {
        const currentPath = path ? `${path}.${key}` : key;
        if (key === "$schema" && path !== "") found.push(currentPath);
        found.push(...findNestedSchemaKeys(value, currentPath));
      }
      return found;
    }

    for (const tool of tools) {
      const found = findNestedSchemaKeys(tool.inputSchema);
      expect(
        found,
        `Tool "${tool.name}" has nested $schema keys at: ${found.join(", ")}`,
      ).toHaveLength(0);
    }
  });

  it("no tool inputSchema exposes regex lookaround patterns", async () => {
    const tools = await getToolList();

    function findLookaroundPatterns(obj: unknown, path = ""): string[] {
      if (obj === null || typeof obj !== "object") return [];
      if (Array.isArray(obj)) {
        return obj.flatMap((item, i) => findLookaroundPatterns(item, `${path}[${i}]`));
      }

      const record = obj as Record<string, unknown>;
      const found: string[] = [];
      for (const [key, value] of Object.entries(record)) {
        const currentPath = path ? `${path}.${key}` : key;
        if (key === "pattern" && typeof value === "string" && /\(\?<?[=!]/.test(value)) {
          found.push(currentPath);
        }
        found.push(...findLookaroundPatterns(value, currentPath));
      }
      return found;
    }

    for (const tool of tools) {
      const found = findLookaroundPatterns(tool.inputSchema);
      expect(
        found,
        `Tool "${tool.name}" exposes provider-incompatible lookaround patterns at: ${found.join(", ")}`,
      ).toHaveLength(0);
    }
  });

  it("no tool inputSchema exposes patterns invalid under strict regex syntax", async () => {
    const tools = await getToolList();

    function findStrictInvalidPatterns(obj: unknown, path = ""): string[] {
      if (obj === null || typeof obj !== "object") return [];
      if (Array.isArray(obj)) {
        return obj.flatMap((item, i) => findStrictInvalidPatterns(item, `${path}[${i}]`));
      }

      const record = obj as Record<string, unknown>;
      const found: string[] = [];
      for (const [key, value] of Object.entries(record)) {
        const currentPath = path ? `${path}.${key}` : key;
        if (key === "pattern" && typeof value === "string") {
          try {
            new RegExp(value, "v");
          } catch {
            found.push(`${currentPath}: ${value}`);
          }
        }
        found.push(...findStrictInvalidPatterns(value, currentPath));
      }
      return found;
    }

    for (const tool of tools) {
      const found = findStrictInvalidPatterns(tool.inputSchema);
      expect(
        found,
        `Tool "${tool.name}" exposes provider-incompatible patterns at: ${found.join(", ")}`,
      ).toHaveLength(0);
    }
  });

  // Zod checks .max() before it parses the elements, so a capped array is
  // rejected with one issue instead of one per element (GHSA-mrhx-c7xc-m3w5).
  it("caps every input array at 1000 items", async () => {
    const tools = await getToolList();

    function findUncappedArrays(obj: unknown, path = ""): string[] {
      if (obj === null || typeof obj !== "object") return [];
      if (Array.isArray(obj)) {
        return obj.flatMap((item, i) => findUncappedArrays(item, `${path}[${i}]`));
      }
      const record = obj as Record<string, unknown>;
      const isArray =
        record.type === "array" || (Array.isArray(record.type) && record.type.includes("array"));
      const found =
        isArray && !(typeof record.maxItems === "number" && record.maxItems <= 1000)
          ? [path || "(root)"]
          : [];
      for (const [key, value] of Object.entries(record)) {
        found.push(...findUncappedArrays(value, path ? `${path}.${key}` : key));
      }
      return found;
    }

    for (const tool of tools) {
      const found = findUncappedArrays(tool.inputSchema);
      expect(found, `Tool "${tool.name}" has uncapped arrays at: ${found.join(", ")}`).toHaveLength(
        0,
      );
    }
  });

  it("rejects an oversized array with a single issue", () => {
    const tool = generatedTools.find((candidate) => candidate.name === "network-import");
    const result = tool?.schema.safeParse({ names: Array.from({ length: 1_000_000 }, () => 1) });

    expect(result?.success).toBe(false);
    expect(result?.error?.issues).toHaveLength(1);
    expect(result?.error?.issues[0]).toMatchObject({ code: "too_big", path: ["names"] });
  });

  it("caps the lists env-apply takes", () => {
    const result = envApplyTool.schema.safeParse({
      scope: "application",
      id: "app-1",
      remove: Array.from({ length: 1001 }, () => "NAME"),
    });

    expect(result.success).toBe(false);
    expect(result.error?.issues).toContainEqual(
      expect.objectContaining({ code: "too_big", path: ["remove"] }),
    );
  });

  it("keeps the input schema shape of the previous converter", async () => {
    const tools = await getToolList();
    const schemas = new Map(
      tools.map((tool) => [tool.name, tool.inputSchema as Record<string, unknown>]),
    );
    const propertiesOf = (name: string) =>
      schemas.get(name)?.properties as Record<string, Record<string, unknown>>;

    function findOpenObjects(obj: unknown, path = ""): string[] {
      if (obj === null || typeof obj !== "object") return [];
      if (Array.isArray(obj)) {
        return obj.flatMap((item, i) => findOpenObjects(item, `${path}[${i}]`));
      }
      const record = obj as Record<string, unknown>;
      const found = record.properties && record.additionalProperties === undefined ? [path] : [];
      for (const [key, value] of Object.entries(record)) {
        found.push(...findOpenObjects(value, path ? `${path}.${key}` : key));
      }
      return found;
    }

    for (const tool of tools) {
      const serialized = JSON.stringify(tool.inputSchema);
      expect(serialized, `Tool "${tool.name}" uses oneOf`).not.toContain('"oneOf"');
      expect(findOpenObjects(tool.inputSchema), `Tool "${tool.name}" has open objects`).toEqual([]);
    }
    // z.any() accepts a missing key, so it is not listed as required.
    expect(schemas.get("backup-update")?.required).not.toContain("metadata");
    // .email().regex(<lookaround>): the format stays, the stripped pattern leaves no allOf.
    expect(propertiesOf("bitbucket-create").bitbucketEmail).toEqual({
      type: "string",
      format: "email",
    });
  });

  it("all tools have name, inputSchema with type=object", async () => {
    const tools = await getToolList();
    for (const tool of tools) {
      expect(tool.name, "tool is missing name").toBeTruthy();
      expect(tool.inputSchema, `tool "${tool.name}" is missing inputSchema`).toBeDefined();
      expect(
        (tool.inputSchema as Record<string, unknown>).type,
        `tool "${tool.name}" inputSchema is missing type`,
      ).toBe("object");
    }
  });

  it("exposes application env upsert with partial-update inputs", async () => {
    const tools = await getToolList();
    const tool = tools.find((candidate) => candidate.name === "application-env-upsert");

    expect(tool).toBeDefined();
    expect(tool?.description).toBe("POST /application.env.upsert");

    const schema = tool?.inputSchema as Record<string, unknown>;
    const properties = schema.properties as Record<string, Record<string, unknown>>;

    expect(schema.required).toEqual(["applicationId", "variables"]);
    expect(properties.applicationId.type).toBe("string");
    expect(properties.variables.type).toBe("object");
    expect(properties.variables.additionalProperties).toMatchObject({
      type: "string",
    });
    expect(properties.variables.propertyNames).toMatchObject({
      pattern: "^[A-Za-z_][A-Za-z0-9_]*$",
    });
    expect(properties.redeploy.type).toBe("boolean");
    expect(properties.dryRun.type).toBe("boolean");
    expect(properties.expectedRevision.type).toBe("string");

    const generatedTool = generatedTools.find(
      (candidate) => candidate.name === "application-env-upsert",
    );
    expect(generatedTool).toBeDefined();
    expect(
      generatedTool?.schema.safeParse({
        applicationId: "app_1",
        variables: {
          REDIS_PASSWORD: "placeholder-secret-value",
        },
      }).success,
    ).toBe(true);
    expect(
      generatedTool?.schema.safeParse({
        applicationId: "app_1",
        variables: {},
      }).success,
    ).toBe(false);
    expect(
      generatedTool?.schema.safeParse({
        applicationId: "app_1",
        variables: {
          "1_BAD": "placeholder-secret-value",
        },
      }).success,
    ).toBe(false);
  });

  it("routes application env upsert without full environment replacement or raw value output", async () => {
    mocked(apiClient.post).mockResolvedValue({
      data: {
        applicationId: "app_1",
        changed: true,
        revision: "env:next",
        dryRun: true,
        redeployed: false,
        variables: [
          {
            name: "REDIS_PASSWORD",
            action: "updated",
            secret: true,
          },
        ],
      },
    });

    const client = await createConnectedClient();
    const consoleError = spyOn(console, "error").mockImplementation(() => {});
    try {
      const result = await client.callTool({
        name: "application-env-upsert",
        arguments: {
          applicationId: "app_1",
          variables: {
            REDIS_PASSWORD: "placeholder-secret-value",
          },
          dryRun: true,
          redeploy: false,
          expectedRevision: "env:current",
        },
      });

      expect(apiClient.get).not.toHaveBeenCalled();
      expect(apiClient.post).toHaveBeenCalledTimes(1);
      expect(apiClient.post).toHaveBeenCalledWith("/application/env/upsert", {
        applicationId: "app_1",
        variables: {
          REDIS_PASSWORD: "placeholder-secret-value",
        },
        dryRun: true,
        redeploy: false,
        expectedRevision: "env:current",
      });
      expect(apiClient.post).not.toHaveBeenCalledWith(
        "/application.saveEnvironment",
        expect.anything(),
      );

      const [, postBody] = mocked(apiClient.post).mock.calls[0] as [
        string,
        Record<string, unknown>,
      ];
      expect(postBody).not.toHaveProperty("env");
      expect(postBody).not.toHaveProperty("buildArgs");
      expect(postBody).not.toHaveProperty("buildSecrets");
      expect(postBody).not.toHaveProperty("createEnvFile");

      const responseText = result.content
        .map((item) => (item.type === "text" ? item.text : ""))
        .join("\n");
      const logText = consoleError.mock.calls.map((call) => String(call[0])).join("\n");

      expect(responseText).toContain('"applicationId": "app_1"');
      expect(responseText).toContain('"secret": true');
      expect(responseText).not.toContain("placeholder-secret-value");
      expect(logText).toContain('"REDIS_PASSWORD":"[REDACTED]"');
      expect(logText).not.toContain("placeholder-secret-value");
    } finally {
      consoleError.mockRestore();
      await client.close();
    }
  });

  it("matches the verified recovery OpenAPI path subtrees", () => {
    const spec = JSON.parse(
      readFileSync(new URL("./generated/openapi.json", import.meta.url), "utf8"),
    ) as { paths: Record<string, unknown> };
    const recoverySubtrees = Object.fromEntries(
      RECOVERY_PATHS.map((path) => [path, spec.paths[path]]),
    );
    const digest = createHash("sha256").update(JSON.stringify(recoverySubtrees)).digest("hex");

    expect(digest).toBe(VERIFIED_RECOVERY_SUBTREE_SHA256);
    expect(RECOVERY_PATHS.every((path) => spec.paths[path] !== undefined)).toBe(true);
  });

  it("keeps two fresh remote and local profile server contracts byte-equivalent", async () => {
    const first = await getToolList();
    const second = await getToolList();

    expect(JSON.stringify(first)).toBe(JSON.stringify(second));
  });

  it("exposes exact recovery names, schemas, and conservative annotations", async () => {
    const tools = await getToolList();
    const envTool = tools.find(({ name }) => name === "compose_env_upsert");
    const exactTool = tools.find(({ name }) => name === "compose_deploy_exact");
    const reconcileTool = tools.find(({ name }) => name === "deployment_reconcile");

    expect(envTool?.annotations).toMatchObject({
      destructiveHint: true,
      openWorldHint: true,
    });
    expect(envTool?.annotations).not.toHaveProperty("idempotentHint");
    expect(envTool?.annotations).not.toHaveProperty("readOnlyHint");
    expect(exactTool?.annotations).toMatchObject({
      destructiveHint: true,
      idempotentHint: true,
      openWorldHint: true,
    });
    expect(reconcileTool?.annotations).toMatchObject({
      destructiveHint: true,
      openWorldHint: true,
    });
    expect(reconcileTool?.annotations).not.toHaveProperty("idempotentHint");
    expect(tools.filter(({ name }) => name === "compose_env_upsert")).toHaveLength(1);
    expect(tools.filter(({ name }) => name === "compose_deploy_exact")).toHaveLength(1);
    expect(tools.filter(({ name }) => name === "deployment_reconcile")).toHaveLength(1);
    expect(tools.some(({ name }) => name === "compose-env-upsert")).toBe(false);
    expect(tools.some(({ name }) => name === "compose-deployExact")).toBe(false);
    expect(tools.some(({ name }) => name === "deployment-reconcile")).toBe(false);
  });

  it("enforces exact SHA and idempotency key bounds", () => {
    const exactTool = generatedTools.find(({ name }) => name === "compose_deploy_exact");
    const validInput = {
      composeId: "compose_1",
      expectedRevision: "a".repeat(40),
      idempotencyKey: "stable-1",
    };

    expect(exactTool?.schema.safeParse(validInput).success).toBe(true);
    for (const expectedRevision of [
      "A".repeat(40),
      "main",
      "g".repeat(40),
      "a".repeat(39),
      "a".repeat(41),
    ]) {
      expect(exactTool?.schema.safeParse({ ...validInput, expectedRevision }).success).toBe(false);
    }
    expect(
      exactTool?.schema.safeParse({ ...validInput, idempotencyKey: "x".repeat(7) }).success,
    ).toBe(false);
    expect(
      exactTool?.schema.safeParse({ ...validInput, idempotencyKey: "x".repeat(201) }).success,
    ).toBe(false);
  });

  it("rejects empty or invalid compose env variable maps", () => {
    const envTool = generatedTools.find(({ name }) => name === "compose_env_upsert");
    expect(
      envTool?.schema.safeParse({ composeId: "compose_1", variables: {}, dryRun: true }).success,
    ).toBe(false);
    expect(
      envTool?.schema.safeParse({
        composeId: "compose_1",
        variables: { "1_INVALID": "value" },
        dryRun: true,
      }).success,
    ).toBe(false);
    expect(
      envTool?.schema.safeParse({
        composeId: "compose_1",
        variables: { VALID_NAME: 123 },
        dryRun: true,
      }).success,
    ).toBe(false);
  });

  it("performs compose env conditional preview then one exact-revision write", async () => {
    mocked(apiClient.post)
      .mockResolvedValueOnce({
        data: {
          composeId: "compose_1",
          changed: true,
          revision: "env:current",
          dryRun: true,
          variables: [{ name: "TOKEN", action: "updated", secret: true }],
        },
      })
      .mockResolvedValueOnce({
        data: {
          composeId: "compose_1",
          changed: true,
          revision: "env:next",
          dryRun: false,
          variables: [{ name: "TOKEN", action: "updated", secret: true }],
        },
      });

    const client = await createConnectedClient();
    const result = await client.callTool({
      name: "compose_env_upsert",
      arguments: {
        composeId: "compose_1",
        variables: { TOKEN: "submitted-value" },
        dryRun: false,
        expectedRevision: "env:current",
      },
    });
    await client.close();

    expect(apiClient.post).toHaveBeenCalledTimes(2);
    expect(apiClient.post).toHaveBeenNthCalledWith(1, "/compose/env/upsert", {
      composeId: "compose_1",
      variables: { TOKEN: "submitted-value" },
      dryRun: true,
      expectedRevision: "env:current",
    });
    expect(apiClient.post).toHaveBeenNthCalledWith(2, "/compose/env/upsert", {
      composeId: "compose_1",
      variables: { TOKEN: "submitted-value" },
      dryRun: false,
      expectedRevision: "env:current",
    });
    expect(apiClient.get).not.toHaveBeenCalled();
    const serializedResult = responseText(result);
    expect(serializedResult).toContain('"name": "TOKEN"');
    expect(serializedResult).toContain('"action": "updated"');
    expect(serializedResult).toContain('"secret": true');
    expect(serializedResult).not.toContain("submitted-value");
  });

  it("runs compose env dry-run as one preview request", async () => {
    mocked(apiClient.post).mockResolvedValue({
      data: {
        composeId: "compose_1",
        changed: false,
        revision: "env:current",
        dryRun: true,
        variables: [{ name: "TOKEN", action: "unchanged", secret: true }],
      },
    });
    const client = await createConnectedClient();
    await client.callTool({
      name: "compose_env_upsert",
      arguments: {
        composeId: "compose_1",
        variables: { TOKEN: "submitted-value" },
        dryRun: true,
      },
    });
    await client.close();

    expect(apiClient.post).toHaveBeenCalledTimes(1);
    expect(apiClient.post).toHaveBeenCalledWith("/compose/env/upsert", {
      composeId: "compose_1",
      variables: { TOKEN: "submitted-value" },
      dryRun: true,
    });
  });

  it("rejects compose env writes without a revision before any request or log", async () => {
    const consoleError = spyOn(console, "error").mockImplementation(() => {});
    const client = await createConnectedClient();
    consoleError.mockClear();
    try {
      const result = await client.callTool({
        name: "compose_env_upsert",
        arguments: {
          composeId: "compose_1",
          variables: { TOKEN: "submitted-value" },
          dryRun: false,
        },
      });

      expect(apiClient.post).not.toHaveBeenCalled();
      expect(apiClient.get).not.toHaveBeenCalled();
      expect(consoleError).not.toHaveBeenCalled();
      expect(responseText(result)).toContain("Invalid input");
    } finally {
      consoleError.mockRestore();
      await client.close();
    }
  });

  it("rejects both secret placeholders at start, middle, and end before request or log", async () => {
    const values = FORBIDDEN_PLACEHOLDER_FIXTURES();
    const consoleError = spyOn(console, "error").mockImplementation(() => {});
    const client = await createConnectedClient();
    consoleError.mockClear();
    try {
      for (const value of values) {
        const result = await client.callTool({
          name: "compose_env_upsert",
          arguments: {
            composeId: "compose_1",
            variables: { TOKEN: value },
            dryRun: true,
          },
        });
        expect(responseText(result)).not.toContain(value);
      }

      expect(apiClient.post).not.toHaveBeenCalled();
      expect(apiClient.get).not.toHaveBeenCalled();
      expect(consoleError).not.toHaveBeenCalled();
    } finally {
      consoleError.mockRestore();
      await client.close();
    }
  });

  it("stops stale, mismatched, and invalid env previews without fallback or write", async () => {
    const client = await createConnectedClient();
    const cases: unknown[] = [
      {
        isAxiosError: true,
        response: { status: 409, data: { message: "remote-sensitive-conflict" } },
      },
      {
        data: {
          composeId: "compose_1",
          changed: true,
          revision: "env:other",
          dryRun: true,
          variables: [{ name: "TOKEN", action: "updated", secret: true }],
        },
      },
      { data: { composeId: "compose_1", revision: "env:current" } },
    ];

    for (const fixture of cases) {
      mock.clearAllMocks();
      if (isRejectedFixture(fixture)) {
        mocked(apiClient.post).mockRejectedValueOnce(fixture);
      } else {
        mocked(apiClient.post).mockResolvedValueOnce(fixture);
      }
      const result = await client.callTool({
        name: "compose_env_upsert",
        arguments: {
          composeId: "compose_1",
          variables: { TOKEN: "submitted-value" },
          dryRun: false,
          expectedRevision: "env:current",
        },
      });

      expect(apiClient.post).toHaveBeenCalledTimes(1);
      expect(apiClient.get).not.toHaveBeenCalled();
      expect(apiClient.post).not.toHaveBeenCalledWith(
        "/compose.saveEnvironment",
        expect.anything(),
      );
      expect(responseText(result)).not.toContain("remote-sensitive-conflict");
    }
    await client.close();
  });

  it("tells the caller to re-preview for a fresh revision on a compose env conflict", async () => {
    mocked(apiClient.post).mockRejectedValueOnce({
      isAxiosError: true,
      response: { status: 409, data: { message: "remote-sensitive-conflict" } },
    });
    const client = await createConnectedClient();
    const result = await client.callTool({
      name: "compose_env_upsert",
      arguments: {
        composeId: "compose_1",
        variables: { TOKEN: "submitted-value" },
        dryRun: false,
        expectedRevision: "env:stale",
      },
    });
    await client.close();

    const text = responseText(result);
    expect(text).toContain("The compose env revision is stale or changed concurrently");
    expect(text).toContain("dryRun=true and no expectedRevision");
    expect(text).not.toContain("remote-sensitive-conflict");
  });

  it("lists superPassword-status on top of any preset, and no other superPassword tool", async () => {
    process.env.DOKPLOY_TOOL_PRESET = "minimal";

    const tools = await getToolList();
    const superPasswordTools = tools.filter(({ name }) => name.startsWith("superPassword"));

    expect(superPasswordTools.map(({ name }) => name)).toEqual(["superPassword-status"]);
  });

  it("explains each super password denial with a fixed message instead of the server body", async () => {
    const cases = [
      {
        serverMessage: "API key write access is locked. Open it in Profile → Super password.",
        expected: "writes through the API key are locked",
      },
      {
        serverMessage:
          "This action needs the super password. Open access in Profile → Super password.",
        expected: "needs open super password access",
      },
      {
        serverMessage:
          "This action needs a browser session with super password access open. API keys cannot perform it.",
        expected: "can never perform it, even while access is open",
      },
    ];

    for (const { serverMessage, expected } of cases) {
      mock.clearAllMocks();
      mocked(apiClient.post).mockRejectedValueOnce({
        isAxiosError: true,
        response: { status: 403, data: { message: serverMessage, code: "FORBIDDEN" } },
      });
      const client = await createConnectedClient();
      const result = await client.callTool({
        name: "compose-fetchSourceType",
        arguments: { composeId: "compose_1" },
      });
      await client.close();

      const text = responseText(result);
      expect(result.isError).toBe(true);
      expect(text).toContain("blocked by the Dokploy super password");
      expect(text).toContain(expected);
      expect(text).not.toContain(serverMessage);
    }
  });

  it("still hides the body of any other 403", async () => {
    mocked(apiClient.post).mockRejectedValueOnce({
      isAxiosError: true,
      response: { status: 403, data: { message: "remote-sensitive-forbidden" } },
    });
    const client = await createConnectedClient();
    const result = await client.callTool({
      name: "compose-fetchSourceType",
      arguments: { composeId: "compose_1" },
    });
    await client.close();

    const text = responseText(result);
    expect(text).toContain("The Dokploy API request failed with status 403");
    expect(text).not.toContain("remote-sensitive-forbidden");
    expect(text).not.toContain("super password");
  });

  it("returns the super password status without the hint or recovery channels", async () => {
    const expiresAt = new Date(Date.now() + (17 * 60 + 42) * 60_000 + 30_000).toISOString();
    mocked(apiClient.get).mockResolvedValueOnce({
      data: {
        isSet: true,
        hint: "remote-hint-text",
        active: true,
        expiresAt,
        lockedUntil: null,
        durationMs: 86_400_000,
        canManage: true,
        viaApiKey: true,
        recoveryChannels: [{ notificationId: "n1", name: "remote-channel-name", type: "telegram" }],
      },
    });
    const client = await createConnectedClient();
    const result = await client.callTool({ name: "superPassword-status", arguments: {} });
    await client.close();

    expect(apiClient.get).toHaveBeenCalledWith("/superPassword.status");
    const text = responseText(result);
    const parsed = JSON.parse(text);
    expect(parsed.data).toMatchObject({
      isSet: true,
      active: true,
      expiresAt,
      timeLeft: "17 h 42 min",
      apiKeyWrites: "allowed while access is open",
    });
    expect(text).not.toContain("remote-hint-text");
    expect(text).not.toContain("remote-channel-name");
    expect(text).not.toContain("recoveryChannels");
  });

  it("reports locked API-key writes while super password access is closed", async () => {
    mocked(apiClient.get).mockResolvedValueOnce({
      data: { isSet: true, active: false, expiresAt: null, lockedUntil: null },
    });
    const client = await createConnectedClient();
    const result = await client.callTool({ name: "superPassword-status", arguments: {} });
    await client.close();

    const parsed = JSON.parse(responseText(result));
    expect(parsed.data.active).toBe(false);
    expect(parsed.data.timeLeft).toBeNull();
    expect(parsed.data.apiKeyWrites).toStartWith("locked:");
  });

  it("retries exact deploy at most three times with one byte-identical body and key", async () => {
    const noResponse = { isAxiosError: true, request: {}, code: "ETIMEDOUT" };
    const unavailable = { isAxiosError: true, response: { status: 503 } };
    mocked(apiClient.post)
      .mockRejectedValueOnce(noResponse)
      .mockRejectedValueOnce(unavailable)
      .mockResolvedValueOnce({
        data: {
          composeId: "compose_1",
          operationId: "operation_1",
          sourceRevision: "a".repeat(40),
          resolvedRevision: "a".repeat(40),
          status: "accepted",
          deduplicated: false,
          idempotencyKey: "stable-key",
        },
      });

    const client = await createConnectedClient();
    const result = await client.callTool({
      name: "compose_deploy_exact",
      arguments: {
        composeId: "compose_1",
        expectedRevision: "a".repeat(40),
        idempotencyKey: "stable-key",
      },
    });
    await client.close();

    expect(apiClient.post).toHaveBeenCalledTimes(3);
    const bodies = mocked(apiClient.post).mock.calls.map((call) => call[1]);
    expect(bodies[1]).toBe(bodies[0]);
    expect(bodies[2]).toBe(bodies[0]);
    expect(JSON.stringify(bodies[1])).toBe(JSON.stringify(bodies[0]));
    expect(JSON.stringify(bodies[2])).toBe(JSON.stringify(bodies[0]));
    expect(responseText(result)).not.toContain("stable-key");
  });

  it("does not retry exact deploy on 409 or an invalid response", async () => {
    const client = await createConnectedClient();
    for (const fixture of [
      { rejected: { isAxiosError: true, response: { status: 409 } } },
      { rejected: { isAxiosError: true } },
      { resolved: { data: { composeId: "compose_1", operationId: "operation_1" } } },
    ]) {
      mock.clearAllMocks();
      if (fixture.rejected) {
        mocked(apiClient.post).mockRejectedValueOnce(fixture.rejected);
      } else if (fixture.resolved) {
        mocked(apiClient.post).mockResolvedValueOnce(fixture.resolved);
      }
      await client.callTool({
        name: "compose_deploy_exact",
        arguments: {
          composeId: "compose_1",
          expectedRevision: "a".repeat(40),
          idempotencyKey: "stable-key",
        },
      });
      expect(apiClient.post).toHaveBeenCalledTimes(1);
    }
    await client.close();
  });

  it("blocks reconcile repair for unavailable, queued, active, final, running, linked, and invalid state", async () => {
    const base = reconcileFixture();
    const fixtures = [
      { ...base, queue: { state: "queue-unavailable", reasonCode: "network-error" } },
      { ...base, queue: { state: "queued" } },
      { ...base, queue: { state: "active" } },
      { ...base, operationStatus: "succeeded" },
      { ...base, operationStatus: "running" },
      { ...base, composeId: "compose_other" },
      { ...base, operationId: "operation_other" },
      {
        ...base,
        deployment: {
          deploymentId: "deployment_1",
          status: "running",
          startedAt: null,
          finishedAt: null,
        },
      },
      { composeId: "compose_1", operationId: "operation_1" },
    ];
    const client = await createConnectedClient();

    for (const data of fixtures) {
      mock.clearAllMocks();
      mocked(apiClient.post).mockResolvedValueOnce({ data });
      await client.callTool({
        name: "deployment_reconcile",
        arguments: { composeId: "compose_1", operationId: "operation_1", repair: true },
      });
      expect(apiClient.post).toHaveBeenCalledTimes(1);
      expect(apiClient.post).not.toHaveBeenCalledWith("/deployment/reconcile", {
        composeId: "compose_1",
        operationId: "operation_1",
        repair: true,
      });
    }
    await client.close();
  });

  it("repairs only eligible queue-empty reconcile state and never retries the repair call", async () => {
    const inspect = reconcileFixture();
    const client = await createConnectedClient();

    mocked(apiClient.post)
      .mockResolvedValueOnce({ data: inspect })
      .mockResolvedValueOnce({ data: { ...inspect, repairPerformed: true } });
    await client.callTool({
      name: "deployment_reconcile",
      arguments: { composeId: "compose_1", operationId: "operation_1", repair: true },
    });
    expect(apiClient.post).toHaveBeenCalledTimes(2);
    expect(apiClient.post).toHaveBeenNthCalledWith(1, "/deployment/reconcile", {
      composeId: "compose_1",
      operationId: "operation_1",
      repair: false,
    });
    expect(apiClient.post).toHaveBeenNthCalledWith(2, "/deployment/reconcile", {
      composeId: "compose_1",
      operationId: "operation_1",
      repair: true,
    });

    mock.clearAllMocks();
    mocked(apiClient.post)
      .mockResolvedValueOnce({ data: inspect })
      .mockRejectedValueOnce({ isAxiosError: true, response: { status: 503 } });
    await client.callTool({
      name: "deployment_reconcile",
      arguments: { composeId: "compose_1", operationId: "operation_1", repair: true },
    });
    expect(apiClient.post).toHaveBeenCalledTimes(2);
    await client.close();
  });

  it("projects recovery output through allowlists and removes secret or diagnostic extras", async () => {
    const response = {
      ...reconcileFixture(),
      env: "forbidden-env",
      value: "forbidden-value",
      idempotencyKey: "forbidden-key",
      logPath: "forbidden-log-path",
      errorMessage: "forbidden-exception",
      queue: { state: "queue-unavailable", reasonCode: "remote-error", data: "forbidden-queue" },
    };
    mocked(apiClient.post).mockResolvedValueOnce({ data: response });
    const client = await createConnectedClient();
    const result = await client.callTool({
      name: "deployment_reconcile",
      arguments: { composeId: "compose_1", operationId: "operation_1", repair: false },
    });
    await client.close();

    const serialized = responseText(result);
    for (const forbidden of [
      "forbidden-env",
      "forbidden-value",
      "forbidden-key",
      "forbidden-log-path",
      "forbidden-exception",
      "forbidden-queue",
    ]) {
      expect(serialized).not.toContain(forbidden);
    }
  });

  it("keeps legacy POST tools non-idempotent, non-retried, and full-save visibly high risk", async () => {
    for (const tool of generatedTools.filter(({ method }) => method === "POST")) {
      if (tool.name !== "compose_deploy_exact") {
        expect(tool.annotations?.idempotentHint, tool.name).not.toBe(true);
      }
    }
    const fullSave = generatedTools.find(({ name }) => name === "compose-saveEnvironment");
    expect(fullSave?.description).toContain("HIGH RISK: full environment replacement");
    expect(fullSave?.annotations?.destructiveHint).toBe(true);
    expect(fullSave?.execution).toBeUndefined();

    mocked(apiClient.post).mockRejectedValue({
      isAxiosError: true,
      response: { status: 503 },
    });
    const client = await createConnectedClient();
    await client.callTool({
      name: "application-redeploy",
      arguments: { applicationId: "application_1" },
    });
    await client.close();
    expect(apiClient.post).toHaveBeenCalledTimes(1);
  });

  type ToolResult = Awaited<
    ReturnType<Awaited<ReturnType<typeof createConnectedClient>>["callTool"]>
  >;

  // Building a server converts every tool schema, so the tests below share one
  // client per test instead of connecting again for each call.
  let sharedClient: Awaited<ReturnType<typeof createConnectedClient>> | undefined;

  afterEach(async () => {
    await sharedClient?.close();
    sharedClient = undefined;
  });

  async function getSharedClient() {
    sharedClient ??= await createConnectedClient();
    return sharedClient;
  }

  async function callTool(name: string, args: Record<string, unknown>): Promise<ToolResult> {
    const client = await getSharedClient();
    return client.callTool({ name, arguments: args });
  }

  async function callToolCapturingLogs(name: string, args: Record<string, unknown>) {
    const client = await getSharedClient();
    const consoleError = spyOn(console, "error").mockImplementation(() => {});
    try {
      const result = await client.callTool({ name, arguments: args });
      return { result, logs: consoleError.mock.calls.map((call) => String(call[0])).join("\n") };
    } finally {
      consoleError.mockRestore();
    }
  }

  function resultData(result: ToolResult): Record<string, unknown> {
    return JSON.parse(responseText(result as Parameters<typeof responseText>[0])).data;
  }

  function resultText(result: ToolResult): string {
    return responseText(result as Parameters<typeof responseText>[0]);
  }

  const base64 = (text: string) => Buffer.from(text, "utf8").toString("base64");
  const fromBase64 = (value: unknown) => Buffer.from(String(value), "base64").toString("utf8");

  it("redacts responses even though DOKPLOY_REDACT_ENV=false", async () => {
    expect(process.env.DOKPLOY_REDACT_ENV).toBe("false");
    mocked(apiClient.get).mockResolvedValueOnce({
      data: {
        applicationId: "app_1",
        name: "web",
        env: `# runtime\nAPI_TOKEN=${SECRET}\nPORT=3000`,
        buildArgs: null,
        previewEnv: "",
        buildSecrets: `NPM_TOKEN=${SECRET}`,
        password: SECRET,
        refreshToken: SECRET,
        secret: true,
        isPreviewDeploymentsActive: false,
        customGitUrl: `https://deploy:${SECRET}@git.example.test/org/repo.git`,
        command: `node server.js --api-token ${SECRET}`,
        compose: { composeFile: `services:\n  web:\n    environment:\n      A_TOKEN: ${SECRET}` },
      },
    });

    const result = await callTool("application-one", { applicationId: "app_1" });

    expect(resultText(result)).not.toContain(SECRET);
    expect(resultData(result)).toEqual({
      applicationId: "app_1",
      name: "web",
      env: "API_TOKEN=[REDACTED]\nPORT=[REDACTED]",
      buildArgs: null,
      previewEnv: "",
      buildSecrets: "NPM_TOKEN=[REDACTED]",
      password: "[REDACTED]",
      refreshToken: "[REDACTED]",
      secret: true,
      isPreviewDeploymentsActive: false,
      customGitUrl: "https://deploy:[REDACTED]@git.example.test/org/repo.git",
      command: "node server.js --api-token [REDACTED]",
      compose: { composeFile: "services:\n  web:\n    environment:\n      A_TOKEN: [REDACTED]" },
    });
  });

  it("adds DOKPLOY_REDACT_FIELDS to the baseline instead of replacing it", async () => {
    const { ConfigManager } = await import("./utils/clientConfig.js");
    process.env.DOKPLOY_REDACT_FIELDS = "internalNote";
    ConfigManager.resetInstance();
    mocked(apiClient.get).mockResolvedValueOnce({
      data: { name: "web", internalNote: "private", env: `A_TOKEN=${SECRET}`, password: SECRET },
    });

    try {
      const result = await callTool("application-one", { applicationId: "app_1" });
      expect(resultData(result)).toEqual({
        name: "web",
        internalNote: "[REDACTED]",
        env: "A_TOKEN=[REDACTED]",
        password: "[REDACTED]",
      });
    } finally {
      delete process.env.DOKPLOY_REDACT_FIELDS;
      ConfigManager.resetInstance();
    }
  });

  it("scrubs secrets out of logs and other free text", async () => {
    mocked(apiClient.get).mockResolvedValueOnce({
      data: [
        "starting",
        `DATABASE_URL=postgres://app:${SECRET}@db:5432/app`,
        `Authorization: Bearer ${SECRET}`,
        `level=error msg="login failed" password=${SECRET}`,
        "done",
      ].join("\n"),
    });

    const result = await callTool("application-readLogs", { applicationId: "app_1" });
    const logs = JSON.parse(resultText(result)).data;

    expect(logs).toBe(
      [
        "starting",
        "DATABASE_URL=postgres://app:[REDACTED]@db:5432/app",
        "Authorization: Bearer [REDACTED]",
        'level=error msg="login failed" password=[REDACTED]',
        "done",
      ].join("\n"),
    );
  });

  it("scrubs error text that comes back inside a successful response", async () => {
    mocked(apiClient.post).mockResolvedValueOnce({
      data: { ok: false, error: `connect failed: redis://:${SECRET}@cache:6379`, attempts: 3 },
    });

    const result = await callTool("application-redeploy", { applicationId: "app_1" });

    expect(resultData(result)).toEqual({
      ok: false,
      error: "connect failed: redis://:[REDACTED]@cache:6379",
      attempts: 3,
    });
  });

  it("keeps only variable names in a docker config", async () => {
    mocked(apiClient.get).mockResolvedValueOnce({
      data: {
        Config: {
          Env: ["PATH=/usr/local/bin", `DB_PASSWORD=${SECRET}`],
          Cmd: ["redis-server", "--requirepass", SECRET],
          Tty: false,
        },
      },
    });

    const result = await callTool("docker-getConfig", { containerId: "container1" });

    expect(resultData(result)).toEqual({
      Config: {
        Env: ["PATH=[REDACTED]", "DB_PASSWORD=[REDACTED]"],
        Cmd: ["redis-server", "--requirepass", "[REDACTED]"],
        Tty: false,
      },
    });
  });

  it("scrubs base64 file content and replaces binary files", async () => {
    for (const [tool, args] of [
      ["docker-readContainerFile", { containerId: "container1", path: "/app/.env" }],
      ["dockerVolume-readVolumeFile", { volumeName: "data", path: "/config.yml" }],
    ] as const) {
      mocked(apiClient.get).mockResolvedValueOnce({
        data: {
          content: base64(`API_TOKEN=${SECRET}\npassword: ${SECRET}\nPORT=3000\n`),
          truncated: false,
        },
      });
      const textResult = await callTool(tool, args);
      const textData = resultData(textResult);
      expect(textData.truncated).toBe(false);
      expect(fromBase64(textData.content)).toBe(
        "API_TOKEN=[REDACTED]\npassword: [REDACTED]\nPORT=3000\n",
      );

      mocked(apiClient.get).mockResolvedValueOnce({
        data: { content: Buffer.from([0, 1, 2, 255, 254]).toString("base64"), truncated: false },
      });
      const binaryResult = await callTool(tool, args);
      expect(resultData(binaryResult)).toEqual({ content: "[REDACTED]", truncated: false });
    }
  });

  it("redacts the output of execution-policy tools and keeps their flags", async () => {
    mocked(apiClient.post).mockResolvedValueOnce({
      data: { ...reconcileFixture(), resolvedRevision: `token=${SECRET}` },
    });

    const result = await callTool("deployment_reconcile", {
      composeId: "compose_1",
      operationId: "operation_1",
      repair: false,
    });

    expect(resultText(result)).not.toContain(SECRET);
    expect(resultData(result)).toEqual({
      ...reconcileFixture(),
      resolvedRevision: "token=[REDACTED]",
      repairPerformed: false,
      deployment: null,
    });
  });

  it("never lists a tool that needs a whole env text, under any preset", async () => {
    for (const preset of ["all", "deploy", "databases"]) {
      process.env.DOKPLOY_TOOL_PRESET = preset;
      const names = (await getToolList()).map(({ name }) => name);
      for (const removed of FULL_ENV_REPLACE_TOOLS) {
        expect(names).not.toContain(removed);
      }
      expect(names.filter((name) => name.endsWith("-saveEnvironment"))).toEqual([]);
      expect(names).toContain("env-keys");
      expect(names).toContain("env-apply");
    }
  });

  it("derives the removed tools from the schemas that require an env text", async () => {
    const { requiresFullEnvText } = await import("./envTools.js");
    expect(generatedTools.filter(requiresFullEnvText).map(({ name }) => name)).toEqual(
      FULL_ENV_REPLACE_TOOLS,
    );
  });

  it("refuses to call a removed full-replace tool", async () => {
    const result = await callTool("compose-saveEnvironment", {
      composeId: "compose_1",
      env: `A_TOKEN=${SECRET}`,
    });

    expect(result.isError).toBe(true);
    expect(resultText(result)).not.toContain(SECRET);
    expect(apiClient.post).not.toHaveBeenCalled();
  });

  it("rejects every full env field on other tools before any request or log", async () => {
    const cases: Array<[string, Record<string, unknown>]> = [
      ["application-update", { applicationId: "app_1", env: `A_TOKEN=${SECRET}` }],
      ["application-update", { applicationId: "app_1", buildArgs: `A_TOKEN=${SECRET}` }],
      ["application-update", { applicationId: "app_1", buildSecrets: `A_TOKEN=${SECRET}` }],
      ["application-update", { applicationId: "app_1", previewEnv: `A_TOKEN=${SECRET}` }],
      ["application-update", { applicationId: "app_1", previewBuildArgs: `A_TOKEN=${SECRET}` }],
      ["application-update", { applicationId: "app_1", previewBuildSecrets: `A_TOKEN=${SECRET}` }],
      ["compose-update", { composeId: "compose_1", env: `A_TOKEN=${SECRET}` }],
      ["postgres-update", { postgresId: "postgres_1", env: `A_TOKEN=${SECRET}` }],
      ["project-create", { name: "demo", env: `A_TOKEN=${SECRET}` }],
      ["environment-update", { environmentId: "environment_1", env: `A_TOKEN=${SECRET}` }],
      ["application-update", { applicationId: "app_1", env: "" }],
      ["application-update", { applicationId: "app_1", env: null }],
    ];

    for (const [tool, args] of cases) {
      const { result, logs } = await callToolCapturingLogs(tool, args);
      const text = resultText(result);

      expect(result.isError, tool).toBe(true);
      expect(text).toContain(`${tool} cannot write env fields`);
      expect(text).toContain("env-apply");
      expect(text).not.toContain(SECRET);
      expect(logs).not.toContain(SECRET);
      expect(logs).not.toContain("Executing tool");
    }
    expect(apiClient.post).not.toHaveBeenCalled();
    expect(apiClient.get).not.toHaveBeenCalled();
  });

  it("still lets other fields of an update tool through", async () => {
    mocked(apiClient.post).mockResolvedValueOnce({ data: { applicationId: "app_1" } });

    await callTool("application-update", { applicationId: "app_1", name: "web" });

    expect(apiClient.post).toHaveBeenCalledWith("/application.update", {
      applicationId: "app_1",
      name: "web",
    });
  });

  it("does not block composeFile writes, scrubs the file in the reply and keeps it out of the log", async () => {
    const composeFile = `services:\n  web:\n    environment:\n      API_TOKEN: ${SECRET}\n      DB_PASSWORD: \${DB_PASSWORD}\n`;
    const scrubbed = `services:\n  web:\n    environment:\n      API_TOKEN: [REDACTED]\n      DB_PASSWORD: \${DB_PASSWORD}\n`;
    mocked(apiClient.post).mockResolvedValueOnce({ data: { composeId: "compose_1", composeFile } });

    const { result, logs } = await callToolCapturingLogs("compose-update", {
      composeId: "compose_1",
      composeFile,
    });

    expect(apiClient.post).toHaveBeenCalledWith("/compose.update", {
      composeId: "compose_1",
      composeFile,
    });
    expect(result.isError).toBeUndefined();
    expect(resultData(result)).toEqual({ composeId: "compose_1", composeFile: scrubbed });
    expect(logs).toContain('"input":{"composeId":"compose_1","composeFile":"[REDACTED]"}');
    expect(logs).not.toContain(SECRET);
  });

  it("rejects redacted text written back through any tool at any depth", async () => {
    const monitoring = (token: string, include: string[]) => ({
      metricsConfig: {
        server: {
          refreshRate: 5,
          port: 4500,
          token,
          urlCallback: "https://panel.example.test/callback",
          retentionDays: 7,
          cronJob: "0 0 * * *",
          thresholds: { cpu: 0, memory: 0 },
        },
        containers: { refreshRate: 5, services: { include } },
      },
    });

    for (const placeholder of ["__DOKPLOY_REDACTED_SECRET__", "[REDACTED]"]) {
      const cases: Array<[string, Record<string, unknown>]> = [
        ["compose-update", { composeId: "compose_1", composeFile: `a: ${placeholder}\n` }],
        ["application-update", { applicationId: "app_1", description: `x ${placeholder} y` }],
        ["admin-setupMonitoring", monitoring(placeholder, [])],
        ["admin-setupMonitoring", monitoring("fixture-token", ["web", `x${placeholder}`])],
        ["application-one", { applicationId: placeholder }],
        [
          "docker-writeContainerFile",
          { containerId: "container1", path: "/a", content: placeholder },
        ],
        ["application-env-upsert", { applicationId: "app_1", variables: { A: `v${placeholder}` } }],
      ];

      for (const [tool, args] of cases) {
        const { result, logs } = await callToolCapturingLogs(tool, args);
        const text = resultText(result);

        expect(result.isError, tool).toBe(true);
        expect(text).toContain(`Invalid input for ${tool}`);
        expect(text).toContain("cannot be written back");
        expect(logs).toBe("");
      }
    }
    expect(apiClient.post).not.toHaveBeenCalled();
    expect(apiClient.get).not.toHaveBeenCalled();
  });

  it("lets restorable tokens through in a compose file and keeps them in the reply", async () => {
    const composeFile = [
      "services:",
      "  web:",
      "    environment:",
      `      PASSWORD: ${PANEL_TOKEN}`,
      `      - API_KEY=${OTHER_PANEL_TOKEN}`,
      `      DATABASE_URL: postgres://app:${PANEL_TOKEN}@db/app`,
      "",
    ].join("\n");
    mocked(apiClient.post).mockResolvedValueOnce({ data: { composeId: "compose_1", composeFile } });

    const { result, logs } = await callToolCapturingLogs("compose-update", {
      composeId: "compose_1",
      composeFile,
    });

    expect(apiClient.post).toHaveBeenCalledWith("/compose.update", {
      composeId: "compose_1",
      composeFile,
    });
    expect(result.isError).toBeUndefined();
    expect(resultData(result)).toEqual({ composeId: "compose_1", composeFile });
    expect(logs).toContain('"input":{"composeId":"compose_1","composeFile":"[REDACTED]"}');
  });

  it("lets restorable tokens through in a file mount", async () => {
    const content = `token = "${PANEL_TOKEN}"\nother = "${OTHER_PANEL_TOKEN}"\n${PANEL_TOKEN}${OTHER_PANEL_TOKEN}\n`;
    mocked(apiClient.post).mockResolvedValueOnce({ data: { mountId: "mount_1", content } });

    const { result } = await callToolCapturingLogs("mounts-update", {
      mountId: "mount_1",
      content,
    });

    expect(apiClient.post).toHaveBeenCalledWith("/mounts.update", { mountId: "mount_1", content });
    expect(result.isError).toBeUndefined();
    expect(resultData(result)).toEqual({ mountId: "mount_1", content });
  });

  it("rejects a token field that also holds a placeholder that cannot be restored", async () => {
    const bare = "__DOKPLOY_REDACTED_SECRET__";
    const texts = [
      `A: ${PANEL_TOKEN}\nB: ${bare}\n`,
      `A: ${bare}\nB: ${PANEL_TOKEN}\n`,
      `A: ${PANEL_TOKEN}\nB: [REDACTED]\n`,
      `A: ${PANEL_TOKEN}${bare}`,
      `A: ${bare}${PANEL_TOKEN}`,
      `A: ${PANEL_TOKEN.slice(0, -2)}${OTHER_PANEL_TOKEN}`,
      `A: ${bare}K7F3K9Q2M4X__`,
      `A: ${bare}K7F3K6Q2M4XAB__`,
      `A: ${bare}k7f3k9q2m4xa__`,
      `A: ${bare}K7F3K6Q2M4XA_`,
      `A: ${bare}K7F3K6Q2M4XA`,
    ];

    for (const text of texts) {
      const cases: Array<[string, Record<string, unknown>]> = [
        ["compose-update", { composeId: "compose_1", composeFile: text }],
        ["mounts-update", { mountId: "mount_1", content: text }],
      ];
      for (const [tool, args] of cases) {
        const { result, logs } = await callToolCapturingLogs(tool, args);

        expect(result.isError, `${tool}: ${text}`).toBe(true);
        expect(resultText(result)).toContain("cannot be written back");
        expect(logs).toBe("");
      }
    }
    expect(apiClient.post).not.toHaveBeenCalled();
  });

  it("rejects a restorable token in every other tool and field", async () => {
    const cases: Array<[string, Record<string, unknown>]> = [
      ["compose-update", { composeId: "compose_1", description: PANEL_TOKEN }],
      ["compose-update", { composeId: PANEL_TOKEN, composeFile: "services: {}\n" }],
      ["compose-update", { composeId: "compose_1", composeFile: "a: b\n", name: PANEL_TOKEN }],
      [
        "compose-create",
        { name: "demo", environmentId: "environment_1", composeFile: `A: ${PANEL_TOKEN}\n` },
      ],
      ["mounts-update", { mountId: "mount_1", filePath: PANEL_TOKEN }],
      ["mounts-update", { mountId: "mount_1", content: "plain", hostPath: `/x/${PANEL_TOKEN}` }],
      [
        "mounts-create",
        {
          type: "file",
          content: PANEL_TOKEN,
          mountPath: "/app/config",
          serviceType: "compose",
          serviceId: "compose_1",
        },
      ],
      ["application-update", { applicationId: "app_1", description: PANEL_TOKEN }],
      ["application-one", { applicationId: PANEL_TOKEN }],
      [
        "docker-writeContainerFile",
        { containerId: "container1", path: "/a", content: PANEL_TOKEN },
      ],
      ["application-env-upsert", { applicationId: "app_1", variables: { A: PANEL_TOKEN } }],
      ["env-apply", { scope: "application", id: "app_1", set: { API_TOKEN: PANEL_TOKEN } }],
    ];

    for (const [tool, args] of cases) {
      const { result, logs } = await callToolCapturingLogs(tool, args);

      expect(result.isError, tool).toBe(true);
      expect(resultText(result)).toContain(`Invalid input for ${tool}`);
      expect(resultText(result)).toContain("cannot be written back");
      expect(logs).toBe("");
    }
    expect(apiClient.post).not.toHaveBeenCalled();
    expect(apiClient.get).not.toHaveBeenCalled();
  });

  it("explains in the rejection where a token may be sent back", async () => {
    const { result } = await callToolCapturingLogs("application-update", {
      applicationId: "app_1",
      description: PANEL_TOKEN,
    });
    const text = resultText(result);

    expect(text).toContain("__DOKPLOY_REDACTED_SECRET__XXXXXXXXXXXX__ may be sent back unchanged");
    expect(text).toContain("compose-update, field composeFile");
    expect(text).toContain("mounts-update, field content");
    expect(text).toContain("Never invent or alter a token");
    expect(text).toContain("[REDACTED] and the bare __DOKPLOY_REDACTED_SECRET__");
    expect(text).toContain("can never be written back");
    expect(text).not.toContain(PANEL_TOKEN);
  });

  it("tells the client in the server instructions how hidden values work", async () => {
    const client = await getSharedClient();
    const instructions = client.getInstructions() ?? "";

    expect(instructions).toContain("Secret values are hidden");
    expect(instructions).toContain("env-keys");
    expect(instructions).toContain("env-apply");
    expect(instructions).toContain("__DOKPLOY_REDACTED_SECRET__XXXXXXXXXXXX__");
    expect(instructions).toContain("compose-update or mounts-update");
  });

  it("lists the blind env tools with their schemas and annotations", async () => {
    const tools = await getToolList();
    const keys = tools.find(({ name }) => name === "env-keys");
    const apply = tools.find(({ name }) => name === "env-apply");

    expect(keys?.annotations).toMatchObject({ readOnlyHint: true, idempotentHint: true });
    expect(apply?.annotations).toMatchObject({ destructiveHint: true });
    expect(apply?.annotations).not.toHaveProperty("readOnlyHint");

    const keysSchema = keys?.inputSchema as Record<string, unknown>;
    const keysProperties = keysSchema.properties as Record<string, Record<string, unknown>>;
    expect(keysSchema.required).toEqual(["scope", "id"]);
    expect(keysProperties.scope.enum).toEqual([
      "application",
      "compose",
      "postgres",
      "mysql",
      "mariadb",
      "mongo",
      "redis",
      "libsql",
      "project",
      "environment",
    ]);
    expect(keysProperties.field.enum).toEqual(["env", "buildArgs", "buildSecrets"]);

    const applySchema = apply?.inputSchema as Record<string, unknown>;
    const applyProperties = applySchema.properties as Record<string, Record<string, unknown>>;
    expect(applySchema.required).toEqual(["scope", "id"]);
    for (const operation of ["set", "generate", "copy"]) {
      expect(applyProperties[operation].propertyNames).toMatchObject({
        pattern: "^[A-Za-z_][A-Za-z0-9_]*$",
      });
    }
    expect(applyProperties.remove).toMatchObject({
      type: "array",
      items: { type: "string", pattern: "^[A-Za-z_][A-Za-z0-9_]*$" },
    });
    const generateOptions = applyProperties.generate.additionalProperties as Record<
      string,
      unknown
    >;
    expect(generateOptions.properties).toMatchObject({
      length: { type: "integer", minimum: 16, maximum: 128 },
      format: { enum: ["base64url", "hex", "alphanumeric"] },
    });

    for (const phrase of [
      "never returned",
      "env-keys",
      "'generate'",
      "'copy'",
      "do not ask the user to paste it into the chat",
      "Dokploy panel UI",
      "application-redeploy",
      "compose-redeploy",
      "postgres-deploy",
    ]) {
      expect(apply?.description).toContain(phrase);
    }
    expect(keys?.description).toContain("Values are never returned");
  });

  it("names only deploy tools that exist in the env-apply description", async () => {
    const names = new Set((await getToolList()).map(({ name }) => name));
    const { envApplyTool } = await import("./envTools.js");
    const mentioned = envApplyTool.description.match(/\b[a-z]+-(?:re)?deploy\b/g) ?? [];

    expect(mentioned.length).toBeGreaterThanOrEqual(10);
    for (const name of mentioned) {
      expect(names.has(name), name).toBe(true);
    }
  });

  it("reads variable names through env-keys and returns only schema fields", async () => {
    mocked(apiClient.get).mockResolvedValueOnce({
      data: {
        scope: "application",
        id: "app_1",
        field: "env",
        revision: "env:rev-1",
        env: `API_TOKEN=${SECRET}`,
        variables: [
          { name: "API_TOKEN", secret: true, empty: false, value: SECRET },
          { name: "PORT", secret: false, empty: true, preview: SECRET },
        ],
        debug: { raw: SECRET },
      },
    });

    const result = await callTool("env-keys", { scope: "application", id: "app_1" });

    expect(apiClient.get).toHaveBeenCalledTimes(1);
    expect(apiClient.get).toHaveBeenCalledWith("/env.keys", {
      params: { scope: "application", id: "app_1" },
    });
    expect(apiClient.post).not.toHaveBeenCalled();
    expect(resultText(result)).not.toContain(SECRET);
    expect(resultData(result)).toEqual({
      scope: "application",
      id: "app_1",
      field: "env",
      revision: "env:rev-1",
      variables: [
        { name: "API_TOKEN", secret: true, empty: false },
        { name: "PORT", secret: false, empty: true },
      ],
    });
  });

  it("passes the field of env-keys and checks it against the scope", async () => {
    mocked(apiClient.get).mockResolvedValueOnce({
      data: {
        scope: "application",
        id: "app_1",
        field: "buildSecrets",
        revision: "env:rev-2",
        variables: [],
      },
    });
    const result = await callTool("env-keys", {
      scope: "application",
      id: "app_1",
      field: "buildSecrets",
    });
    expect(apiClient.get).toHaveBeenCalledWith("/env.keys", {
      params: { scope: "application", id: "app_1", field: "buildSecrets" },
    });
    expect(resultData(result).field).toBe("buildSecrets");

    mock.clearAllMocks();
    const rejected = await callTool("env-keys", {
      scope: "compose",
      id: "compose_1",
      field: "buildArgs",
    });
    expect(rejected.isError).toBe(true);
    expect(resultText(rejected)).toContain("exist only for scope 'application'");
    expect(apiClient.get).not.toHaveBeenCalled();
  });

  it("fails env-keys on a response for another target or with a wrong shape", async () => {
    const valid = {
      scope: "application",
      id: "app_1",
      field: "env",
      revision: "env:rev-1",
      variables: [{ name: "API_TOKEN", secret: true, empty: false }],
    };
    const responses = [
      { ...valid, id: "app_other" },
      { ...valid, scope: "compose" },
      { ...valid, field: "buildArgs" },
      { ...valid, variables: [{ name: "API_TOKEN", secret: "yes", empty: false }] },
      { scope: "application", id: "app_1", env: `API_TOKEN=${SECRET}` },
      `API_TOKEN=${SECRET}`,
    ];

    for (const data of responses) {
      mock.clearAllMocks();
      mocked(apiClient.get).mockResolvedValueOnce({ data });
      const result = await callTool("env-keys", { scope: "application", id: "app_1" });
      const text = resultText(result);

      expect(result.isError).toBe(true);
      expect(text).toContain("Failed to execute env-keys");
      expect(text).not.toContain(SECRET);
      expect(text).not.toContain("app_other");
    }
  });

  it("applies env changes through env-apply without returning or logging values", async () => {
    const input = {
      scope: "compose",
      id: "compose_1",
      set: { PUBLIC_URL: `https://app.example.test/${SECRET}`, PORT: "3000" },
      remove: ["OLD_FLAG"],
      generate: { SESSION_SECRET: { length: 64, format: "hex" }, API_KEY: {} },
      copy: {
        DB_PASSWORD: { fromScope: "postgres", fromId: "postgres_1", fromName: "POSTGRES_PASSWORD" },
      },
      dryRun: false,
      expectedRevision: "env:rev-1",
    };
    mocked(apiClient.post).mockResolvedValueOnce({
      data: {
        scope: "compose",
        id: "compose_1",
        field: "env",
        changed: true,
        revision: "env:rev-2",
        dryRun: false,
        env: `SESSION_SECRET=${SECRET}`,
        variables: [
          { name: "PUBLIC_URL", action: "updated", source: "set", secret: false, value: SECRET },
          { name: "PORT", action: "unchanged", source: "set", secret: false },
          { name: "OLD_FLAG", action: "missing", source: "remove", secret: false },
          {
            name: "SESSION_SECRET",
            action: "created",
            source: "generate",
            secret: true,
            generated: SECRET,
          },
          { name: "API_KEY", action: "created", source: "generate", secret: true },
          { name: "DB_PASSWORD", action: "created", source: "copy", secret: true },
        ],
      },
    });

    const { result, logs } = await callToolCapturingLogs("env-apply", input);

    expect(apiClient.post).toHaveBeenCalledTimes(1);
    expect(apiClient.post).toHaveBeenCalledWith("/env.apply", input);
    expect(apiClient.get).not.toHaveBeenCalled();
    expect(resultText(result)).not.toContain(SECRET);
    expect(resultData(result)).toEqual({
      scope: "compose",
      id: "compose_1",
      field: "env",
      changed: true,
      revision: "env:rev-2",
      dryRun: false,
      variables: [
        { name: "PUBLIC_URL", action: "updated", source: "set", secret: false },
        { name: "PORT", action: "unchanged", source: "set", secret: false },
        { name: "OLD_FLAG", action: "missing", source: "remove", secret: false },
        { name: "SESSION_SECRET", action: "created", source: "generate", secret: true },
        { name: "API_KEY", action: "created", source: "generate", secret: true },
        { name: "DB_PASSWORD", action: "created", source: "copy", secret: true },
      ],
    });
    expect(logs).toContain('"set":{"PUBLIC_URL":"[REDACTED]","PORT":"[REDACTED]"}');
    expect(logs).toContain('"remove":["OLD_FLAG"]');
    expect(logs).not.toContain(SECRET);
    expect(logs).not.toContain("3000");
  });

  it("validates env-apply input before any request or log", async () => {
    const target = { scope: "application", id: "app_1" };
    const source = { fromScope: "postgres", fromId: "postgres_1", fromName: "POSTGRES_PASSWORD" };
    const cases: Array<[Record<string, unknown>, string]> = [
      [{ ...target }, "Provide at least one variable"],
      [{ ...target, set: {}, remove: [], generate: {}, copy: {} }, "Provide at least one variable"],
      [{ ...target, dryRun: true }, "Provide at least one variable"],
      [{ ...target, set: { A: SECRET }, remove: ["A"] }, "Repeated: A."],
      [
        { ...target, set: { A: SECRET }, generate: { A: {}, B: {} }, copy: { B: source } },
        "Repeated: A, B.",
      ],
      [{ ...target, remove: ["A"], copy: { A: source } }, "Repeated: A."],
      [
        { scope: "postgres", id: "postgres_1", field: "buildArgs", set: { A: SECRET } },
        "exist only for scope 'application'",
      ],
      [
        { ...target, copy: { A: { ...source, fromField: "buildSecrets" } } },
        "exist only for fromScope 'application'",
      ],
    ];

    for (const [args, expected] of cases) {
      const { result, logs } = await callToolCapturingLogs("env-apply", args);
      const text = resultText(result);

      expect(result.isError).toBe(true);
      expect(text).toContain("Invalid input for env-apply");
      expect(text).toContain(expected);
      expect(text).not.toContain(SECRET);
      expect(logs).toBe("");
    }
    expect(apiClient.post).not.toHaveBeenCalled();
  });

  it("accepts a name repeated inside remove and field values for applications", async () => {
    mocked(apiClient.post).mockResolvedValueOnce({
      data: {
        scope: "application",
        id: "app_1",
        field: "buildArgs",
        changed: true,
        revision: "env:rev-3",
        dryRun: true,
        variables: [{ name: "A", action: "removed", source: "remove", secret: false }],
      },
    });

    const result = await callTool("env-apply", {
      scope: "application",
      id: "app_1",
      field: "buildArgs",
      remove: ["A", "A"],
      dryRun: true,
    });

    expect(result.isError).toBeUndefined();
    expect(apiClient.post).toHaveBeenCalledWith("/env.apply", {
      scope: "application",
      id: "app_1",
      field: "buildArgs",
      remove: ["A", "A"],
      dryRun: true,
    });
  });

  it("rejects env-apply values that contain a redaction placeholder", async () => {
    for (const value of FORBIDDEN_PLACEHOLDER_FIXTURES()) {
      const { result, logs } = await callToolCapturingLogs("env-apply", {
        scope: "application",
        id: "app_1",
        set: { API_TOKEN: value },
      });

      expect(result.isError).toBe(true);
      expect(resultText(result)).toContain("cannot be written back");
      expect(resultText(result)).not.toContain(value);
      expect(logs).toBe("");
    }
    expect(apiClient.post).not.toHaveBeenCalled();
  });

  it("rejects invalid variable names and generate options in the env-apply schema", async () => {
    const { envApplyTool } = await import("./envTools.js");
    const target = { scope: "application", id: "app_1" };
    const source = { fromScope: "postgres", fromId: "postgres_1", fromName: "POSTGRES_PASSWORD" };

    for (const invalid of [
      { ...target, set: { "1_BAD": "v" } },
      { ...target, set: { "WITH-DASH": "v" } },
      { ...target, set: { A: 1 } },
      { ...target, remove: ["bad name"] },
      { ...target, generate: { A: { length: 15 } } },
      { ...target, generate: { A: { length: 129 } } },
      { ...target, generate: { A: { length: 32.5 } } },
      { ...target, generate: { A: { format: "base64" } } },
      { ...target, copy: { A: { ...source, fromName: "bad-name" } } },
      { ...target, copy: { A: { fromScope: "postgres", fromName: "X" } } },
      { ...target, copy: { A: { ...source, fromScope: "server" } } },
      { scope: "server", id: "server_1", set: { A: "v" } },
      { scope: "application", id: "", set: { A: "v" } },
      { ...target, field: "previewEnv", set: { A: "v" } },
    ]) {
      expect(envApplyTool.schema.safeParse(invalid).success, JSON.stringify(invalid)).toBe(false);
    }

    expect(
      envApplyTool.schema.safeParse({
        ...target,
        set: { _A1: "v" },
        generate: { B: { length: 16, format: "alphanumeric" }, C: { length: 128 }, D: {} },
        copy: { E: { ...source, fromField: "env" } },
      }).success,
    ).toBe(true);

    const result = await callTool("env-apply", { ...target, set: { "1_BAD": SECRET } });
    expect(result.isError).toBe(true);
    expect(resultText(result)).not.toContain(SECRET);
    expect(apiClient.post).not.toHaveBeenCalled();
  });

  const PANEL_LAYOUT = [
    { type: "comment", ref: "c1", text: "App settings" },
    { type: "hidden", ref: "h1", kind: "overridden", variable: "SERVICE_URL" },
    { type: "variable", name: "SERVICE_TOKEN" },
    { type: "hidden", ref: "h2", kind: "comment", variable: "OLD_TOKEN" },
    { type: "blank" },
    { type: "variable", name: "SERVICE_URL" },
  ];
  const layoutResponse = (revision = "env:rev-1", layout: unknown = PANEL_LAYOUT) => ({
    data: {
      scope: "application",
      id: "app_1",
      field: "env",
      revision,
      variables: [
        { name: "SERVICE_TOKEN", secret: true, empty: false },
        { name: "SERVICE_URL", secret: false, empty: false },
      ],
      layout,
    },
  });
  const sectioned = [
    { type: "comment", text: "=== Web ===" },
    { type: "hidden", ref: "h1" },
    { type: "variable", name: "SERVICE_URL" },
    { type: "blank" },
    { type: "comment", text: "=== Auth ===" },
    { type: "comment", ref: "c1", text: "Signs sessions" },
    { type: "variable", name: "SERVICE_TOKEN" },
    { type: "hidden", ref: "h2" },
  ];

  it("describes layout reading and rewriting in the env tool schemas", async () => {
    const tools = await getToolList();
    const keys = tools.find(({ name }) => name === "env-keys");
    const apply = tools.find(({ name }) => name === "env-apply");
    const keysProperties = (keys?.inputSchema as Record<string, unknown>).properties as Record<
      string,
      Record<string, unknown>
    >;
    const applyProperties = (apply?.inputSchema as Record<string, unknown>).properties as Record<
      string,
      Record<string, unknown>
    >;

    expect(keysProperties.layout).toMatchObject({ type: "boolean" });
    expect(applyProperties.layout).toMatchObject({ type: "array" });
    const itemTypes = JSON.stringify(applyProperties.layout.items);
    for (const type of ["variable", "comment", "hidden", "blank"]) {
      expect(itemTypes).toContain(`"${type}"`);
    }
    for (const phrase of ["layout=true", "'overridden'", "'unreadable'"]) {
      expect(keys?.description).toContain(phrase);
    }
    for (const phrase of [
      "'layout' adds comments and arranges the variables into sections",
      "=== Database ===",
      "hidden lines can be moved but not dropped",
      "expectedRevision",
    ]) {
      expect(apply?.description).toContain(phrase);
    }
  });

  it("reads the layout through GET /env.layout and keeps only schema fields", async () => {
    mocked(apiClient.get).mockResolvedValueOnce(
      layoutResponse("env:rev-1", [
        { type: "comment", ref: "c1", text: `API_TOKEN=${SECRET}`, line: `# ${SECRET}` },
        { type: "hidden", ref: "h1", kind: "comment", value: SECRET },
        { type: "variable", name: "SERVICE_TOKEN", value: SECRET },
      ]),
    );

    const result = await callTool("env-keys", { scope: "application", id: "app_1", layout: true });

    expect(apiClient.get).toHaveBeenCalledTimes(1);
    expect(apiClient.get).toHaveBeenCalledWith("/env.layout", {
      params: { scope: "application", id: "app_1" },
    });
    expect(resultText(result)).not.toContain(SECRET);
    expect(resultData(result).layout).toEqual([
      { type: "comment", ref: "c1", text: "API_TOKEN=[REDACTED]" },
      { type: "hidden", ref: "h1", kind: "comment" },
      { type: "variable", name: "SERVICE_TOKEN" },
    ]);
  });

  it("fails env-keys with layout=true when the panel returns no layout", async () => {
    const { layout: _layout, ...withoutLayout } = layoutResponse().data;
    mocked(apiClient.get).mockResolvedValueOnce({ data: withoutLayout });

    const result = await callTool("env-keys", { scope: "application", id: "app_1", layout: true });

    expect(result.isError).toBe(true);
    expect(resultText(result)).toContain("Failed to execute env-keys");
  });

  it("checks a layout against the panel layout and then applies it", async () => {
    const input = {
      scope: "application",
      id: "app_1",
      layout: sectioned,
      expectedRevision: "env:rev-1",
    };
    mocked(apiClient.get).mockResolvedValueOnce(layoutResponse());
    mocked(apiClient.post).mockResolvedValueOnce({
      data: {
        scope: "application",
        id: "app_1",
        field: "env",
        changed: true,
        revision: "env:rev-2",
        dryRun: false,
        variables: [],
        layout: [
          { type: "comment", ref: "c1", text: "=== Web ===" },
          { type: "variable", name: "SERVICE_URL", value: SECRET },
        ],
        env: `SERVICE_TOKEN=${SECRET}`,
      },
    });

    const result = await callTool("env-apply", input);

    expect(apiClient.get).toHaveBeenCalledTimes(1);
    expect(apiClient.get).toHaveBeenCalledWith("/env.layout", {
      params: { scope: "application", id: "app_1" },
    });
    expect(apiClient.post).toHaveBeenCalledTimes(1);
    expect(apiClient.post).toHaveBeenCalledWith("/env.apply", input);
    expect(resultText(result)).not.toContain(SECRET);
    expect(resultData(result)).toEqual({
      scope: "application",
      id: "app_1",
      field: "env",
      changed: true,
      revision: "env:rev-2",
      dryRun: false,
      variables: [],
      layout: [
        { type: "comment", ref: "c1", text: "=== Web ===" },
        { type: "variable", name: "SERVICE_URL" },
      ],
    });
  });

  it("names layout problems from the panel layout without sending the change", async () => {
    mocked(apiClient.get).mockResolvedValueOnce(layoutResponse());

    const result = await callTool("env-apply", {
      scope: "application",
      id: "app_1",
      field: "env",
      layout: [
        { type: "variable", name: "SERVICE_URL" },
        { type: "hidden", ref: "h1" },
        { type: "variable", name: "UNKNOWN_NAME" },
        { type: "comment", ref: "c1" },
        { type: "comment", ref: "c1" },
        { type: "hidden", ref: "h9" },
      ],
      expectedRevision: "env:rev-1",
    });
    const text = resultText(result);

    expect(result.isError).toBe(true);
    expect(apiClient.get).toHaveBeenCalledTimes(1);
    expect(apiClient.get).toHaveBeenCalledWith("/env.layout", {
      params: { scope: "application", id: "app_1", field: "env" },
    });
    expect(apiClient.post).not.toHaveBeenCalled();
    for (const problem of [
      "Invalid input for env-apply",
      "The layout names variables that do not exist: UNKNOWN_NAME.",
      "The layout leaves out variables: SERVICE_TOKEN.",
      "The layout refers to lines that do not exist: h9.",
      "The layout places lines more than once: c1.",
      "The layout leaves out hidden lines: h2.",
      "have to stay above it: h1 (SERVICE_URL).",
    ]) {
      expect(text).toContain(problem);
    }
  });

  it("leaves a layout of another revision to the panel's conflict answer", async () => {
    mocked(apiClient.get).mockResolvedValueOnce(layoutResponse("env:rev-9", []));
    mocked(apiClient.post).mockRejectedValueOnce({
      isAxiosError: true,
      response: { status: 409, data: { message: "conflict" } },
    });

    const result = await callTool("env-apply", {
      scope: "application",
      id: "app_1",
      layout: sectioned,
      expectedRevision: "env:rev-1",
    });

    expect(apiClient.post).toHaveBeenCalledTimes(1);
    expect(resultText(result)).toContain("Call env-keys to get the current revision");
  });

  it("explains a layout the panel rejects without passing its text on", async () => {
    mocked(apiClient.get).mockResolvedValueOnce(layoutResponse());
    mocked(apiClient.post).mockRejectedValueOnce({
      isAxiosError: true,
      response: { status: 400, data: { message: `remote-body ${SECRET}` } },
    });

    const result = await callTool("env-apply", {
      scope: "application",
      id: "app_1",
      layout: sectioned,
      expectedRevision: "env:rev-1",
    });
    const text = resultText(result);

    expect(text).toContain("The panel rejected the layout with status 400");
    expect(text).toContain("Nothing was changed");
    expect(text).not.toContain("remote-body");
    expect(text).not.toContain(SECRET);
  });

  it("rejects a malformed layout before any request", async () => {
    const target = { scope: "application", id: "app_1" };
    const cases: Array<[Record<string, unknown>, string]> = [
      [
        { ...target, layout: sectioned, set: { NEW_NAME: "1" }, expectedRevision: "env:rev-1" },
        "Send layout alone",
      ],
      [{ ...target, layout: sectioned }, "A layout needs expectedRevision"],
      [
        { ...target, layout: [{ type: "comment" }], expectedRevision: "env:rev-1" },
        "needs a text, a ref or both",
      ],
      [
        {
          ...target,
          layout: [{ type: "comment", text: "two\nlines" }],
          expectedRevision: "env:rev-1",
        },
        "Invalid arguments for tool env-apply",
      ],
      [
        { ...target, layout: [{ type: "hidden", ref: "c1" }], expectedRevision: "env:rev-1" },
        "Invalid arguments for tool env-apply",
      ],
      [
        {
          ...target,
          layout: [{ type: "comment", text: "old [REDACTED]" }],
          expectedRevision: "env:rev-1",
        },
        "redacted text that cannot be written back",
      ],
    ];

    for (const [args, expected] of cases) {
      mock.clearAllMocks();
      const result = await callTool("env-apply", args);

      expect(result.isError).toBe(true);
      expect(resultText(result)).toContain(expected);
      expect(apiClient.get).not.toHaveBeenCalled();
      expect(apiClient.post).not.toHaveBeenCalled();
    }
  });

  it("sends env-apply once and answers failures with fixed messages only", async () => {
    const args = { scope: "application", id: "app_1", generate: { SESSION_SECRET: {} } };
    const cases: Array<[number, string]> = [
      [409, "Call env-keys to get the current revision"],
      [404, "a Dokploy version without the blind env API also answers this way"],
      [400, "The Dokploy API request failed with status 400"],
      [403, "The Dokploy API request failed with status 403"],
      [503, "The Dokploy API request failed with status 503"],
    ];

    for (const [status, expected] of cases) {
      mock.clearAllMocks();
      mocked(apiClient.post).mockRejectedValueOnce({
        isAxiosError: true,
        response: { status, data: { message: `remote-body ${SECRET}`, env: `A=${SECRET}` } },
      });
      const { result, logs } = await callToolCapturingLogs("env-apply", args);
      const text = resultText(result);

      expect(apiClient.post).toHaveBeenCalledTimes(1);
      expect(result.isError).toBe(true);
      expect(text).toContain(expected);
      expect(text).not.toContain("remote-body");
      expect(text).not.toContain(SECRET);
      expect(logs).not.toContain("remote-body");
      expect(logs).not.toContain(SECRET);
    }
  });

  it("fails env-apply on a response for another target", async () => {
    mocked(apiClient.post).mockResolvedValueOnce({
      data: {
        scope: "application",
        id: "app_other",
        field: "env",
        changed: true,
        revision: "env:rev-2",
        dryRun: false,
        variables: [],
      },
    });

    const result = await callTool("env-apply", {
      scope: "application",
      id: "app_1",
      remove: ["OLD_FLAG"],
    });

    expect(result.isError).toBe(true);
    expect(resultText(result)).toContain("Failed to execute env-apply");
    expect(resultText(result)).not.toContain("app_other");
  });

  it("never surfaces a remote error body, for any status", async () => {
    for (const status of [400, 401, 404, 409, 422, 500, 502]) {
      mock.clearAllMocks();
      mocked(apiClient.get).mockRejectedValueOnce({
        isAxiosError: true,
        message: `Request failed: remote-message ${SECRET}`,
        response: {
          status,
          data: { message: `remote-body env API_TOKEN=${SECRET}`, stack: `at ${SECRET}` },
        },
      });
      const { result, logs } = await callToolCapturingLogs("application-one", {
        applicationId: "app_1",
      });
      const text = resultText(result);

      expect(result.isError).toBe(true);
      expect(text).not.toContain("remote-body");
      expect(text).not.toContain("remote-message");
      expect(text).not.toContain(SECRET);
      expect(logs).not.toContain("remote-body");
      expect(logs).not.toContain(SECRET);
    }
  });

  it("says precisely which actions the super password keeps away from API keys", async () => {
    const tools = await getToolList();
    const description =
      tools.find(({ name }) => name === "superPassword-status")?.description ?? "";

    expect(description).toContain(
      "Never available through an API key, only in the panel in a browser:",
    );
    expect(description).toContain(
      "deleting a whole service, database, project, environment, server",
    );
    expect(description).toContain(
      "Allowed through the API key while access is open: every other write",
    );
    expect(description).toContain("deleting a schedule, domain, mount, port, redirect");
    expect(description).toContain("removing single env variables with env-apply");
    expect(description).not.toContain("Dangerous actions");
    expect(description).not.toMatch(/\(revealing env, deletions/);

    mocked(apiClient.get).mockResolvedValueOnce({
      data: { isSet: true, active: true, expiresAt: null, lockedUntil: null },
    });
    const data = resultData(await callTool("superPassword-status", {}));

    expect(data).not.toHaveProperty("dangerousActions");
    expect(data.browserOnlyActions).toStartWith(
      "never through an API key, only in the panel in a browser with access open: revealing secret values (env, API keys, container or volume file contents, docker inspect), terminals, deleting a whole service,",
    );
    expect(data.browserOnlyActions).toEndWith("and managing users, API keys and SSO");
    expect(data.apiKeyAllowedWrites).toStartWith(
      "through the API key while access is open: every other write, including deleting a schedule, domain, mount, port, redirect, basic-auth entry, backup configuration, volume backup, deployment record, tag, container or image,",
    );
    expect(data.apiKeyAllowedWrites).toEndWith("and removing single env variables with env-apply");
  });

  it("limits the browser-only denial to the action that was refused", async () => {
    mocked(apiClient.post).mockRejectedValueOnce({
      isAxiosError: true,
      response: {
        status: 403,
        data: {
          message:
            "This action needs a browser session with super password access open. API keys cannot perform it.",
        },
      },
    });

    const text = resultText(
      await callTool("compose-delete", { composeId: "compose_1", deleteVolumes: false }),
    );

    expect(text).toContain("can never perform it, even while access is open");
    expect(text).toContain(
      "This applies to this action only: other writes, including most deletions, work through the API key while access is open.",
    );
  });
});

function FORBIDDEN_PLACEHOLDER_FIXTURES() {
  return ["__DOKPLOY_REDACTED_SECRET__", "[REDACTED]"].flatMap((placeholder) => [
    `${placeholder}suffix`,
    `prefix${placeholder}suffix`,
    `prefix${placeholder}`,
  ]);
}

function isRejectedFixture(value: unknown): value is Record<string, unknown> {
  return (
    value !== null &&
    typeof value === "object" &&
    "isAxiosError" in value &&
    (value as { isAxiosError?: unknown }).isAxiosError === true
  );
}

function reconcileFixture() {
  return {
    composeId: "compose_1",
    operationId: "operation_1",
    sourceRevision: "a".repeat(40),
    resolvedRevision: null,
    operationStatus: "dispatch_unknown",
    deployment: null,
    queue: { state: "queue-empty" },
    repairPerformed: false,
    createdAt: "2026-07-20T00:00:00.000Z",
    updatedAt: "2026-07-20T00:00:01.000Z",
    checkedAt: "2026-07-20T00:00:02.000Z",
  };
}
