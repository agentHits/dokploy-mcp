import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, spyOn } from "bun:test";
import { Server } from "node:http";
import type { HttpBindings } from "@hono/node-server";
import { ConfigManager } from "./utils/clientConfig.js";

const TOKEN = "a".repeat(64);
// The routes destructure c.env; these requests never reach the transports.
const BINDINGS = { incoming: {}, outgoing: {} } as unknown as HttpBindings;
const NOT_INITIALIZE = JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list" });

function post(body: BodyInit, headers: Record<string, string> = {}): RequestInit {
  return {
    method: "POST",
    headers: { "content-type": "application/json", ...headers },
    body,
    duplex: "half",
  } as RequestInit;
}

function streamOf(size: number): ReadableStream<Uint8Array> {
  const chunk = new Uint8Array(64 * 1024).fill(0x20);
  let sent = 0;
  return new ReadableStream({
    pull(controller) {
      if (sent >= size) {
        controller.close();
        return;
      }
      controller.enqueue(chunk);
      sent += chunk.length;
    },
  });
}

// Importing http-server loads the API client, which reads DOKPLOY_URL and
// DOKPLOY_API_KEY once at import time.
describe("http-server app", () => {
  const savedEnv = { url: process.env.DOKPLOY_URL, key: process.env.DOKPLOY_API_KEY };
  let createApp: typeof import("./http-server.js").createApp;
  let readAuthToken: typeof import("./http-server.js").readAuthToken;
  let MAX_BODY_BYTES: number;

  beforeAll(async () => {
    process.env.DOKPLOY_URL = "https://dokploy.example";
    process.env.DOKPLOY_API_KEY = "test-key";
    ConfigManager.resetInstance();
    ({ createApp, readAuthToken, MAX_BODY_BYTES } = await import("./http-server.js"));
  });

  afterAll(() => {
    for (const [key, value] of [
      ["DOKPLOY_URL", savedEnv.url],
      ["DOKPLOY_API_KEY", savedEnv.key],
    ] as const) {
      if (value === undefined) {
        delete process.env[key];
      } else {
        process.env[key] = value;
      }
    }
    ConfigManager.resetInstance();
  });

  describe("readAuthToken", () => {
    it("returns undefined when MCP_AUTH_TOKEN is unset or blank", () => {
      expect(readAuthToken({})).toBeUndefined();
      expect(readAuthToken({ MCP_AUTH_TOKEN: "   " })).toBeUndefined();
    });

    it("returns the trimmed token", () => {
      expect(readAuthToken({ MCP_AUTH_TOKEN: ` ${TOKEN}\n` })).toBe(TOKEN);
    });

    it("rejects tokens shorter than 32 characters", () => {
      expect(() => readAuthToken({ MCP_AUTH_TOKEN: "a".repeat(31) })).toThrow("MCP_AUTH_TOKEN");
    });

    // bearerAuth answers 400 to any other character, so such a token could never match.
    it("rejects characters a bearer token cannot carry", () => {
      expect(() => readAuthToken({ MCP_AUTH_TOKEN: `${"a".repeat(40)} !` })).toThrow(
        "MCP_AUTH_TOKEN",
      );
    });
  });

  describe("createApp authentication", () => {
    it("lets requests through when no token is configured", async () => {
      const res = await createApp(undefined).request("/mcp", post(NOT_INITIALIZE), BINDINGS);
      expect(res.status).toBe(400);
      expect(await res.json()).toMatchObject({ error: { code: -32000 } });
    });

    it("keeps /health open", async () => {
      const res = await createApp(TOKEN).request("/health", {}, BINDINGS);
      expect(res.status).toBe(200);
    });

    it.each<[string, string]>([
      ["POST", "/mcp"],
      ["GET", "/mcp"],
      ["DELETE", "/mcp"],
      ["GET", "/sse"],
      ["POST", "/messages?sessionId=x"],
    ])("rejects %s %s without a token", async (method, path) => {
      const init: RequestInit = method === "POST" ? post(NOT_INITIALIZE) : { method };
      const res = await createApp(TOKEN).request(path, init, BINDINGS);
      expect(res.status).toBe(401);
      expect(res.headers.get("www-authenticate")).toStartWith("Bearer");
      expect(await res.json()).toEqual({
        jsonrpc: "2.0",
        error: { code: -32001, message: "Unauthorized" },
        id: null,
      });
    });

    it("rejects a wrong token", async () => {
      const res = await createApp(TOKEN).request(
        "/mcp",
        post(NOT_INITIALIZE, { authorization: `Bearer ${"b".repeat(64)}` }),
        BINDINGS,
      );
      expect(res.status).toBe(401);
    });

    it("rejects another Authorization scheme", async () => {
      const res = await createApp(TOKEN).request(
        "/mcp",
        post(NOT_INITIALIZE, { authorization: `Basic ${TOKEN}` }),
        BINDINGS,
      );
      expect(res.status).toBe(400);
      expect(await res.json()).toMatchObject({ error: { code: -32001 } });
    });

    it("passes the right token to the route", async () => {
      const res = await createApp(TOKEN).request(
        "/mcp",
        post(NOT_INITIALIZE, { authorization: `Bearer ${TOKEN}` }),
        BINDINGS,
      );
      expect(res.status).toBe(400);
      expect(await res.json()).toMatchObject({ error: { code: -32000 } });
    });

    it("checks the token before it reads the body", async () => {
      const res = await createApp(TOKEN).request(
        "/mcp",
        post(streamOf(MAX_BODY_BYTES * 2)),
        BINDINGS,
      );
      expect(res.status).toBe(401);
    });
  });

  describe("createApp body limit", () => {
    const auth = { authorization: `Bearer ${TOKEN}` };

    it("rejects a Content-Length above the limit before reading the body", async () => {
      const res = await createApp(TOKEN).request(
        "/mcp",
        post(NOT_INITIALIZE, { ...auth, "content-length": String(MAX_BODY_BYTES + 1) }),
        BINDINGS,
      );
      expect(res.status).toBe(413);
      expect(await res.json()).toMatchObject({
        error: { code: -32000, message: "Payload Too Large" },
      });
    });

    it.each(["/mcp", "/messages?sessionId=x"])(
      "rejects a body without Content-Length once it passes the limit on %s",
      async (path) => {
        const res = await createApp(TOKEN).request(
          path,
          post(streamOf(MAX_BODY_BYTES + 1), auth),
          BINDINGS,
        );
        expect(res.status).toBe(413);
      },
    );

    it("passes a body under the limit to the route", async () => {
      const body = NOT_INITIALIZE.padEnd(MAX_BODY_BYTES - 1, " ");
      const res = await createApp(TOKEN).request("/mcp", post(body, auth), BINDINGS);
      expect(res.status).toBe(400);
      expect(await res.json()).toMatchObject({ error: { code: -32000 } });
    });
  });
});

describe("http-server", () => {
  const ENV_KEYS = ["DOKPLOY_URL", "DOKPLOY_API_KEY"] as const;
  const original = new Map<string, string | undefined>();
  const originalArgv1 = process.argv[1];

  beforeEach(() => {
    for (const key of ENV_KEYS) {
      original.set(key, process.env[key]);
    }
    process.env.DOKPLOY_URL = "https://dokploy.example";
    process.env.DOKPLOY_API_KEY = "test-key";
    ConfigManager.resetInstance();
  });

  afterEach(() => {
    for (const key of ENV_KEYS) {
      const value = original.get(key);
      if (value === undefined) {
        delete process.env[key];
      } else {
        process.env[key] = value;
      }
    }
    if (originalArgv1 === undefined) {
      process.argv.splice(1, 1);
    } else {
      process.argv[1] = originalArgv1;
    }
    ConfigManager.resetInstance();
  });

  // `bun build` puts this module into build/index.js, the file in
  // process.argv[1]. A self-start check on argv[1] then fired on import next
  // to the main() call from src/index.ts, and the second listen on port 3000
  // crashed the process.
  it("listens only when main() is called, even if argv[1] names the module", async () => {
    process.argv[1] = new URL("./http-server.ts", import.meta.url).pathname;
    const listen = spyOn(Server.prototype, "listen").mockImplementation(function (this: Server) {
      return this;
    });

    try {
      const { main } = await import("./http-server.js");
      expect(listen).not.toHaveBeenCalled();

      await main();
      expect(listen).toHaveBeenCalledTimes(1);
      expect(listen.mock.calls[0]?.[0]).toBe(3000);
    } finally {
      listen.mockRestore();
    }
  });
});
