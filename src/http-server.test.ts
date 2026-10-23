import { afterEach, beforeEach, describe, expect, it, spyOn } from "bun:test";
import { Server } from "node:http";
import { ConfigManager } from "./utils/clientConfig.js";

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
