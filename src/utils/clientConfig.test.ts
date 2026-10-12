import { afterEach, beforeEach, describe, expect, it, spyOn } from "bun:test";
import { ConfigManager, getClientConfig, parseCustomHeaders } from "./clientConfig.js";
import { redactSensitive } from "./redactSensitive.js";

describe("parseCustomHeaders", () => {
  it("returns no custom headers when unset", () => {
    expect(parseCustomHeaders(undefined)).toEqual({});
  });

  it("accepts Cloudflare Access-style headers", () => {
    const headers = parseCustomHeaders(
      JSON.stringify({
        "CF-Access-Client-Id": "client-id-placeholder",
        "CF-Access-Client-Secret": "client-secret-placeholder",
      }),
    );

    expect(headers).toEqual({
      "CF-Access-Client-Id": "client-id-placeholder",
      "CF-Access-Client-Secret": "client-secret-placeholder",
    });
  });

  it("rejects malformed JSON", () => {
    expect(() => parseCustomHeaders("not-json")).toThrow(/must be valid JSON/);
  });

  it("rejects an empty string when configured", () => {
    expect(() => parseCustomHeaders("")).toThrow(/must be valid JSON/);
  });

  it("rejects arrays", () => {
    expect(() => parseCustomHeaders("[]")).toThrow(/must be a JSON object/);
  });

  it("rejects non-object JSON", () => {
    expect(() => parseCustomHeaders('"header-value"')).toThrow(/must be a JSON object/);
  });

  it("rejects non-string values", () => {
    expect(() => parseCustomHeaders(JSON.stringify({ "X-Custom-Header": 123 }))).toThrow(
      /only string header values/,
    );
  });

  it("rejects empty header names", () => {
    expect(() => parseCustomHeaders(JSON.stringify({ "": "value" }))).toThrow(/empty header name/);
  });

  it("rejects reserved header names case-insensitively", () => {
    expect(() => parseCustomHeaders(JSON.stringify({ "X-API-Key": "override" }))).toThrow(
      /cannot override reserved header/,
    );
    expect(() => parseCustomHeaders(JSON.stringify({ "Content-Type": "text/plain" }))).toThrow(
      /cannot override reserved header/,
    );
    expect(() => parseCustomHeaders(JSON.stringify({ ACCEPT: "text/plain" }))).toThrow(
      /cannot override reserved header/,
    );
  });
});

describe("getClientConfig", () => {
  const ENV_KEYS = [
    "DOKPLOY_URL",
    "DOKPLOY_API_KEY",
    "DOKPLOY_REDACT_ENV",
    "DOKPLOY_REDACT_FIELDS",
  ] as const;
  const original = new Map<string, string | undefined>();

  beforeEach(() => {
    for (const key of ENV_KEYS) {
      original.set(key, process.env[key]);
    }
    process.env.DOKPLOY_URL = "https://dokploy.example";
    process.env.DOKPLOY_API_KEY = "test-key";
    delete process.env.DOKPLOY_REDACT_ENV;
    delete process.env.DOKPLOY_REDACT_FIELDS;
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
    ConfigManager.resetInstance();
  });

  function loadConfigCapturingLogs() {
    const consoleError = spyOn(console, "error").mockImplementation(() => {});
    try {
      const config = getClientConfig();
      return { config, logs: consoleError.mock.calls.map((call) => String(call[0])) };
    } finally {
      consoleError.mockRestore();
    }
  }

  it("adds no custom fields and logs nothing by default", () => {
    const { config, logs } = loadConfigCapturingLogs();

    expect(config.extraRedactFields).toEqual([]);
    expect(config).not.toHaveProperty("redactEnv");
    expect(logs).toEqual([]);
  });

  it("treats DOKPLOY_REDACT_FIELDS as additions to the baseline", () => {
    process.env.DOKPLOY_REDACT_FIELDS = " note , internalRef ,, ";
    const { config } = loadConfigCapturingLogs();

    expect(config.extraRedactFields).toEqual(["note", "internalRef"]);
    expect(
      redactSensitive(
        { env: "A=1", password: "p", note: "n", name: "web" },
        config.extraRedactFields,
      ),
    ).toEqual({ env: "A=[REDACTED]", password: "[REDACTED]", note: "[REDACTED]", name: "web" });
  });

  it("ignores DOKPLOY_REDACT_ENV=false and warns once without logging any value", () => {
    for (const value of ["false", "0", "no", "off", ""]) {
      ConfigManager.resetInstance();
      process.env.DOKPLOY_REDACT_ENV = value;
      const { config, logs } = loadConfigCapturingLogs();
      getClientConfig();

      expect(config).not.toHaveProperty("redactEnv");
      expect(logs).toHaveLength(1);
      const entry = JSON.parse(logs[0] ?? "{}");
      expect(entry.level).toBe("warn");
      expect(entry.message).toBe(
        "DOKPLOY_REDACT_ENV=false is ignored: response redaction cannot be disabled in this build",
      );
      expect(entry.context).toEqual({ service: "Config" });
      expect(logs[0]).not.toContain("test-key");
    }
  });

  it("does not warn when DOKPLOY_REDACT_ENV asks for redaction", () => {
    process.env.DOKPLOY_REDACT_ENV = "true";
    expect(loadConfigCapturingLogs().logs).toEqual([]);
  });
});
