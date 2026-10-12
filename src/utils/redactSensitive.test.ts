import { describe, expect, it } from "bun:test";
import { BASELINE_REDACTED_FIELDS, redactSensitive } from "./redactSensitive.js";

const SECRET = "fake-value-7Qx";
const base64 = (text: string) => Buffer.from(text, "utf8").toString("base64");
const fromBase64 = (value: unknown) => Buffer.from(String(value), "base64").toString("utf8");

describe("redactSensitive: baseline fields", () => {
  it("redacts exact baseline field names", () => {
    const result = redactSensitive({ password: "hunter2", apiKey: "k-123", token: "t-1" });
    expect(result).toEqual({
      password: "[REDACTED]",
      apiKey: "[REDACTED]",
      token: "[REDACTED]",
    });
  });

  it("contains every field the baseline promises", () => {
    for (const field of ["environment", "composeFile", "dockerCompose"]) {
      expect(BASELINE_REDACTED_FIELDS).not.toContain(field);
    }
    for (const field of [
      "env",
      "buildArgs",
      "buildSecrets",
      "previewEnv",
      "previewBuildArgs",
      "previewBuildSecrets",
      "githubPrivateKey",
      "githubClientSecret",
      "githubWebhookSecret",
      "webhookSecret",
      "metricsToken",
      "authorization",
      "cookie",
      "credentials",
      "connectionString",
      "dsn",
    ]) {
      expect(BASELINE_REDACTED_FIELDS).toContain(field);
    }
  });

  it("redacts the fields added to the baseline", () => {
    const result = redactSensitive({
      previewEnv: `A_TOKEN=${SECRET}`,
      previewBuildArgs: `B_TOKEN=${SECRET}`,
      webhookSecret: SECRET,
      metricsToken: SECRET,
      authorization: `Bearer ${SECRET}`,
      cookie: `sid=${SECRET}`,
      credentials: SECRET,
      connectionString: `Server=db;Password=${SECRET}`,
      dsn: `https://${SECRET}@errors.example.test/1`,
    });
    expect(JSON.stringify(result)).not.toContain(SECRET);
    expect(result).toMatchObject({
      previewEnv: "A_TOKEN=[REDACTED]",
      previewBuildArgs: "B_TOKEN=[REDACTED]",
      webhookSecret: "[REDACTED]",
      authorization: "[REDACTED]",
      cookie: "[REDACTED]",
      connectionString: "[REDACTED]",
      dsn: "[REDACTED]",
    });
  });

  it("redacts provider-prefixed secret fields by suffix", () => {
    const result = redactSensitive({
      githubPrivateKey: "fixture-key",
      githubClientSecret: "fixture-secret",
      gitlabAccessToken: "fixture-token",
      awsSecretAccessKey: "fixture-access",
      "Set-Cookie": "sid=fixture",
    });
    expect(result).toEqual({
      githubPrivateKey: "[REDACTED]",
      githubClientSecret: "[REDACTED]",
      gitlabAccessToken: "[REDACTED]",
      awsSecretAccessKey: "[REDACTED]",
      "Set-Cookie": "[REDACTED]",
    });
  });

  it("matches case-insensitively", () => {
    const result = redactSensitive({ PASSWORD: "x", GithubPrivateKey: "y" });
    expect(result).toEqual({ PASSWORD: "[REDACTED]", GithubPrivateKey: "[REDACTED]" });
  });

  it("matches snake_case and header-style spellings of the same field", () => {
    const result = redactSensitive({
      api_key: "a",
      "X-Api-Key": "b",
      PRIVATE_KEY: "c",
      client_secret: "d",
      "build-args": "E_TOKEN=e",
    });
    expect(result).toEqual({
      api_key: "[REDACTED]",
      "X-Api-Key": "[REDACTED]",
      PRIVATE_KEY: "[REDACTED]",
      client_secret: "[REDACTED]",
      "build-args": "E_TOKEN=[REDACTED]",
    });
  });

  it("redacts provider keys and webhook URLs that carry a token", () => {
    const result = redactSensitive({
      secretKey: "a",
      applicationKey: "b",
      consumerKey: "c",
      webhookUrl: "https://hooks.example.test/services/T000/B000/fixture",
      sshKeyId: "ssh_1",
      apiKeyId: "key_1",
    });
    expect(result).toEqual({
      secretKey: "[REDACTED]",
      applicationKey: "[REDACTED]",
      consumerKey: "[REDACTED]",
      webhookUrl: "[REDACTED]",
      sshKeyId: "ssh_1",
      apiKeyId: "key_1",
    });
  });

  it("always applies the baseline: an empty or custom list cannot remove it", () => {
    expect(redactSensitive({ password: SECRET }, [])).toEqual({ password: "[REDACTED]" });
    expect(redactSensitive({ password: SECRET, env: `A=${SECRET}` }, ["note"])).toEqual({
      password: "[REDACTED]",
      env: "A=[REDACTED]",
    });
  });

  it("adds custom fields on top of the baseline via suffix match", () => {
    const result = redactSensitive({ myCustomField: "x", other: "y", token: "z" }, ["customField"]);
    expect(result).toEqual({ myCustomField: "[REDACTED]", other: "y", token: "[REDACTED]" });
  });

  it("redacts inside nested objects and arrays", () => {
    const result = redactSensitive({
      apps: [{ name: "web", env: "A_SECRET=1" }, { config: { registryPassword: "p" } }],
    });
    expect(result).toEqual({
      apps: [
        { name: "web", env: "A_SECRET=[REDACTED]" },
        { config: { registryPassword: "[REDACTED]" } },
      ],
    });
  });
});

describe("redactSensitive: value types under a sensitive key", () => {
  it("keeps booleans, numbers, null, undefined and empty strings", () => {
    const data = {
      secret: true,
      isSecret: false,
      token: 0,
      password: null,
      apiKey: undefined,
      env: "",
      credentials: 42,
    };
    expect(redactSensitive(data)).toEqual(data);
  });

  it("replaces a non-empty string, a list and a non-plain object", () => {
    const result = redactSensitive({
      password: SECRET,
      token: [SECRET, SECRET],
      secret: new Date(0),
      privateKey: [],
    });
    expect(result).toEqual({
      password: "[REDACTED]",
      token: "[REDACTED]",
      secret: "[REDACTED]",
      privateKey: [],
    });
  });

  it("keeps the keys of a map and redacts every value", () => {
    const result = redactSensitive({
      credentials: { username: "deploy", password: SECRET, nested: { a: SECRET }, port: 22 },
      env: { DB_PASSWORD: SECRET, DEBUG: true, EMPTY: "", NOTHING: null },
    });
    expect(result).toEqual({
      credentials: {
        username: "[REDACTED]",
        password: "[REDACTED]",
        nested: "[REDACTED]",
        port: "[REDACTED]",
      },
      env: { DB_PASSWORD: "[REDACTED]", DEBUG: "[REDACTED]", EMPTY: "", NOTHING: null },
    });
  });
});

describe("redactSensitive: env-shaped values keep names only", () => {
  it("turns a docker Env list into NAME=[REDACTED] items", () => {
    const result = redactSensitive({
      Config: { Env: ["PATH=/usr/bin", `DB_PASSWORD=${SECRET}`, "EMPTY=", "MULTI=a=b"] },
    });
    expect(result).toEqual({
      Config: { Env: ["PATH=[REDACTED]", "DB_PASSWORD=[REDACTED]", "EMPTY=", "MULTI=[REDACTED]"] },
    });
  });

  it("replaces a list that is not made of NAME=value strings", () => {
    expect(redactSensitive({ env: ["A=1", SECRET] })).toEqual({ env: "[REDACTED]" });
    expect(redactSensitive({ env: ["A=1", { name: "B", value: SECRET }] })).toEqual({
      env: "[REDACTED]",
    });
  });

  it("turns env text into one NAME=[REDACTED] line per variable", () => {
    const env = [
      "# database",
      `DB_PASSWORD=${SECRET}`,
      "",
      `export API_TOKEN="${SECRET} with spaces"`,
      "  PORT = 3000",
      "EMPTY=",
    ].join("\n");
    expect(redactSensitive({ env })).toEqual({
      env: "DB_PASSWORD=[REDACTED]\nAPI_TOKEN=[REDACTED]\nPORT=[REDACTED]\nEMPTY=",
    });
  });

  it("drops the continuation lines of a multi-line quoted value", () => {
    const env = `CERT="line one\nSECRET_LINE=${SECRET}\nlast line"\r\nAFTER=1`;
    expect(redactSensitive({ buildSecrets: env })).toEqual({
      buildSecrets: "CERT=[REDACTED]\nAFTER=[REDACTED]",
    });
  });

  it("replaces text that is not env-shaped", () => {
    expect(redactSensitive({ env: `just ${SECRET}` })).toEqual({ env: "[REDACTED]" });
    expect(redactSensitive({ env: `A=1\nnot an assignment ${SECRET}` })).toEqual({
      env: "[REDACTED]",
    });
    expect(redactSensitive({ buildArgs: "# only a comment" })).toEqual({ buildArgs: "[REDACTED]" });
  });

  it("never keeps a NAME= prefix under a field that is not a variable list", () => {
    const result = redactSensitive({
      apiKey: "ZmFrZXZhbHVl=",
      token: ["ZmFrZXZhbHVl=", "QUJD=x"],
      password: "NAME=value",
    });
    expect(result).toEqual({ apiKey: "[REDACTED]", token: "[REDACTED]", password: "[REDACTED]" });
  });
});

describe("redactSensitive: relation objects and compose files", () => {
  it("keeps the ids and names of an environment relation and redacts the env inside it", () => {
    const result = redactSensitive({
      environment: {
        environmentId: "e1",
        name: "production",
        env: "A=secret",
        project: { projectId: "p1", env: "B=secret" },
      },
    });
    expect(result).toEqual({
      environment: {
        environmentId: "e1",
        name: "production",
        env: "A=[REDACTED]",
        project: { projectId: "p1", env: "B=[REDACTED]" },
      },
    });
  });

  it("redacts env at any depth below non-sensitive objects and lists", () => {
    const result = redactSensitive({
      project: {
        environments: [
          {
            environmentId: "e1",
            applications: [{ applicationId: "a1", environment: { env: `X_TOKEN=${SECRET}` } }],
          },
        ],
      },
    });
    expect(result).toEqual({
      project: {
        environments: [
          {
            environmentId: "e1",
            applications: [{ applicationId: "a1", environment: { env: "X_TOKEN=[REDACTED]" } }],
          },
        ],
      },
    });
  });

  it("keeps the structure of a compose file with environment in map form", () => {
    const composeFile = [
      "services:",
      "  web:",
      "    image: registry.example.test/org/web:1.2.3",
      "    environment:",
      `      DB_PASSWORD: ${SECRET}`,
      `      API_TOKEN: \${API_TOKEN}`,
      `      SESSION_SECRET: "\${SESSION_SECRET:-${SECRET}}"`,
      `      DATABASE_URL: postgres://app:${SECRET}@db:5432/app`,
      `      REDIS_URL: redis://:\${REDIS_PASSWORD}@cache:6379`,
      "      PORT: 3000",
      '      AUTH_ENABLED: "true"',
      "    ports:",
      '      - "3000:3000"',
      "",
    ].join("\n");

    const result = redactSensitive({ composeFile }) as { composeFile: string };

    expect(result.composeFile).not.toContain(SECRET);
    expect(result.composeFile).toBe(
      [
        "services:",
        "  web:",
        "    image: registry.example.test/org/web:1.2.3",
        "    environment:",
        "      DB_PASSWORD: [REDACTED]",
        `      API_TOKEN: \${API_TOKEN}`,
        `      SESSION_SECRET: "\${SESSION_SECRET:-[REDACTED]}"`,
        "      DATABASE_URL: postgres://app:[REDACTED]@db:5432/app",
        `      REDIS_URL: redis://:\${REDIS_PASSWORD}@cache:6379`,
        "      PORT: 3000",
        '      AUTH_ENABLED: "true"',
        "    ports:",
        '      - "3000:3000"',
        "",
      ].join("\n"),
    );
  });

  it("keeps the structure of a compose file with environment in list form", () => {
    const dockerCompose = [
      "services:",
      "  worker:",
      "    image: registry.example.test/org/session-worker:latest",
      `    command: ["worker", "--api-token", "${SECRET}"]`,
      "    environment:",
      `      - DB_PASSWORD=${SECRET}`,
      `      - API_TOKEN=\${API_TOKEN}`,
      `      - "SESSION_SECRET=${SECRET} with spaces"`,
      `      - JWT_SECRET=\${{project.JWT_SECRET}}`,
      "      - PORT=3000",
      "    volumes:",
      "      - session_data:/data",
      "volumes:",
      "  session_data:",
      "",
    ].join("\n");

    const result = redactSensitive({ dockerCompose }) as { dockerCompose: string };

    expect(result.dockerCompose).not.toContain(SECRET);
    expect(result.dockerCompose).toBe(
      [
        "services:",
        "  worker:",
        "    image: registry.example.test/org/session-worker:latest",
        '    command: ["worker", "--api-token", "[REDACTED]"]',
        "    environment:",
        "      - DB_PASSWORD=[REDACTED]",
        `      - API_TOKEN=\${API_TOKEN}`,
        '      - "SESSION_SECRET=[REDACTED]"',
        `      - JWT_SECRET=\${{project.JWT_SECRET}}`,
        "      - PORT=3000",
        "    volumes:",
        "      - session_data:/data",
        "volumes:",
        "  session_data:",
        "",
      ].join("\n"),
    );
  });

  it("scrubs a parsed compose document in both environment forms", () => {
    const result = redactSensitive({
      services: {
        web: { environment: { DB_PASSWORD: SECRET, API_TOKEN: `\${API_TOKEN}`, PORT: 3000 } },
        worker: { environment: [`DB_PASSWORD=${SECRET}`, `API_TOKEN=\${API_TOKEN}`, "PORT=3000"] },
      },
    });
    expect(result).toEqual({
      services: {
        web: { environment: { DB_PASSWORD: "[REDACTED]", API_TOKEN: "[REDACTED]", PORT: 3000 } },
        worker: { environment: ["DB_PASSWORD=[REDACTED]", `API_TOKEN=\${API_TOKEN}`, "PORT=3000"] },
      },
    });
  });
});

describe("redactSensitive: free text and structure", () => {
  it("scrubs secrets out of every remaining string", () => {
    const result = redactSensitive({
      logs: `started\nDB_PASSWORD=${SECRET}\ndone`,
      customGitUrl: `https://deploy:${SECRET}@git.example.test/org/repo.git`,
      items: [`Authorization: Bearer ${SECRET}`, "plain"],
      appName: "auth-service-x1",
    });
    expect(result).toEqual({
      logs: "started\nDB_PASSWORD=[REDACTED]\ndone",
      customGitUrl: "https://deploy:[REDACTED]@git.example.test/org/repo.git",
      items: ["Authorization: Bearer [REDACTED]", "plain"],
      appName: "auth-service-x1",
    });
  });

  it("scrubs a response that is a bare string", () => {
    expect(redactSensitive(`line 1\nAPI_TOKEN=${SECRET}`)).toBe("line 1\nAPI_TOKEN=[REDACTED]");
  });

  it("redacts the argument that follows a secret-looking flag in an argv list", () => {
    const result = redactSensitive({
      Args: ["redis-server", "--requirepass", SECRET, "--port", "6379", "--no-auth", "kept"],
      Cmd: ["tool", "--token", `\${API_TOKEN}`, "--password-stdin", "--user", "deploy"],
    });
    expect(result).toEqual({
      Args: ["redis-server", "--requirepass", "[REDACTED]", "--port", "6379", "--no-auth", "kept"],
      Cmd: ["tool", "--token", `\${API_TOKEN}`, "--password-stdin", "--user", "deploy"],
    });
  });

  it("leaves non-sensitive data untouched", () => {
    const data = { appName: "web", domain: "app.example.test", port: 3000, https: true, tags: [] };
    expect(redactSensitive(data)).toEqual(data);
  });

  it("redacts every occurrence of a shared or circular object", () => {
    const shared = { password: SECRET };
    const data: Record<string, unknown> = { first: shared, second: shared };
    data.self = data;

    const result = redactSensitive(data) as Record<string, Record<string, unknown>>;
    expect(result.first).toEqual({ password: "[REDACTED]" });
    expect(result.second).toEqual({ password: "[REDACTED]" });
    expect(result.self).toBe(result);
  });

  it("drops prototype-pollution keys", () => {
    const data = JSON.parse('{"__proto__": {"polluted": true}, "name": "safe"}');
    const result = redactSensitive(data) as Record<string, unknown>;
    expect(Object.keys(result)).toEqual(["name"]);
  });
});

describe("redactSensitive: base64 file content", () => {
  it("scrubs text content next to an encoding marker and returns it re-encoded", () => {
    const result = redactSensitive({
      encoding: "base64",
      content: base64(`# config\nAPI_TOKEN=${SECRET}\nPORT=3000\n`),
    }) as Record<string, unknown>;

    expect(result.encoding).toBe("base64");
    expect(fromBase64(result.content)).toBe("# config\nAPI_TOKEN=[REDACTED]\nPORT=3000\n");
  });

  it("recognises the other marker spellings", () => {
    const content = base64(`password: ${SECRET}`);
    for (const marker of [
      { contentEncoding: "BASE64" },
      { content_encoding: " base64 " },
      { isBase64: true },
      { base64Encoded: true },
    ]) {
      const result = redactSensitive({ ...marker, content }) as Record<string, unknown>;
      expect(fromBase64(result.content)).toBe("password: [REDACTED]");
    }
  });

  it("replaces binary content and content that is not valid base64", () => {
    const binary = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x00, 0xff, 0xfe]).toString("base64");
    const withNul = base64(`text\u0000${SECRET}`);
    expect(redactSensitive({ encoding: "base64", content: binary })).toEqual({
      encoding: "base64",
      content: "[REDACTED]",
    });
    expect(redactSensitive({ encoding: "base64", content: withNul })).toEqual({
      encoding: "base64",
      content: "[REDACTED]",
    });
    expect(redactSensitive({ encoding: "base64", content: `not base64 ${SECRET}` })).toEqual({
      encoding: "base64",
      content: "[REDACTED]",
    });
  });

  it("keeps non-ASCII text, also when the size limit cut the last character", () => {
    const bytes = Buffer.from(`# комментарий\nAPI_TOKEN=${SECRET}\nимя=значение`, "utf8");
    const truncated = bytes.subarray(0, bytes.length - 1).toString("base64");

    const result = redactSensitive({ content: truncated, truncated: true }, [], {
      base64Content: true,
    }) as Record<string, unknown>;

    expect(result.truncated).toBe(true);
    expect(fromBase64(result.content)).toBe("# комментарий\nAPI_TOKEN=[REDACTED]\nимя=значени");
  });

  it("treats the root content as base64 only when the caller says so", () => {
    const content = base64(`password: ${SECRET}`);
    expect(redactSensitive({ content })).toEqual({ content });

    const result = redactSensitive({ content }, [], { base64Content: true }) as Record<
      string,
      unknown
    >;
    expect(fromBase64(result.content)).toBe("password: [REDACTED]");
  });

  it("leaves plain text content alone when nothing marks it as base64", () => {
    expect(redactSensitive({ encoding: "utf8", content: `API_TOKEN=${SECRET}` })).toEqual({
      encoding: "utf8",
      content: "API_TOKEN=[REDACTED]",
    });
  });
});

describe("redactSensitive: values that are already hidden", () => {
  const PANEL_BARE = "__DOKPLOY_REDACTED_SECRET__";
  const PANEL_TOKEN = `${PANEL_BARE}K7F3K6Q2M4XA__`;
  const PLACEHOLDERS = [PANEL_TOKEN, PANEL_BARE, "[REDACTED]"];

  it("keeps a compose file and a file mount with tokens byte for byte", () => {
    const composeFile = [
      "services:",
      "  web:",
      "    environment:",
      `      PASSWORD: ${PANEL_TOKEN}`,
      `      - API_KEY=${PANEL_TOKEN}`,
      `      DATABASE_URL: postgres://app:${PANEL_TOKEN}@db/app`,
      `    command: ["worker", "--api-token", "${PANEL_TOKEN}"]`,
    ].join("\n");
    const data = {
      composeId: "compose_1",
      composeFile,
      mounts: [{ mountId: "mount_1", type: "file", content: `token = "${PANEL_TOKEN}"\n` }],
    };

    expect(redactSensitive(data)).toEqual(data);
  });

  it("keeps a placeholder under a secret field instead of replacing it", () => {
    for (const placeholder of PLACEHOLDERS) {
      const data = {
        password: placeholder,
        apiKey: placeholder,
        credentials: { username: placeholder },
        env: `A_TOKEN=${placeholder}\nEMPTY=`,
        Config: { Env: [`DB_PASSWORD=${placeholder}`] },
        Args: ["server", "--requirepass", placeholder],
      };
      expect(redactSensitive(data), placeholder).toEqual(data);
    }
  });

  it("still redacts a secret that only contains a placeholder", () => {
    for (const placeholder of PLACEHOLDERS) {
      const result = redactSensitive({
        password: `${SECRET}${placeholder}`,
        env: `A_TOKEN=${placeholder}${SECRET}`,
        Config: { Env: [`DB_PASSWORD=${placeholder} ${SECRET}`] },
        credentials: { username: `x${placeholder}` },
      });
      expect(result, placeholder).toEqual({
        password: "[REDACTED]",
        env: "A_TOKEN=[REDACTED]",
        Config: { Env: ["DB_PASSWORD=[REDACTED]"] },
        credentials: { username: "[REDACTED]" },
      });
    }
  });

  it("returns its own output unchanged", () => {
    const data = {
      password: SECRET,
      env: `A_TOKEN=${SECRET}\nB_TOKEN=${PANEL_TOKEN}`,
      Config: { Env: [`DB_PASSWORD=${SECRET}`, `API_KEY=${PANEL_TOKEN}`] },
      composeFile: `PASSWORD: ${PANEL_TOKEN}\nOTHER_SECRET: ${SECRET}\n`,
      logs: `postgres://app:${SECRET}@db/app postgres://app:${PANEL_TOKEN}@db/app`,
    };
    const once = redactSensitive(data);

    expect(JSON.stringify(once)).not.toContain(SECRET);
    expect(JSON.stringify(once)).toContain(PANEL_TOKEN);
    expect(redactSensitive(once)).toEqual(once);
  });
});
