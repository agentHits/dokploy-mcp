import { describe, expect, it } from "bun:test";
import { isSensitiveName, PANEL_REDACTED, REDACTED, scrubSecrets } from "./scrubSecrets.js";

const SECRET = "fake-value-7Qx";

// Token-shaped fixtures are assembled at run time so the repository never
// contains a literal that a secret scanner would report.
const fakeToken = (prefix: string, length: number) =>
  `${prefix}${"a1B2c3D4".repeat(8)}`.slice(0, prefix.length + length);
const base64Url = (value: unknown) => Buffer.from(JSON.stringify(value)).toString("base64url");
const FAKE_JWT = `${base64Url({ alg: "HS256" })}.${base64Url({ sub: "fixture" })}.c2lnbmF0dXJl`;
const FAKE_ACCESS_KEY_ID = `AKIA${"ABCDEFGHIJKLMNOP"}`;
const PEM_BEGIN = `-----BEGIN ${"RSA PRIVATE"} KEY-----`;
const PEM_END = `-----END ${"RSA PRIVATE"} KEY-----`;
const FAKE_PEM = `${PEM_BEGIN}\nMIIEfixtureAAAA\nBBBBfixture==\n${PEM_END}`;

function expectScrubbed(input: string, expected: string) {
  const output = scrubSecrets(input);
  expect(output).toBe(expected);
  expect(output).not.toContain(SECRET);
}

function expectUntouched(input: string) {
  expect(scrubSecrets(input)).toBe(input);
}

describe("scrubSecrets: NAME=value assignments", () => {
  it("redacts bare, exported and quoted values of secret-looking names", () => {
    expectScrubbed(`DB_PASSWORD=${SECRET}`, "DB_PASSWORD=[REDACTED]");
    expectScrubbed(`export API_TOKEN=${SECRET}`, "export API_TOKEN=[REDACTED]");
    expectScrubbed(`export API_TOKEN='${SECRET} x'`, "export API_TOKEN='[REDACTED]'");
    expectScrubbed(`CLIENT_SECRET="${SECRET} x"`, 'CLIENT_SECRET="[REDACTED]"');
    expectScrubbed(`password = "${SECRET}"`, 'password = "[REDACTED]"');
  });

  it("covers every keyword of the name list", () => {
    const names = [
      "AWS_ACCESS_KEY",
      "accesskey",
      "X_API_KEY",
      "apikey",
      "BASIC_AUTH",
      "GCP_CREDENTIALS",
      "SSH_PRIVATE_KEY",
      "GITHUB_TOKEN",
      "APP_SECRET",
      "DB_PASSWORD",
      "DB_PASSWD",
      "ROOT_PWD",
      "SMTP_PASS",
      "SENTRY_DSN",
      "COOKIE_NAME",
      "SESSION_ID",
      "URL_SIGNATURE",
      "HASH_SALT",
      "SLACK_WEBHOOK",
      "LICENSE",
      "ENCRYPTION_SEED",
      "JWT_VALUE",
    ];
    for (const name of names) {
      expectScrubbed(`${name}=${SECRET}`, `${name}=[REDACTED]`);
    }
  });

  it("treats key as a whole word only", () => {
    for (const name of ["APP_KEY", "key", "signingKey", "sshKeys", "keyFile", "master.key"]) {
      expect(isSensitiveName(name)).toBe(true);
    }
    for (const name of ["monkey", "KEYCLOAK_URL", "keyboard", "hotkeys", "turnkey"]) {
      expect(isSensitiveName(name)).toBe(false);
    }
    expectScrubbed(`APP_KEY=${SECRET}`, "APP_KEY=[REDACTED]");
    expectUntouched("monkey=1 keyboard=us");
  });

  it("redacts the whole rest of a dotenv line, including spaces", () => {
    expectScrubbed(`PASSWORD=${SECRET} with spaces`, "PASSWORD=[REDACTED]");
    expectScrubbed(`  - POSTGRES_PASSWORD=${SECRET} tail`, "  - POSTGRES_PASSWORD=[REDACTED]");
    expectScrubbed(`A=1\r\nSECRET_KEY=${SECRET}\r\nB=2`, "A=1\r\nSECRET_KEY=[REDACTED]\r\nB=2");
  });

  it("stops at the closing quote when the pair itself is quoted", () => {
    expectScrubbed(`  - "POSTGRES_PASSWORD=${SECRET} tail"`, '  - "POSTGRES_PASSWORD=[REDACTED]"');
    expectScrubbed(
      `"Env":["PATH=/usr/bin","API_TOKEN=${SECRET}"]`,
      '"Env":["PATH=/usr/bin","API_TOKEN=[REDACTED]"]',
    );
    expectScrubbed(`[\\"API_TOKEN=${SECRET} x\\"]`, '[\\"API_TOKEN=[REDACTED]\\"]');
  });

  it("redacts only the value token inside a command or log line", () => {
    expectScrubbed(
      `docker run -e PASSWORD=${SECRET} -e PORT=3000 image`,
      "docker run -e PASSWORD=[REDACTED] -e PORT=3000 image",
    );
    expectScrubbed(
      `level=info msg="login ok" token=${SECRET} user=bob`,
      'level=info msg="login ok" token=[REDACTED] user=bob',
    );
    expectScrubbed(`GET /cb?token=${SECRET}&state=1 HTTP/1.1`, "GET /cb?token=[REDACTED] HTTP/1.1");
    expectScrubbed(`<a href="/reset?token=${SECRET}">`, '<a href="/reset?token=[REDACTED]">');
    expectScrubbed(`Server=db;Pwd=${SECRET};`, "Server=db;Pwd=[REDACTED]");
  });

  it("leaves non-secret names, comparisons and arrow functions alone", () => {
    expectUntouched("PORT=3000\nNODE_ENV=production\nDOMAIN=app.example.test");
    expectUntouched("if (password == null) return; const pick = (token) => token;");
    expectUntouched("PASSWORD=");
    expectUntouched("retries=3 timeout=30s");
  });
});

describe("scrubSecrets: key: value pairs", () => {
  it("redacts YAML values up to the end of the line", () => {
    expectScrubbed(`password: ${SECRET} and more`, "password: [REDACTED]");
    expectScrubbed(
      `  db_password:   ${SECRET}\n  port: 5432`,
      "  db_password:   [REDACTED]\n  port: 5432",
    );
    expectScrubbed(`password: "${SECRET} x" # note`, 'password: "[REDACTED]" # note');
    expectScrubbed(`password: 'it''s ${SECRET}'`, "password: '[REDACTED]'");
    expectScrubbed(`X-Auth-Token: ${SECRET}`, "X-Auth-Token: [REDACTED]");
    expectScrubbed(`Set-Cookie: sid=${SECRET}; Path=/`, "Set-Cookie: [REDACTED]");
  });

  it("redacts JSON values and keeps the structure", () => {
    expectScrubbed(
      `{"password":"${SECRET}","user":"bob","pin_secret":12345,"n":1}`,
      '{"password":"[REDACTED]","user":"bob","pin_secret":[REDACTED],"n":1}',
    );
    expectScrubbed(
      `{\\"apiKey\\": \\"${SECRET}\\", \\"user\\": \\"bob\\"}`,
      '{\\"apiKey\\": \\"[REDACTED]\\", \\"user\\": \\"bob\\"}',
    );
    expectScrubbed(`{'token': '${SECRET}', 'ok': True}`, "{'token': '[REDACTED]', 'ok': True}");
  });

  it("keeps booleans, null and empty values under secret-looking keys", () => {
    expectUntouched('{"secret":true,"isSecret":false,"token":null,"password":""}');
    expectUntouched("passHostHeader: true\nauth:\n  enabled: false");
  });

  it("stops at the closing quote of a quoted header", () => {
    expectScrubbed(
      `curl -H "X-Api-Key: ${SECRET} x" -H "Accept: application/json" https://app.example.test`,
      'curl -H "X-Api-Key: [REDACTED]" -H "Accept: application/json" https://app.example.test',
    );
  });

  it("does not treat image tags, ports or volume mappings as pairs", () => {
    expectUntouched("image: registry.example.test/oauth2-proxy/oauth2-proxy:v7.6.0");
    expectUntouched('      - "session_data:/var/lib/data"');
    expectUntouched("    - url: http://auth:3000");
    expectUntouched("auth-router:\n  service: auth-service\n  rule: Host(`app.example.test`)");
    expectUntouched("2026-01-01T10:00:00.000Z INFO listening on http://localhost:3000");
  });
});

describe("scrubSecrets: URLs and headers", () => {
  it("redacts the password of URL userinfo", () => {
    expectScrubbed(
      `DATABASE_URL=postgres://app:${SECRET}@db:5432/app`,
      "DATABASE_URL=postgres://app:[REDACTED]@db:5432/app",
    );
    expectScrubbed(`redis://:${SECRET}@cache:6379/0`, "redis://:[REDACTED]@cache:6379/0");
    expectScrubbed(`amqp://user:p@ss${SECRET}@queue/vhost`, "amqp://user:[REDACTED]@queue/vhost");
  });

  it("redacts a lone token used as userinfo", () => {
    expectScrubbed(
      `https://${SECRET}@git.example.test/org/repo.git`,
      "https://[REDACTED]@git.example.test/org/repo.git",
    );
    expectScrubbed(
      `https://${SECRET}:x-oauth-basic@git.example.test/org/repo.git`,
      "https://[REDACTED]:x-oauth-basic@git.example.test/org/repo.git",
    );
  });

  it("leaves URLs without userinfo alone", () => {
    expectUntouched("https://app.example.test/users/me@example.test?page=2");
    expectUntouched("http://localhost:3000/health");
  });

  it("redacts Authorization headers and bare Bearer tokens", () => {
    expectScrubbed(`Authorization: Bearer ${SECRET}`, "Authorization: Bearer [REDACTED]");
    expectScrubbed("Authorization: Basic ZmFrZTpmYWtl", "Authorization: Basic [REDACTED]");
    expectScrubbed(`authorization: Token ${SECRET}`, "authorization: [REDACTED]");
    expectScrubbed(`"Authorization": "Bearer ${SECRET}"`, '"Authorization": "Bearer [REDACTED]"');
    expectScrubbed(
      `upstream got Bearer ${SECRET} from client`,
      "upstream got Bearer [REDACTED] from client",
    );
  });
});

describe("scrubSecrets: CLI flags", () => {
  it("redacts values of secret-looking long flags", () => {
    expectScrubbed(
      `mysql --password=${SECRET} --user root`,
      "mysql --password=[REDACTED] --user root",
    );
    expectScrubbed(
      `redis-server --requirepass ${SECRET} --port 6379`,
      "redis-server --requirepass [REDACTED] --port 6379",
    );
    expectScrubbed(`tool --api-token "${SECRET} x" run`, 'tool --api-token "[REDACTED]" run');
    expectScrubbed(`tool -token=${SECRET}`, "tool -token=[REDACTED]");
    expectScrubbed(
      `command: ["redis-server", "--requirepass", "${SECRET}"]`,
      'command: ["redis-server", "--requirepass", "[REDACTED]"]',
    );
  });

  it("leaves negated flags and flags followed by another flag alone", () => {
    expectUntouched("pg_dump --no-password appdb");
    expectUntouched("docker login --password-stdin --username deploy");
    expectUntouched("server --port 8080 --verbose");
  });
});

describe("scrubSecrets: well-known token shapes", () => {
  it("redacts provider tokens wherever they appear", () => {
    const tokens = [
      fakeToken("ghp_", 36),
      fakeToken("gho_", 36),
      fakeToken("ghu_", 36),
      fakeToken("ghs_", 36),
      fakeToken("ghr_", 36),
      fakeToken("github_pat_", 40),
      fakeToken("glpat-", 20),
      fakeToken("xoxb-", 24),
      fakeToken("xoxp-", 24),
      fakeToken("sk-", 24),
      FAKE_ACCESS_KEY_ID,
      FAKE_JWT,
    ];
    for (const token of tokens) {
      expect(scrubSecrets(`fetched with ${token} ok`)).toBe("fetched with [REDACTED] ok");
      expect(scrubSecrets(`"value":"${token}"`)).toBe('"value":"[REDACTED]"');
    }
  });

  it("does not match short or embedded look-alikes", () => {
    expectUntouched("task-runner-for-background-jobs-and-more started");
    expectUntouched("sk-short");
    expectUntouched(`X${FAKE_ACCESS_KEY_ID}Q`);
  });

  it("redacts PEM private key blocks, also when newlines are escaped", () => {
    expect(scrubSecrets(`before\n${FAKE_PEM}\nafter`)).toBe("before\n[REDACTED]\nafter");
    expect(scrubSecrets(`{"k":"${FAKE_PEM.replaceAll("\n", "\\n")}"}`)).toBe('{"k":"[REDACTED]"}');
    expect(scrubSecrets(`SSH_KEY="${FAKE_PEM}"`)).toBe('SSH_KEY="[REDACTED]"');
  });

  it("redacts the body of a private key block that was cut off", () => {
    const output = scrubSecrets(`log: ${PEM_BEGIN}\nMIIEfixtureAAAA\nBBBBfix`);
    expect(output).toBe("log: [REDACTED]");
  });

  it("leaves certificates and public keys alone", () => {
    expectUntouched("-----BEGIN CERTIFICATE-----\nMIIDfixture\n-----END CERTIFICATE-----");
  });
});

describe("scrubSecrets: variable references", () => {
  it("keeps pure references", () => {
    expectUntouched(`DB_PASSWORD=\${DB_PASSWORD}`);
    expectUntouched("API_TOKEN=$API_TOKEN");
    expectUntouched(`SECRET_KEY=\${{project.SECRET_KEY}}`);
    expectUntouched(`SECRET_KEY=\${{ environment.SECRET_KEY }}`);
    expectUntouched(`DB_PASSWORD=\${DB_PASSWORD:?DB_PASSWORD is required}`);
    expectUntouched(`      - "JWT_SECRET=\${JWT_SECRET}"`);
    expectUntouched(`password: \${DB_PASSWORD}`);
    expectUntouched(`command: redis-server --requirepass \${REDIS_PASSWORD}`);
    expectUntouched(`url: postgres://\${DB_USER:-app}:\${DB_PASSWORD}@db:5432/\${DB_NAME}`);
    expectUntouched(`Authorization: Bearer \${API_TOKEN}`);
  });

  it("redacts the inline default of a reference", () => {
    expectScrubbed(
      `DB_PASSWORD=\${DB_PASSWORD:-${SECRET}}`,
      `DB_PASSWORD=\${DB_PASSWORD:-[REDACTED]}`,
    );
    expectScrubbed(
      `DB_PASSWORD=\${DB_PASSWORD-${SECRET}}`,
      `DB_PASSWORD=\${DB_PASSWORD-[REDACTED]}`,
    );
    expectScrubbed(
      `url: postgres://app:\${DB_PASSWORD:-${SECRET}}@db/app`,
      `url: postgres://app:\${DB_PASSWORD:-[REDACTED]}@db/app`,
    );
    expectUntouched(`DB_PASSWORD=\${DB_PASSWORD:-\${FALLBACK_PASSWORD}}`);
  });

  it("redacts a value that only contains a reference among other text", () => {
    expectScrubbed(`API_TOKEN=${SECRET}-\${SUFFIX}`, "API_TOKEN=[REDACTED]");
  });
});

describe("scrubSecrets: placeholders and idempotence", () => {
  it("keeps existing placeholders as they are", () => {
    expectUntouched(`API_TOKEN=${REDACTED}`);
    expectUntouched(`password: ${PANEL_REDACTED}`);
    expectUntouched(`postgres://app:${PANEL_REDACTED}@db/app`);
    expectUntouched(`{"token": ${REDACTED}]}`);
    expectUntouched(`Authorization: Bearer ${REDACTED}`);
    expectUntouched(`mysql --password=${PANEL_REDACTED}`);
  });

  it("returns its own output unchanged", () => {
    const corpus = [
      `DB_PASSWORD=${SECRET}`,
      `export API_TOKEN='${SECRET} x' # note`,
      `  - "POSTGRES_PASSWORD=${SECRET} tail"`,
      `level=info token=${SECRET} password: ${SECRET} rest`,
      `{"password":"${SECRET}","pin_secret":12345,"list":["API_KEY=${SECRET}"]}`,
      `{\\"apiKey\\": \\"${SECRET}\\"}`,
      `postgres://app:${SECRET}@db/app?password=${SECRET}`,
      `Authorization: Bearer ${SECRET}`,
      `AUTH_HEADER=Bearer ${SECRET}`,
      `curl -H "X-Api-Key: ${SECRET}" --token ${SECRET} --password="${SECRET}"`,
      `Set-Cookie: session=${SECRET}; Path=/`,
      `DB_PASSWORD=\${DB_PASSWORD:-${SECRET}}`,
      `token: ${fakeToken("ghp_", 36)} and ${FAKE_JWT}`,
      `SSH_KEY="${FAKE_PEM}"\nNEXT_TOKEN=${SECRET}`,
      `password: "unterminated ${SECRET}\nsecret: '${SECRET}`,
      `"token": ${SECRET}]} trailing`,
    ];
    for (const input of corpus) {
      const once = scrubSecrets(input);
      expect(once).not.toContain(SECRET);
      expect(scrubSecrets(once)).toBe(once);
    }
  });

  it("stays idempotent on random combinations of fragments", () => {
    const fragments = [
      "PASSWORD",
      "token",
      "api_key",
      "name",
      "Authorization",
      "Bearer",
      "=",
      ":",
      ": ",
      " ",
      "\n",
      '"',
      "'",
      '\\"',
      "\\",
      ",",
      "}",
      "]",
      "#",
      "--password",
      "--no-auth",
      SECRET,
      "true",
      `\${VAR}`,
      `\${VAR:-fallback}`,
      REDACTED,
      PANEL_REDACTED,
      "https://u:p@h/x",
      "export ",
      "- ",
      `sk-${"a".repeat(22)}`,
      PEM_BEGIN,
      PEM_END,
    ];
    let seed = 20261012;
    const next = (bound: number) => {
      seed = (seed * 1103515245 + 12345) & 0x7fffffff;
      return seed % bound;
    };

    for (let round = 0; round < 20000; round++) {
      let input = "";
      for (let i = 1 + next(12); i > 0; i--) {
        input += fragments[next(fragments.length)];
      }
      const once = scrubSecrets(input);
      expect(scrubSecrets(once)).toBe(once);
    }
  });
});

describe("scrubSecrets: large inputs", () => {
  const MEBIBYTE = 1024 * 1024;
  const TIME_LIMIT_MS = 2000;

  function timed(input: string): { output: string; elapsed: number } {
    const started = performance.now();
    const output = scrubSecrets(input);
    return { output, elapsed: performance.now() - started };
  }

  it("scrubs a 1 MB log within the time limit", () => {
    const line = `2026-01-01T00:00:00Z INFO request id=42 path=/api/items?page=2 token=${SECRET} msg="ok" user=bob\n`;
    const input = line.repeat(Math.ceil(MEBIBYTE / line.length));
    const { output, elapsed } = timed(input);

    expect(input.length).toBeGreaterThanOrEqual(MEBIBYTE);
    expect(output).not.toContain(SECRET);
    expect(output).toContain("token=[REDACTED] msg=");
    expect(elapsed).toBeLessThan(TIME_LIMIT_MS);
  });

  it("does not backtrack on long single-line inputs built to be slow", () => {
    const repeat = (unit: string) => unit.repeat(Math.ceil(MEBIBYTE / unit.length));
    const inputs = [
      "a".repeat(MEBIBYTE),
      repeat("a-"),
      repeat("a."),
      repeat("eyJaa-"),
      repeat("a://"),
      repeat("http://a.b/c "),
      `x ${repeat('pass="\\" ')}`,
      `x ${repeat("pass='a'' ")}`,
      `x ${repeat('pass=\\"a ')}`,
      `x ${repeat('"token":"\\" ')}`,
      `x ${repeat('"token: a ')}`,
      `x ${repeat('--token "a\\" ')}`,
      repeat("token: "),
      repeat("pass="),
      repeat("--password "),
      repeat(`${PEM_BEGIN}\n`),
      repeat(`word${" ".repeat(200)}`),
      `TOKEN=${"${A:-".repeat(20000)}x${"}".repeat(20000)}`,
    ];
    for (const input of inputs) {
      expect(timed(input).elapsed).toBeLessThan(TIME_LIMIT_MS);
    }
  });
});
