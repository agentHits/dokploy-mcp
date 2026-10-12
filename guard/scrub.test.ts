import { describe, expect, it } from "bun:test";
import { scrubOutputText, scrubToolResponse } from "./scrub.js";

const SECRET = "fake-value-7Qx";
const PLAIN = "plain-setting-42";
const PANEL_BARE = "__DOKPLOY_REDACTED_SECRET__";
const PANEL_TOKEN = `${PANEL_BARE}K7F3K6Q2M4XA__`;

function expectScrubbed(input: string, expected: string) {
  const output = scrubOutputText(input);
  expect(output).toBe(expected);
  expect(scrubOutputText(output)).toBe(output);
}

function sshResult(stdout: string, indent: number, command = "docker ps") {
  const body = { server: "app-1", command, stdout, stderr: "", code: 0, success: true };
  return JSON.stringify(body, null, indent);
}

describe("scrubOutputText: environment dumps", () => {
  it("hides every value once three assignment lines are present, whatever the name", () => {
    expectScrubbed(
      `PATH=/usr/bin:/bin\nHOSTNAME=app-1\nGREETING=${PLAIN} with spaces\nDB_PASSWORD=${SECRET}`,
      "PATH=[REDACTED]\nHOSTNAME=[REDACTED]\nGREETING=[REDACTED]\nDB_PASSWORD=[REDACTED]",
    );
  });

  it("covers the export and declare forms and keeps the quotes", () => {
    expectScrubbed(
      `export A="${PLAIN}"\nexport B='${PLAIN}'\ndeclare -x C="${PLAIN}"\ndeclare -- D=${PLAIN}\n  E=${PLAIN}`,
      `export A="[REDACTED]"\nexport B='[REDACTED]'\ndeclare -x C="[REDACTED]"\ndeclare -- D=[REDACTED]\n  E=[REDACTED]`,
    );
  });

  it("keeps empty values, placeholders and the lines around the dump", () => {
    expectScrubbed(
      `$ printenv\nEMPTY=\nQUOTED=""\nA=[REDACTED]\nB=${PANEL_BARE}\nC=${PANEL_TOKEN}\nD="${PANEL_TOKEN}"\nE=${PLAIN}\n-- done`,
      `$ printenv\nEMPTY=\nQUOTED=""\nA=[REDACTED]\nB=${PANEL_BARE}\nC=${PANEL_TOKEN}\nD="${PANEL_TOKEN}"\nE=[REDACTED]\n-- done`,
    );
  });

  it("keeps Windows line endings", () => {
    expectScrubbed(
      `A=${PLAIN}\r\nB=${PLAIN}\r\nC=${PLAIN}\r\n`,
      "A=[REDACTED]\r\nB=[REDACTED]\r\nC=[REDACTED]\r\n",
    );
  });

  it("hides a value that only starts with a placeholder", () => {
    expectScrubbed(
      `A=${PANEL_TOKEN}${SECRET}\nB=[REDACTED] ${SECRET}\nC=x`,
      "A=[REDACTED]\nB=[REDACTED]\nC=[REDACTED]",
    );
  });

  it("leaves fewer than three assignment lines to the name rules", () => {
    expectScrubbed(
      `NODE_ENV=production\nAPI_TOKEN=${SECRET}`,
      "NODE_ENV=production\nAPI_TOKEN=[REDACTED]",
    );
    expectScrubbed(
      "uid=0(root) gid=0(root) groups=0(root)",
      "uid=0(root) gid=0(root) groups=0(root)",
    );
  });

  it("does not take logfmt records for an environment dump", () => {
    const logs = [
      'time="2026-01-01T00:00:00Z" level=info msg="server started" port=3000',
      'time="2026-01-01T00:00:01Z" level=info msg="request" path=/health status=200',
      `time="2026-01-01T00:00:02Z" level=error msg="auth failed" token=${SECRET}`,
      "ts=2026-01-01T00:00:03Z caller=main.go:42 msg=ready",
    ];
    const output = scrubOutputText(logs.join("\n")).split("\n");

    expect(output[0]).toBe(logs[0] ?? "");
    expect(output[1]).toBe(logs[1] ?? "");
    expect(output[2]).toBe(
      'time="2026-01-01T00:00:02Z" level=error msg="auth failed" token=[REDACTED]',
    );
    expect(output[3]).toBe(logs[3] ?? "");
  });

  it("still hides upper-case variables whose value looks like more assignments", () => {
    const output = scrubOutputText(
      `JAVA_OPTS=-Xmx1g -Dkey=${PLAIN}\nPGOPTIONS=-c search_path=app\nA=1`,
    );
    expect(output).toBe("JAVA_OPTS=[REDACTED]\nPGOPTIONS=[REDACTED]\nA=[REDACTED]");
  });
});

describe("scrubOutputText: docker inspect output", () => {
  const container = (env: unknown) => [
    {
      Id: "0123456789ab",
      Config: { Image: "app:1.2.3", Env: env, Cmd: ["node", "server.js"] },
      State: { Status: "running", Pid: 4242 },
    },
  ];

  it("hides the values of a pretty-printed Env list and nothing else", () => {
    const input = JSON.stringify(
      container(["PATH=/usr/bin", `GREETING=${PLAIN}`, "EMPTY="]),
      null,
      4,
    );
    const expected = JSON.stringify(
      container(["PATH=[REDACTED]", "GREETING=[REDACTED]", "EMPTY="]),
      null,
      4,
    );
    expectScrubbed(input, expected);
  });

  it("handles compact JSON, several containers and quotes inside a value", () => {
    const tricky = 'MOTD=say "hi", then [bye]';
    const input = JSON.stringify([
      ...container([tricky, `A=${PLAIN}`]),
      ...container([`B=${PLAIN}`]),
    ]);
    const expected = JSON.stringify([
      ...container(["MOTD=[REDACTED]", "A=[REDACTED]"]),
      ...container(["B=[REDACTED]"]),
    ]);
    expectScrubbed(input, expected);
  });

  it("keeps placeholders and hides items that are not assignments", () => {
    const input = JSON.stringify(
      container([`A=${PANEL_TOKEN}`, "B=[REDACTED]", `C=${PANEL_BARE}`, PLAIN, PANEL_TOKEN]),
    );
    const expected = JSON.stringify(
      container([`A=${PANEL_TOKEN}`, "B=[REDACTED]", `C=${PANEL_BARE}`, "[REDACTED]", PANEL_TOKEN]),
    );
    expectScrubbed(input, expected);
  });

  it("hides an Env given as one string", () => {
    expectScrubbed(
      JSON.stringify({ Env: `A=${PLAIN}\nB=${PLAIN}` }),
      JSON.stringify({ Env: "A=[REDACTED]\nB=[REDACTED]" }),
    );
    expectScrubbed('{"Env": null, "Name": "web"}', '{"Env": null, "Name": "web"}');
  });

  it("covers output that was cut off in the middle of the list", () => {
    const whole = JSON.stringify(container([`A=${PLAIN}`, `B=${PLAIN}`, `C=${PLAIN}`]), null, 4);
    const cut = whole.slice(0, whole.indexOf("C="));
    const output = scrubOutputText(cut);

    expect(output).not.toContain(PLAIN);
    expect(output).toContain('"A=[REDACTED]"');
    expect(scrubOutputText(output)).toBe(output);
  });

  it("covers a swarm service spec", () => {
    const spec = {
      Spec: { TaskTemplate: { ContainerSpec: { Image: "app:1", Env: [`A=${PLAIN}`] } } },
    };
    const output = scrubOutputText(JSON.stringify([spec], null, 4));

    expect(output).not.toContain(PLAIN);
    expect(output).toContain('"Image": "app:1"');
  });
});

describe("scrubOutputText: reuse of the server scrubber", () => {
  it("applies the name and format rules to ordinary output", () => {
    expectScrubbed(
      `curl -H "Authorization: Bearer ${SECRET}" https://app.example.test`,
      'curl -H "Authorization: Bearer [REDACTED]" https://app.example.test',
    );
    expectScrubbed(
      `DATABASE_URL: postgres://app:${SECRET}@db:5432/app`,
      "DATABASE_URL: postgres://app:[REDACTED]@db:5432/app",
    );
    expectScrubbed(`  password: ${SECRET}`, "  password: [REDACTED]");
  });

  it("leaves ordinary output alone", () => {
    const outputs = [
      "CONTAINER ID   IMAGE     STATUS\n0123456789ab   app:1     Up 3 days",
      "Filesystem      Size  Used Avail Use% Mounted on\n/dev/sda1        80G   40G   40G  50% /",
      " 10:00:00 up 3 days,  2:00,  1 user,  load average: 0.10, 0.20, 0.30",
      '{"status":"ok","uptime":12345}',
      "",
    ];
    for (const output of outputs) expectScrubbed(output, output);
  });

  it("keeps restorable tokens byte for byte", () => {
    const text = [
      `PASSWORD: ${PANEL_TOKEN}`,
      `- API_KEY=${PANEL_TOKEN}`,
      `postgres://app:${PANEL_TOKEN}@db/app`,
    ].join("\n");
    expectScrubbed(text, text);
  });
});

describe("scrubToolResponse", () => {
  const dump = `PATH=/usr/bin\nNODE_ENV=production\nDB_PASSWORD=${SECRET}\nGREETING=${PLAIN}`;
  const hidden =
    "PATH=[REDACTED]\nNODE_ENV=[REDACTED]\nDB_PASSWORD=[REDACTED]\nGREETING=[REDACTED]";

  it("scrubs the command output inside the JSON text of a content block", () => {
    for (const indent of [0, 2]) {
      const response = [{ type: "text", text: sshResult(dump, indent, "printenv") }];
      const { value, changed } = scrubToolResponse(response);

      expect(changed).toBe(true);
      expect(value).toEqual([{ type: "text", text: sshResult(hidden, indent, "printenv") }]);
    }
  });

  it("keeps the shape the client passed", () => {
    const text = sshResult(dump, 2);
    const scrubbed = sshResult(hidden, 2);

    expect(scrubToolResponse(text).value).toBe(scrubbed);
    expect(scrubToolResponse({ content: [{ type: "text", text }], isError: false }).value).toEqual({
      content: [{ type: "text", text: scrubbed }],
      isError: false,
    });
    expect(
      scrubToolResponse([
        { type: "text", text: "ok" },
        { type: "text", text },
      ]).value,
    ).toEqual([
      { type: "text", text: "ok" },
      { type: "text", text: scrubbed },
    ]);
  });

  it("scrubs docker inspect output that sits in stdout", () => {
    const inspect = JSON.stringify([{ Config: { Env: [`A=${PLAIN}`], Image: "app:1" } }], null, 4);
    const { value } = scrubToolResponse([{ type: "text", text: sshResult(inspect, 2) }]);
    const stdout = JSON.parse((value as Array<{ text: string }>)[0]?.text ?? "{}").stdout;

    expect(stdout).toBe(
      JSON.stringify([{ Config: { Env: ["A=[REDACTED]"], Image: "app:1" } }], null, 4),
    );
  });

  it("hides secret fields and Env lists of a JSON result itself", () => {
    const text = JSON.stringify({ name: "web", password: SECRET, Env: [`A=${PLAIN}`], port: 3000 });
    const { value } = scrubToolResponse([{ type: "text", text }]);

    expect(value).toEqual([
      {
        type: "text",
        text: JSON.stringify({
          name: "web",
          password: "[REDACTED]",
          Env: ["A=[REDACTED]"],
          port: 3000,
        }),
      },
    ]);
  });

  it("scrubs plain text results and JSON that would not survive a rewrite", () => {
    const plain = `Tail of /var/log/app.log\nlogin ok token=${SECRET}`;
    expect(scrubToolResponse([{ type: "text", text: plain }]).value).toEqual([
      { type: "text", text: "Tail of /var/log/app.log\nlogin ok token=[REDACTED]" },
    ]);

    const lossy = `{"id": 12345678901234567890, "apiKey": "${SECRET}"}`;
    expect(scrubToolResponse(lossy).value).toBe(
      '{"id": 12345678901234567890, "apiKey": "[REDACTED]"}',
    );
  });

  it("reports no change and returns equal data when nothing is secret", () => {
    const responses: unknown[] = [
      [{ type: "text", text: sshResult("CONTAINER ID   IMAGE\n0123456789ab   app:1", 2) }],
      [{ type: "text", text: sshResult("", 0) }],
      "plain text",
      { content: [{ type: "text", text: "ok" }] },
      [{ type: "image", data: "aGVsbG8=", mimeType: "image/png" }],
      null,
      42,
      [],
    ];
    for (const response of responses) {
      const { value, changed } = scrubToolResponse(response);
      expect(changed).toBe(false);
      expect(value).toEqual(response);
    }
  });

  it("does not touch binary payloads", () => {
    const data = Buffer.from(`API_TOKEN=${SECRET}`).toString("base64");
    const response = [
      { type: "image", data, mimeType: "image/png" },
      {
        type: "resource",
        resource: { uri: "file:///a", mimeType: "text/plain", text: `API_TOKEN=${SECRET}` },
      },
    ];
    const { value, changed } = scrubToolResponse(response);

    expect(changed).toBe(true);
    expect(value).toEqual([
      { type: "image", data, mimeType: "image/png" },
      {
        type: "resource",
        resource: { uri: "file:///a", mimeType: "text/plain", text: "API_TOKEN=[REDACTED]" },
      },
    ]);
  });

  it("keeps restorable tokens and is idempotent", () => {
    const stdout = `PASSWORD: ${PANEL_TOKEN}\n- API_KEY=${PANEL_TOKEN}\npostgres://app:${PANEL_TOKEN}@db/app`;
    const untouched = scrubToolResponse([{ type: "text", text: sshResult(stdout, 2) }]);
    expect(untouched.changed).toBe(false);

    const mixed = `A=${PANEL_TOKEN}\nB=${SECRET}\nC=${PANEL_BARE}\nD=[REDACTED]`;
    const once = scrubToolResponse([{ type: "text", text: sshResult(mixed, 2) }]);
    const twice = scrubToolResponse(once.value);

    expect(JSON.stringify(once.value)).not.toContain(SECRET);
    expect(JSON.stringify(once.value)).toContain(PANEL_TOKEN);
    expect(twice.changed).toBe(false);
    expect(twice.value).toEqual(once.value);
  });
});

describe("scrub idempotence", () => {
  it("returns its own output unchanged on random combinations of fragments", () => {
    const fragments = [
      "PASSWORD",
      "NAME",
      "token",
      "level",
      "Env",
      '"Env"',
      '"Env": [',
      '"Env":"',
      "export ",
      "declare -x ",
      "=",
      ":",
      ": ",
      " ",
      "\n",
      "\r\n",
      '"',
      "'",
      '\\"',
      "\\",
      "\\n",
      ",",
      "[",
      "]",
      "{",
      "}",
      SECRET,
      PLAIN,
      "[REDACTED]",
      PANEL_BARE,
      PANEL_TOKEN,
      "https://u:p@h/x",
      "Bearer ",
      "A=1\nB=2\nC=3\n",
    ];
    let seed = 20261012;
    const next = (bound: number) => {
      seed = (seed * 1103515245 + 12345) & 0x7fffffff;
      return seed % bound;
    };

    for (let round = 0; round < 20000; round++) {
      let input = "";
      for (let i = 1 + next(14); i > 0; i--) {
        input += fragments[next(fragments.length)];
      }
      const once = scrubOutputText(input);
      expect(scrubOutputText(once)).toBe(once);

      const wrapped = scrubToolResponse([{ type: "text", text: sshResult(input, 2) }]);
      const again = scrubToolResponse(wrapped.value);
      expect(again.value).toEqual(wrapped.value);
      expect(again.changed).toBe(false);
    }
  });

  it("scrubs a 1 MB environment dump and a 1 MB log within the time limit", () => {
    const dump = `SETTING_NAME=${PLAIN}\n`.repeat(40_000);
    const log = `time="2026-01-01T00:00:00Z" level=info msg="request" token=${SECRET}\n`.repeat(
      15_000,
    );
    const inspect = JSON.stringify([{ Config: { Env: Array(30_000).fill(`A=${PLAIN}`) } }]);

    for (const input of [dump, log, inspect]) {
      const started = performance.now();
      const output = scrubOutputText(input);
      expect(performance.now() - started).toBeLessThan(2000);
      expect(output).not.toContain(PLAIN);
      expect(output).not.toContain(SECRET);
    }
  });
});
