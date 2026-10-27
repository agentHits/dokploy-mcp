import { randomUUID } from "node:crypto";
import type { HttpBindings } from "@hono/node-server";
import { serve } from "@hono/node-server";
import { SSEServerTransport } from "@modelcontextprotocol/sdk/server/sse.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { isInitializeRequest } from "@modelcontextprotocol/sdk/types.js";
import { Hono } from "hono";
import { bearerAuth } from "hono/bearer-auth";
import { bodyLimit } from "hono/body-limit";
import { createServer } from "./server.js";
import { createLogger } from "./utils/logger.js";

const PORT = 3000;
// The MCP SDK transports cap the bodies they parse themselves at 4 MB.
export const MAX_BODY_BYTES = 4 * 1024 * 1024;
const MIN_AUTH_TOKEN_LENGTH = 32;
// The token characters hono's bearerAuth accepts in the Authorization header.
const AUTH_TOKEN_PATTERN = /^[A-Za-z0-9._~+/-]+=*$/;
const logger = createLogger("MCP-HTTP-Server");

const jsonrpcError = (code: number, message: string) => ({
  jsonrpc: "2.0" as const,
  error: { code, message },
  id: null,
});

export function readAuthToken(env: NodeJS.ProcessEnv = process.env): string | undefined {
  const token = env.MCP_AUTH_TOKEN?.trim();
  if (!token) {
    return undefined;
  }
  if (token.length < MIN_AUTH_TOKEN_LENGTH || !AUTH_TOKEN_PATTERN.test(token)) {
    throw new Error(
      `MCP_AUTH_TOKEN must be at least ${MIN_AUTH_TOKEN_LENGTH} characters of A-Z, a-z, 0-9 and ._~+/- (for example, the output of \`openssl rand -hex 32\`)`,
    );
  }
  return token;
}

// When MCP transport takes over the raw Node response, we must prevent
// Hono/@hono/node-server from trying to write its own response headers.
// We return a Promise that NEVER resolves — the underlying Node response
// is already being handled by the MCP transport, so Hono must not touch it.
function neverResolve(): Promise<never> {
  return new Promise(() => {});
}

export function createApp(authToken: string | undefined) {
  const app = new Hono<{ Bindings: HttpBindings }>();

  const transports = {
    streamable: {} as Record<string, StreamableHTTPServerTransport>,
    sse: {} as Record<string, SSEServerTransport>,
  };

  // Health check
  app.get("/health", (c) => c.json({ status: "ok", timestamp: new Date().toISOString() }));

  // Registered after /health, so the health check stays open and every
  // route added below needs the token.
  if (authToken) {
    app.use(
      "*",
      bearerAuth({
        token: authToken,
        noAuthenticationHeader: { message: jsonrpcError(-32001, "Unauthorized") },
        invalidAuthenticationHeader: {
          message: jsonrpcError(-32001, "Invalid Authorization header"),
        },
        invalidToken: { message: jsonrpcError(-32001, "Unauthorized") },
      }),
    );
  }

  app.use(
    "*",
    bodyLimit({
      maxSize: MAX_BODY_BYTES,
      onError: (c) => c.json(jsonrpcError(-32000, "Payload Too Large"), 413),
    }),
  );

  // Modern Streamable HTTP - POST
  app.post("/mcp", async (c) => {
    const { incoming, outgoing } = c.env;
    try {
      const sessionId = c.req.header("mcp-session-id");
      let transport: StreamableHTTPServerTransport;
      const body = await c.req.json();

      if (sessionId && transports.streamable[sessionId]) {
        transport = transports.streamable[sessionId];
      } else if (!sessionId && isInitializeRequest(body)) {
        transport = new StreamableHTTPServerTransport({
          sessionIdGenerator: () => randomUUID(),
          onsessioninitialized: (sid) => {
            transports.streamable[sid] = transport;
            logger.info("New MCP session initialized", { sessionId: sid });
          },
        });

        transport.onclose = () => {
          if (transport.sessionId) {
            logger.info("MCP session closed", { sessionId: transport.sessionId });
            delete transports.streamable[transport.sessionId];
          }
        };

        const server = createServer();
        await server.connect(
          transport as unknown as import("@modelcontextprotocol/sdk/shared/transport.js").Transport,
        );
      } else {
        return c.json(
          jsonrpcError(
            -32000,
            "Bad Request: No valid session ID or invalid initialization request",
          ),
          400,
        );
      }

      await transport.handleRequest(incoming, outgoing, body);
      return neverResolve();
    } catch (error) {
      logger.error("Error handling HTTP request", {
        error: error instanceof Error ? error.message : String(error),
      });
      return c.json(jsonrpcError(-32603, "Internal server error"), 500);
    }
  });

  // Modern Streamable HTTP - GET (SSE notifications)
  app.get("/mcp", async (c) => {
    const { incoming, outgoing } = c.env;
    const sessionId = c.req.header("mcp-session-id");

    if (!sessionId || !transports.streamable[sessionId]) {
      return c.json(jsonrpcError(-32000, "Invalid or missing session ID"), 400);
    }

    try {
      const transport = transports.streamable[sessionId];
      await transport.handleRequest(incoming, outgoing);
      return neverResolve();
    } catch (error) {
      logger.error("Error handling GET request", {
        error: error instanceof Error ? error.message : String(error),
      });
      return c.json(jsonrpcError(-32603, "Internal server error"), 500);
    }
  });

  // Modern Streamable HTTP - DELETE (session termination)
  app.delete("/mcp", async (c) => {
    const { incoming, outgoing } = c.env;
    const sessionId = c.req.header("mcp-session-id");

    if (!sessionId || !transports.streamable[sessionId]) {
      return c.json(jsonrpcError(-32000, "Invalid or missing session ID"), 400);
    }

    try {
      const transport = transports.streamable[sessionId];
      await transport.handleRequest(incoming, outgoing);

      if (transports.streamable[sessionId]) {
        logger.info("MCP session terminated", { sessionId });
        delete transports.streamable[sessionId];
      }
      return neverResolve();
    } catch (error) {
      logger.error("Error handling DELETE request", {
        error: error instanceof Error ? error.message : String(error),
      });
      return c.json(jsonrpcError(-32603, "Internal server error"), 500);
    }
  });

  // Legacy SSE endpoint
  app.get("/sse", async (c) => {
    const { outgoing } = c.env;
    try {
      const transport = new SSEServerTransport("/messages", outgoing);
      transports.sse[transport.sessionId] = transport;

      outgoing.on("close", () => {
        logger.info("Legacy SSE session closed", { sessionId: transport.sessionId });
        delete transports.sse[transport.sessionId];
      });

      const server = createServer();
      await server.connect(transport);
      logger.info("New legacy SSE session initialized", { sessionId: transport.sessionId });
      return neverResolve();
    } catch (error) {
      logger.error("Error handling SSE request", {
        error: error instanceof Error ? error.message : String(error),
      });
      return c.json(jsonrpcError(-32603, "Internal server error"), 500);
    }
  });

  // Legacy message endpoint
  app.post("/messages", async (c) => {
    const { incoming, outgoing } = c.env;
    try {
      const sessionId = c.req.query("sessionId");
      if (!sessionId) {
        return c.json(jsonrpcError(-32000, "sessionId query parameter is required"), 400);
      }

      const transport = transports.sse[sessionId];
      if (!transport) {
        return c.json(jsonrpcError(-32000, "No transport found for sessionId"), 400);
      }

      const body = await c.req.json();
      await transport.handlePostMessage(incoming, outgoing, body);
      return neverResolve();
    } catch (error) {
      logger.error("Error handling legacy message request", {
        error: error instanceof Error ? error.message : String(error),
      });
      return c.json(jsonrpcError(-32603, "Internal server error"), 500);
    }
  });

  return app;
}

// Only src/index.ts starts the server. `bun build` puts this module into
// build/index.js, the file in process.argv[1], so a self-start check here
// would run next to that call and the second listen would crash on the port.
export async function main() {
  const authToken = readAuthToken();
  if (!authToken) {
    logger.warn(
      "MCP_AUTH_TOKEN is not set: anyone who can reach this port can call every Dokploy tool with this server's API key",
    );
  }
  const app = createApp(authToken);

  serve({ fetch: app.fetch, port: PORT }, () => {
    logger.info("MCP Dokploy server started", {
      port: PORT,
      auth: authToken ? "bearer" : "none",
      protocols: ["Streamable HTTP (MCP 2025-03-26)", "Legacy SSE (MCP 2024-11-05)"],
      endpoints: {
        modern: `http://localhost:${PORT}/mcp`,
        legacy: `http://localhost:${PORT}/sse`,
        health: `http://localhost:${PORT}/health`,
      },
    });
  });
}
