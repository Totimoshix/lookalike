import http from "node:http";
import { existsSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { analyzeRequestSchema, generateLookalikesRequestSchema } from "@capstone/shared";
import { analyzeUrl, generateLookalikeSet } from "./services/orchestrator.js";
import { analyzeUrlFast } from "./services/fastOrchestrator.js";
import { buildHealthResponse } from "./services/healthStatus.js";

const here = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(here, "..", "..");
const envPath = path.join(repoRoot, ".env");

if (existsSync(envPath)) {
  process.loadEnvFile?.(envPath);
}

const port = Number(process.env.PORT ?? 3000);
const host = process.env.HOST ?? "127.0.0.1";

async function checkExistingApi(baseUrl: string) {
  try {
    const response = await fetch(`${baseUrl}/health`);
    if (!response.ok) {
      return false;
    }
    const payload = (await response.json()) as { service?: string };
    return payload.service === "capstone-domain-guardian-local-api";
  } catch {
    return false;
  }
}

function writeJson(response: http.ServerResponse, statusCode: number, payload: unknown) {
  response.writeHead(statusCode, {
    "content-type": "application/json",
    "access-control-allow-origin": "*",
    "access-control-allow-headers": "content-type",
    "access-control-allow-methods": "GET,POST,OPTIONS"
  });
  response.end(JSON.stringify(payload));
}

async function readJsonBody(request: http.IncomingMessage): Promise<unknown> {
  const chunks: Buffer[] = [];
  for await (const chunk of request) {
    chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
  }

  if (chunks.length === 0) {
    return {};
  }

  return JSON.parse(Buffer.concat(chunks).toString("utf8"));
}

const server = http.createServer(async (request, response) => {
  const method = request.method ?? "GET";
  const url = new URL(request.url ?? "/", `http://${request.headers.host ?? "localhost"}`);

  if (method === "OPTIONS") {
    response.writeHead(204, {
      "access-control-allow-origin": "*",
      "access-control-allow-headers": "content-type",
      "access-control-allow-methods": "GET,POST,OPTIONS"
    });
    response.end();
    return;
  }

  try {
    if (method === "GET" && url.pathname === "/health") {
      writeJson(response, 200, await buildHealthResponse("capstone-domain-guardian-local-api"));
      return;
    }

    if (method === "POST" && url.pathname === "/analyze") {
      const parsed = analyzeRequestSchema.parse(await readJsonBody(request));
      const result = await analyzeUrl(parsed);
      writeJson(response, 200, result);
      return;
    }

    if (method === "POST" && url.pathname === "/analyze/fast") {
      const parsed = analyzeRequestSchema.parse(await readJsonBody(request));
      const result = await analyzeUrlFast(parsed);
      writeJson(response, 200, result);
      return;
    }

    if (method === "POST" && url.pathname === "/generate-lookalikes") {
      const parsed = generateLookalikesRequestSchema.parse(await readJsonBody(request));
      const result = await generateLookalikeSet(parsed);
      writeJson(response, 200, result);
      return;
    }

    writeJson(response, 404, {
      message: `No route for ${method} ${url.pathname}`
    });
  } catch (error) {
    writeJson(response, 400, {
      message: error instanceof Error ? error.message : "Unexpected server error"
    });
  }
});

server.on("error", async (error: NodeJS.ErrnoException) => {
  if (error.code === "EADDRINUSE") {
    const baseUrl = `http://${host}:${port}`;
    if (await checkExistingApi(baseUrl)) {
      console.log(`Capstone API already running on ${baseUrl}`);
      process.exit(0);
      return;
    }

    console.error(`Port ${port} is already in use by another service.`);
    process.exit(1);
    return;
  }

  throw error;
});

server.listen(port, host, () => {
  console.log(`Capstone API listening on http://${host}:${port}`);
});
