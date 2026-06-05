import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// Mock the orchestration layer so the handlers are tested in isolation (no
// network, no AWS). These mocks replace the exact module specifiers the
// handlers import.
vi.mock("../../api/src/services/orchestrator.js", () => ({
  analyzeUrl: vi.fn(),
  generateLookalikeSet: vi.fn()
}));
vi.mock("../../api/src/services/fastOrchestrator.js", () => ({
  analyzeUrlFast: vi.fn()
}));
vi.mock("../../api/src/services/healthStatus.js", () => ({
  buildHealthResponse: vi.fn(async (service: string) => ({ ok: true, service }))
}));

import { handler as analyzeHandler } from "../../api/src/handlers/analyze";
import { handler as analyzeFastHandler } from "../../api/src/handlers/analyzeFast";
import { handler as generateHandler } from "../../api/src/handlers/generateLookalikes";
import { handler as healthHandler } from "../../api/src/handlers/health";
import { analyzeUrl, generateLookalikeSet } from "../../api/src/services/orchestrator";
import { analyzeUrlFast } from "../../api/src/services/fastOrchestrator";

type Resp = { statusCode: number; headers: Record<string, string>; body: string };

// The handler type is (event, context, callback); we only await the returned
// promise. Cast through unknown to satisfy the AWS Lambda signature in tests.
const invoke = async (h: unknown, event: unknown): Promise<Resp> => {
  const fn = h as (e: unknown, c: unknown, cb: unknown) => Promise<Resp>;
  return fn(event, {}, () => undefined);
};

const body = (r: Resp) => JSON.parse(r.body);

beforeEach(() => {
  vi.mocked(analyzeUrl).mockResolvedValue({ verdict: "High", threat_score: 72 } as never);
  vi.mocked(analyzeUrlFast).mockResolvedValue({ verdict: "High", threat_score: 70, partial: true } as never);
  vi.mocked(generateLookalikeSet).mockResolvedValue({ candidates: [] } as never);
});

afterEach(() => vi.clearAllMocks());

describe("analyze handler", () => {
  it("short-circuits warmup pings without doing work", async () => {
    const r = await invoke(analyzeHandler, { warmup: true });
    expect(r.statusCode).toBe(200);
    expect(body(r)).toEqual({ warm: true });
    expect(analyzeUrl).not.toHaveBeenCalled();
  });

  it("answers CORS preflight for the REST (v1) payload shape", async () => {
    const r = await invoke(analyzeHandler, { httpMethod: "OPTIONS" });
    expect(r.statusCode).toBe(204);
    expect(analyzeUrl).not.toHaveBeenCalled();
  });

  it("answers CORS preflight for the HTTP-API (v2) payload shape", async () => {
    const r = await invoke(analyzeHandler, { requestContext: { http: { method: "OPTIONS" } } });
    expect(r.statusCode).toBe(204);
  });

  it("analyzes a valid request and returns the result with CORS headers", async () => {
    const r = await invoke(analyzeHandler, { body: JSON.stringify({ url: "https://paypa1.com" }) });
    expect(r.statusCode).toBe(200);
    expect(body(r).verdict).toBe("High");
    expect(r.headers["access-control-allow-origin"]).toBeDefined();
    expect(vi.mocked(analyzeUrl)).toHaveBeenCalledWith(
      expect.objectContaining({ url: "https://paypa1.com", mode: "manual_entry" })
    );
  });

  it("rejects a request missing the url field with 400", async () => {
    const r = await invoke(analyzeHandler, { body: JSON.stringify({ mode: "manual_entry" }) });
    expect(r.statusCode).toBe(400);
    expect(body(r).message).toBeDefined();
    expect(analyzeUrl).not.toHaveBeenCalled();
  });

  it("rejects malformed JSON with 400 (no crash)", async () => {
    const r = await invoke(analyzeHandler, { body: "{not valid json" });
    expect(r.statusCode).toBe(400);
  });
});

describe("analyzeFast handler", () => {
  it("short-circuits warmup pings", async () => {
    const r = await invoke(analyzeFastHandler, { warmup: true });
    expect(r.statusCode).toBe(200);
    expect(body(r)).toEqual({ warm: true });
    expect(analyzeUrlFast).not.toHaveBeenCalled();
  });

  it("returns a fast analysis for a valid request", async () => {
    const r = await invoke(analyzeFastHandler, { body: JSON.stringify({ url: "https://paypa1.com" }) });
    expect(r.statusCode).toBe(200);
    expect(body(r).partial).toBe(true);
    expect(analyzeUrlFast).toHaveBeenCalledOnce();
  });

  it("rejects an empty url with 400", async () => {
    const r = await invoke(analyzeFastHandler, { body: JSON.stringify({ url: "" }) });
    expect(r.statusCode).toBe(400);
  });
});

describe("generateLookalikes handler", () => {
  it("answers CORS preflight", async () => {
    const r = await invoke(generateHandler, { httpMethod: "OPTIONS" });
    expect(r.statusCode).toBe(204);
  });

  it("generates for a valid canonical_domain", async () => {
    const r = await invoke(generateHandler, { body: JSON.stringify({ canonical_domain: "amazon.com" }) });
    expect(r.statusCode).toBe(200);
    expect(generateLookalikeSet).toHaveBeenCalledOnce();
  });

  it("rejects a missing canonical_domain with 400", async () => {
    const r = await invoke(generateHandler, { body: JSON.stringify({ brand_name: "Amazon" }) });
    expect(r.statusCode).toBe(400);
  });
});

describe("health handler", () => {
  it("returns 200 with the service identity", async () => {
    const r = await invoke(healthHandler, {});
    expect(r.statusCode).toBe(200);
    expect(body(r).service).toBe("capstone-domain-guardian-api");
  });
});
