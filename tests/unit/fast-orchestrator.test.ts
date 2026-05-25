import { beforeEach, describe, expect, it, vi } from "vitest";
import { analysisResultSchema } from "@capstone/shared";

vi.mock("../../api/src/services/reputation", () => ({
  collectReputationSignals: vi.fn().mockResolvedValue({
    reputational: {
      blacklisted_in_phishTank: false,
      blacklisted_in_openPhish: false,
      google_safe_browsing: false,
      virus_total_detections: 0,
      abuse_ipdb_reports: null,
      phishing_feed_hits: 0
    },
    diagnostics: [
      {
        signal: "blacklisted_in_openPhish",
        provider: "openphish",
        status: "ok" as const
      }
    ]
  })
}));

vi.mock("../../api/src/services/bedrock", () => ({
  callBedrockJson: vi.fn().mockResolvedValue(null)
}));

const { analyzeUrlFast } = await import("../../api/src/services/fastOrchestrator");
const reputationModule = await import("../../api/src/services/reputation");

describe("fastOrchestrator", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("returns a schema-valid AnalysisResult with partial:true", async () => {
    const result = await analyzeUrlFast({ url: "https://amaz0n-login-secure.com", mode: "manual_entry" });
    expect(() => analysisResultSchema.parse(result)).not.toThrow();
    expect(result.partial).toBe(true);
  });

  it("includes the fast_path diagnostic", async () => {
    const result = await analyzeUrlFast({ url: "https://example.com", mode: "manual_entry" });
    const diag = result.evidence_summary.signal_diagnostics.find((d) => d.signal === "fast_path");
    expect(diag).toBeDefined();
    expect(diag?.status).toBe("ok");
  });

  it("skips page fetch / LLM (no fetch_ms or llm_ms timings)", async () => {
    const result = await analyzeUrlFast({ url: "https://example.com", mode: "manual_entry" });
    expect(result.timings.fetch_ms).toBeNull();
    expect(result.timings.llm_ms).toBeNull();
  });

  it("honors brand_override without consulting Bedrock", async () => {
    const result = await analyzeUrlFast({
      url: "https://amaz0n-login.com",
      mode: "manual_entry",
      brand_override: "amazon.com"
    });
    expect(result.brand_match.method).toBe("override");
    expect(result.brand_match.brand_name.toLowerCase()).toContain("amazon");
  });

  it("calls reputation collector exactly once", async () => {
    await analyzeUrlFast({ url: "https://example.com", mode: "manual_entry" });
    expect(reputationModule.collectReputationSignals).toHaveBeenCalledTimes(1);
  });

  it("falls back to empty reputation when collector exceeds the budget", async () => {
    (reputationModule.collectReputationSignals as ReturnType<typeof vi.fn>).mockImplementationOnce(
      () =>
        new Promise((resolve) => {
          setTimeout(() => resolve({ reputational: {}, diagnostics: [] }), 5000);
        })
    );
    const result = await analyzeUrlFast({ url: "https://example.com", mode: "manual_entry" });
    const diag = result.evidence_summary.signal_diagnostics.find((d) => d.signal === "reputation");
    expect(diag?.status).toBe("query_failed");
  }, 10000);
});
