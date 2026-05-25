import { beforeEach, describe, expect, it, vi } from "vitest";
import type { AnalysisResult } from "@capstone/shared";

const tabsUpdate = vi.fn();

vi.stubGlobal("chrome", {
  runtime: {
    getURL: (path: string) => `chrome-extension://test-id/${path}`,
    onInstalled: { addListener: vi.fn() }
  },
  tabs: {
    update: tabsUpdate
  }
});

vi.mock("../../extension/src/lib/api", () => ({
  analyzeDomainFast: vi.fn()
}));

vi.mock("../../extension/src/lib/storage", () => ({
  getRealtimeProtection: vi.fn().mockResolvedValue(true),
  getTrustedDomains: vi.fn().mockResolvedValue(new Set<string>()),
  getSessionBypass: vi.fn().mockResolvedValue(new Set<string>()),
  getCachedAnalysis: vi.fn().mockResolvedValue(null),
  setCachedAnalysis: vi.fn().mockResolvedValue(undefined),
  putPendingWarning: vi.fn().mockResolvedValue(undefined),
  addSessionBypass: vi.fn().mockResolvedValue(undefined)
}));

const { handleNavigation } = await import("../../extension/src/background/navigationGuard");
const api = await import("../../extension/src/lib/api");
const storage = await import("../../extension/src/lib/storage");

function makeResult(verdict: AnalysisResult["verdict"]): AnalysisResult {
  return {
    schema_version: "analysis-result.v2",
    mode: "manual_entry",
    analyzed_url: "https://test.example",
    normalized_domain: "test.example",
    normalized_url: "https://test.example",
    brand_match: {
      brand_name: "Unknown",
      canonical_domain: "test.example",
      confidence: 0,
      method: "unknown",
      matched_keywords: []
    },
    threat_score: verdict === "Critical" || verdict === "Malicious" ? 90 : 40,
    verdict,
    reasoning: "test",
    risk_factors: {} as AnalysisResult["risk_factors"],
    evidence_summary: { highlights: [], evidence_items: [], signal_diagnostics: [] },
    reporting_contacts: {} as AnalysisResult["reporting_contacts"],
    signal_sources: [],
    timings: { total_ms: 0, fetch_ms: null, enrichment_ms: null, llm_ms: null },
    export_metadata: { generated_at: "", generated_by: "", schema_version: "", sources: [] },
    partial: true
  };
}

describe("navigationGuard", () => {
  beforeEach(() => {
    tabsUpdate.mockReset();
    (api.analyzeDomainFast as ReturnType<typeof vi.fn>).mockReset();
    (storage.getRealtimeProtection as ReturnType<typeof vi.fn>).mockResolvedValue(true);
    (storage.getTrustedDomains as ReturnType<typeof vi.fn>).mockResolvedValue(new Set());
    (storage.getSessionBypass as ReturnType<typeof vi.fn>).mockResolvedValue(new Set());
    (storage.getCachedAnalysis as ReturnType<typeof vi.fn>).mockResolvedValue(null);
  });

  it("skips subframe navigations", async () => {
    await handleNavigation({ tabId: 1, url: "https://attacker.example", frameId: 9 });
    expect(api.analyzeDomainFast).not.toHaveBeenCalled();
    expect(tabsUpdate).not.toHaveBeenCalled();
  });

  it("skips non-http URLs", async () => {
    await handleNavigation({ tabId: 1, url: "chrome://settings", frameId: 0 });
    expect(api.analyzeDomainFast).not.toHaveBeenCalled();
  });

  it("skips the extension's own warning page", async () => {
    await handleNavigation({
      tabId: 1,
      url: "chrome-extension://test-id/warning.html?id=abc",
      frameId: 0
    });
    expect(api.analyzeDomainFast).not.toHaveBeenCalled();
  });

  it("skips when realtime protection is off", async () => {
    (storage.getRealtimeProtection as ReturnType<typeof vi.fn>).mockResolvedValue(false);
    await handleNavigation({ tabId: 1, url: "https://attacker.example", frameId: 0 });
    expect(api.analyzeDomainFast).not.toHaveBeenCalled();
  });

  it("skips domains on the bundled allowlist", async () => {
    await handleNavigation({ tabId: 1, url: "https://www.google.com/search", frameId: 0 });
    expect(api.analyzeDomainFast).not.toHaveBeenCalled();
    expect(tabsUpdate).not.toHaveBeenCalled();
  });

  it("skips trusted domains", async () => {
    (storage.getTrustedDomains as ReturnType<typeof vi.fn>).mockResolvedValue(
      new Set(["attacker.example"])
    );
    await handleNavigation({ tabId: 1, url: "https://attacker.example", frameId: 0 });
    expect(api.analyzeDomainFast).not.toHaveBeenCalled();
  });

  it("skips domains on the session bypass list", async () => {
    (storage.getSessionBypass as ReturnType<typeof vi.fn>).mockResolvedValue(
      new Set(["attacker.example"])
    );
    await handleNavigation({ tabId: 1, url: "https://attacker.example", frameId: 0 });
    expect(api.analyzeDomainFast).not.toHaveBeenCalled();
  });

  it("redirects to the warning page when the cache holds a High verdict", async () => {
    (storage.getCachedAnalysis as ReturnType<typeof vi.fn>).mockResolvedValue({
      verdict: "High",
      threat_score: 70,
      brand_match: makeResult("High").brand_match,
      evidence_summary: makeResult("High").evidence_summary,
      reasoning: "cached",
      normalized_url: "https://attacker.example",
      cached_at: Date.now(),
      ttl_ms: 60_000
    });
    await handleNavigation({ tabId: 5, url: "https://attacker.example", frameId: 0 });
    expect(api.analyzeDomainFast).not.toHaveBeenCalled();
    expect(tabsUpdate).toHaveBeenCalledTimes(1);
    const [tabId, props] = tabsUpdate.mock.calls[0]!;
    expect(tabId).toBe(5);
    expect(props.url).toContain("warning.html");
  });

  it("does not redirect when the cache holds a Safe verdict", async () => {
    (storage.getCachedAnalysis as ReturnType<typeof vi.fn>).mockResolvedValue({
      verdict: "Safe",
      threat_score: 10,
      brand_match: makeResult("Safe").brand_match,
      evidence_summary: makeResult("Safe").evidence_summary,
      reasoning: "cached",
      normalized_url: "https://attacker.example",
      cached_at: Date.now(),
      ttl_ms: 60_000
    });
    await handleNavigation({ tabId: 5, url: "https://attacker.example", frameId: 0 });
    expect(api.analyzeDomainFast).not.toHaveBeenCalled();
    expect(tabsUpdate).not.toHaveBeenCalled();
  });

  it("calls /analyze/fast and redirects for High verdicts on cache miss", async () => {
    (api.analyzeDomainFast as ReturnType<typeof vi.fn>).mockResolvedValue(makeResult("Critical"));
    await handleNavigation({ tabId: 8, url: "https://attacker.example", frameId: 0 });
    expect(api.analyzeDomainFast).toHaveBeenCalledTimes(1);
    expect(storage.setCachedAnalysis).toHaveBeenCalled();
    expect(tabsUpdate).toHaveBeenCalledTimes(1);
  });

  it("caches but does not redirect when verdict is Low on cache miss", async () => {
    (api.analyzeDomainFast as ReturnType<typeof vi.fn>).mockResolvedValue(makeResult("Low"));
    await handleNavigation({ tabId: 8, url: "https://attacker.example", frameId: 0 });
    expect(storage.setCachedAnalysis).toHaveBeenCalled();
    expect(tabsUpdate).not.toHaveBeenCalled();
  });

  it("swallows API failures silently", async () => {
    const warnSpy = vi.spyOn(console, "warn").mockImplementation(() => undefined);
    (api.analyzeDomainFast as ReturnType<typeof vi.fn>).mockRejectedValue(new Error("API down"));
    await handleNavigation({ tabId: 8, url: "https://attacker.example", frameId: 0 });
    expect(tabsUpdate).not.toHaveBeenCalled();
    warnSpy.mockRestore();
  });
});
