import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { analysisResultSchema, type RiskFactors } from "@capstone/shared";

// Integration test for the REAL analyzeUrl orchestration. Only the network-
// bound services are mocked (page fetch, WHOIS/DNS/TLS, reputation feeds,
// passive history, Bedrock). Everything else — brand resolution, legitimacy
// detection, lexical signals, verdict floors, evidence, and the final schema
// validation — runs for real, so this exercises the wiring the unit tests skip.

const infraBase = () => ({
  domain_age_days: null, registrar: null, registrant_org: null, registration_length_years: null,
  whois_privacy: null, hidden_ownership: null, registrant_country: null, ssl_valid: true, ssl_error: null,
  certificate_issuer: null, certificate_reputation: null, certificate_age_days: null,
  certificate_domain_mismatch: null, creation_date_anomaly: null, mx_records_present: false,
  dns_records: { a: [], mx: [], txt: [], ns: [] }, dns_history_changes: null, fast_flux_detected: null,
  ip_reputation_score: null, hosting_asn: null, hosting_asn_reputation: null, shared_hosting_risk: null,
  redirect_count: null, final_url: null, tld: "com", ownership_changes_detected: null
});

const cleanReputation = (): { reputational: RiskFactors["reputational"]; diagnostics: [] } => ({
  reputational: {
    blacklisted_in_phishTank: false, blacklisted_in_openPhish: false, google_safe_browsing: false,
    virus_total_detections: 0, abuse_ipdb_reports: 0, phishing_feed_hits: 0
  },
  diagnostics: []
});

vi.mock("../../api/src/services/pageFetcher.js", () => ({
  fetchPage: vi.fn(async (url: string) => ({
    requestedUrl: url, finalUrl: url, redirectChain: [], statusCode: 200,
    html: "", headers: {}, fetchMs: 1, error: null
  }))
}));
vi.mock("../../api/src/services/domainIntelligence.js", () => ({
  collectInfrastructureSignals: vi.fn(async () => infraBase())
}));
vi.mock("../../api/src/services/reputation.js", () => ({
  collectReputationSignals: vi.fn(async () => cleanReputation())
}));
vi.mock("../../api/src/services/historySignals.js", () => ({
  collectPassiveHistorySignals: vi.fn(async () => ({
    passiveHistory: { passive_dns_observed: null, passive_dns_notes: [], archive_first_seen_days: null, ownership_changes_detected: null },
    dnsHistoryChanges: null,
    diagnostics: []
  }))
}));
// Force the LLM to be unavailable so we prove the deterministic fallback path.
vi.mock("../../api/src/services/bedrock.js", () => ({
  callBedrockJson: vi.fn(async () => null)
}));

import { analyzeUrl } from "../../api/src/services/orchestrator";
import { collectReputationSignals } from "../../api/src/services/reputation";

beforeEach(() => {
  vi.mocked(collectReputationSignals).mockResolvedValue(cleanReputation() as never);
});
afterEach(() => vi.clearAllMocks());

describe("analyzeUrl pipeline (real orchestration, mocked network)", () => {
  it("produces a schema-valid result and flags a lookalike as High+ without the LLM", async () => {
    const result = await analyzeUrl({ url: "https://paypa1.com", mode: "manual_entry" });

    // The orchestrator parses with analysisResultSchema before returning, so a
    // returned result is already valid — assert explicitly as a guardrail.
    expect(() => analysisResultSchema.parse(result)).not.toThrow();
    expect(result.schema_version).toBe("analysis-result.v2");
    expect(result.brand_match.brand_name).toBe("PayPal");
    expect(["High", "Critical", "Malicious"]).toContain(result.verdict);
    // Bedrock returned null → deterministic fallback reasoning must be present.
    expect(typeof result.reasoning).toBe("string");
    expect(result.reasoning.length).toBeGreaterThan(0);
  });

  it("keeps a legitimate domain Safe/Low (legitimacy suppression)", async () => {
    const result = await analyzeUrl({ url: "https://google.com", mode: "manual_entry" });
    expect(["Safe", "Low"]).toContain(result.verdict);
    expect(result.risk_factors.lexical.is_homoglyph).toBeNull();
  });

  it("lets a phishing-feed hit drive a Critical verdict (reputation floor, no LLM downgrade)", async () => {
    vi.mocked(collectReputationSignals).mockResolvedValue({
      reputational: {
        blacklisted_in_phishTank: true, blacklisted_in_openPhish: false, google_safe_browsing: false,
        virus_total_detections: 0, abuse_ipdb_reports: 0, phishing_feed_hits: 1
      },
      diagnostics: []
    } as never);

    const result = await analyzeUrl({ url: "https://totallyrandom-unknown-site-xyz.com", mode: "manual_entry" });
    expect(result.verdict).toBe("Critical");
    expect(result.threat_score).toBeGreaterThanOrEqual(80);
  });
});
