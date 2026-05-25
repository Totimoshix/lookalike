import { describe, expect, it } from "vitest";
import type { AnalysisResult } from "@capstone/shared";
import {
  headlineForVerdict,
  pickTopReasons,
  shortSummary,
  toPlainBullet,
  toneForVerdict
} from "../../extension/src/lib/plainLanguage";

function makeResult(overrides: Partial<AnalysisResult> = {}): AnalysisResult {
  return {
    schema_version: "analysis-result.v2",
    mode: "manual_entry",
    analyzed_url: "https://amaz0n-login.com",
    normalized_domain: "amaz0n-login.com",
    normalized_url: "https://amaz0n-login.com",
    brand_match: {
      brand_name: "Amazon",
      canonical_domain: "amazon.com",
      confidence: 0.92,
      method: "catalog",
      matched_keywords: []
    },
    threat_score: 80,
    verdict: "Critical",
    reasoning: "Strong lookalike of Amazon with credential harvesting form. Recently registered.",
    risk_factors: {} as AnalysisResult["risk_factors"],
    evidence_summary: {
      highlights: ["Detected lookalike character substitution.", "Recently registered."],
      evidence_items: [
        {
          key: "domain_age",
          label: "Domain age (days)",
          category: "infrastructure",
          severity: "high",
          value: 4
        },
        {
          key: "credential_form",
          label: "Credential harvesting indicators",
          category: "content",
          severity: "critical",
          value: true
        },
        {
          key: "homoglyph",
          label: "Homoglyph detected",
          category: "lexical",
          severity: "high",
          value: true
        }
      ],
      signal_diagnostics: []
    },
    reporting_contacts: {} as AnalysisResult["reporting_contacts"],
    signal_sources: [],
    timings: { total_ms: 100, fetch_ms: null, enrichment_ms: null, llm_ms: null },
    export_metadata: { generated_at: "", generated_by: "", schema_version: "", sources: [] },
    partial: false,
    ...overrides
  };
}

describe("plainLanguage", () => {
  it("sorts top reasons by severity (critical first)", () => {
    const result = makeResult();
    const reasons = pickTopReasons(result);
    expect(reasons[0]).toContain("password");
  });

  it("translates known evidence keys into plain English", () => {
    const result = makeResult();
    const reasons = pickTopReasons(result, 3);
    expect(reasons).toEqual(
      expect.arrayContaining([
        expect.stringMatching(/password/i),
        expect.stringMatching(/4 days/i),
        expect.stringMatching(/Amazon/i)
      ])
    );
  });

  it("falls back to evidence label when no translation exists", () => {
    const result = makeResult({
      evidence_summary: {
        highlights: [],
        evidence_items: [
          {
            key: "completely_unknown_signal",
            label: "Unknown signal",
            category: "behavioral",
            severity: "medium",
            value: true,
            note: "Custom note"
          }
        ],
        signal_diagnostics: []
      }
    });
    expect(toPlainBullet(result.evidence_summary.evidence_items[0]!, result)).toBe("Custom note");
  });

  it("uses highlights as fallback when no evidence items exist", () => {
    const result = makeResult({
      evidence_summary: {
        highlights: ["Generic high risk hint."],
        evidence_items: [],
        signal_diagnostics: []
      }
    });
    expect(pickTopReasons(result, 3)).toEqual(["Generic high risk hint."]);
  });

  it("maps verdicts to expected tones and headlines", () => {
    expect(toneForVerdict("Safe")).toBe("safe");
    expect(toneForVerdict("Medium")).toBe("caution");
    expect(toneForVerdict("High")).toBe("warning");
    expect(toneForVerdict("Critical")).toBe("danger");
    expect(toneForVerdict("Malicious")).toBe("danger");
    expect(toneForVerdict("Unknown")).toBe("unknown");

    expect(headlineForVerdict("Safe")).toMatch(/safe/i);
    expect(headlineForVerdict("Critical")).toMatch(/phishing/i);
    expect(headlineForVerdict("Malicious")).toMatch(/malicious/i);
  });

  it("extracts the first sentence as the short summary", () => {
    const result = makeResult({
      reasoning: "First sentence here. Second sentence here. Third."
    });
    expect(shortSummary(result)).toBe("First sentence here.");
  });
});
