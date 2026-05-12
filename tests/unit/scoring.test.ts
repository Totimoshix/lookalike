import { describe, expect, it } from "vitest";
import type { BrandMatch, RiskFactors } from "@capstone/shared";
import { normalizeInputUrl } from "@capstone/shared";
import { buildLexicalSignals, buildMachineLearningSignals, computeThreatScore } from "../../api/src/services/scoring";

const amazonBrand: BrandMatch = {
  brand_name: "Amazon",
  canonical_domain: "amazon.com",
  confidence: 0.94,
  method: "catalog",
  matched_keywords: ["amazon"]
};

const unknownBrand: BrandMatch = {
  brand_name: "Unknown",
  canonical_domain: "1mazon.ca",
  confidence: 0,
  method: "unknown",
  matched_keywords: []
};

describe("scoring pipeline", () => {
  it("does not self-compare lexical similarity when no brand match is identified", () => {
    const normalized = normalizeInputUrl("1mazon.ca");
    const lexical = buildLexicalSignals({
      normalizedDomain: normalized.registrableDomain,
      punycodeHostname: normalized.punycodeHostname,
      isIdn: normalized.isIdn,
      tld: normalized.tld,
      isIpLiteral: normalized.isIpLiteral,
      brandMatch: unknownBrand
    });

    expect(lexical.jaro_winkler_similarity).toBeNull();
    expect(lexical.edit_distance_to_target).toBeNull();
    expect(lexical.typosquatting_type).toBeNull();
    expect(lexical.mixed_character_sets).toBe(true);
  });

  it("scores a lookalike domain as high risk when multiple signals align", () => {
    const normalized = normalizeInputUrl("amaz0n-login-secure.com");
    const lexical = buildLexicalSignals({
      normalizedDomain: normalized.registrableDomain,
      punycodeHostname: normalized.punycodeHostname,
      isIdn: normalized.isIdn,
      tld: normalized.tld,
      isIpLiteral: normalized.isIpLiteral,
      brandMatch: amazonBrand
    });

    const riskFactors: RiskFactors = {
      lexical,
      infrastructure: {
        domain_age_days: 3,
        registrar: "Namecheap, Inc.",
        registrant_org: "Privacy service",
        registration_length_years: 1,
        whois_privacy: true,
        hidden_ownership: true,
        registrant_country: "Unknown",
        ssl_valid: false,
        ssl_error: "certificate expired",
        certificate_issuer: null,
        certificate_reputation: null,
        certificate_age_days: null,
        certificate_domain_mismatch: true,
        creation_date_anomaly: true,
        mx_records_present: false,
        dns_records: { a: ["203.0.113.5"], mx: [], txt: [], ns: ["ns1.example.com"] },
        dns_history_changes: null,
        fast_flux_detected: false,
        ip_reputation_score: 80,
        hosting_asn: "AS123 ExampleHost",
        hosting_asn_reputation: "unclassified",
        shared_hosting_risk: true,
        redirect_count: 2,
        final_url: "http://amaz0n-login-secure.com"
      },
      content: {
        page_title: "Amazon account verification",
        html_similarity_score: 0.78,
        logo_reuse_detected: true,
        text_reuse_score: 0.8,
        credential_harvesting_detected: true,
        forms_detected: 1,
        password_fields_detected: 1,
        form_submits_to_real_brand: true,
        hidden_iframes: false,
        obfuscated_javascript: true,
        suspicious_script_patterns: ["keyboard_capture"],
        missing_security_headers: ["content-security-policy"],
        server_header_exposure: "Apache/2.4.18",
        redirect_chain: ["http://amaz0n-login-secure.com/login"],
        body_keywords: ["verify", "signin"]
      },
      reputational: {
        blacklisted_in_phishTank: null,
        blacklisted_in_openPhish: null,
        google_safe_browsing: true,
        virus_total_detections: 15,
        abuse_ipdb_reports: 12,
        phishing_feed_hits: 1
      },
      behavioral: {
        keyboard_event_listeners: true,
        http_to_https_mismatch: true,
        external_form_action: true
      },
      email_auth: {
        spf_present: false,
        dkim_present: false,
        dmarc_present: false,
        spf_dkim_dmarc_missing: true
      },
      passive_history: {
        passive_dns_observed: null,
        passive_dns_notes: [],
        archive_first_seen_days: null,
        ownership_changes_detected: true
      },
      machine_learning: buildMachineLearningSignals({
        normalizedUrl: normalized.normalizedUrl,
        lexical,
        content: {
          page_title: "Amazon account verification",
          html_similarity_score: 0.78,
          logo_reuse_detected: true,
          text_reuse_score: 0.8,
          credential_harvesting_detected: true,
          forms_detected: 1,
          password_fields_detected: 1,
          form_submits_to_real_brand: true,
          hidden_iframes: false,
          obfuscated_javascript: true,
          suspicious_script_patterns: ["keyboard_capture"],
          missing_security_headers: ["content-security-policy"],
          server_header_exposure: "Apache/2.4.18",
          redirect_chain: ["http://amaz0n-login-secure.com/login"],
          body_keywords: ["verify", "signin"]
        },
        infrastructure: {
          domain_age_days: 3,
          registrar: "Namecheap, Inc.",
          registrant_org: "Privacy service",
          registration_length_years: 1,
          whois_privacy: true,
          hidden_ownership: true,
          registrant_country: "Unknown",
          ssl_valid: false,
          ssl_error: "certificate expired",
          certificate_issuer: null,
          certificate_reputation: null,
          certificate_age_days: null,
          certificate_domain_mismatch: true,
          creation_date_anomaly: true,
          mx_records_present: false,
          dns_records: { a: ["203.0.113.5"], mx: [], txt: [], ns: ["ns1.example.com"] },
          dns_history_changes: null,
          fast_flux_detected: false,
          ip_reputation_score: 80,
          hosting_asn: "AS123 ExampleHost",
          hosting_asn_reputation: "unclassified",
          shared_hosting_risk: true,
          redirect_count: 2,
          final_url: "http://amaz0n-login-secure.com"
        }
      })
    };

    const result = computeThreatScore(riskFactors);

    expect(result.score).toBeGreaterThanOrEqual(75);
    expect(["Critical", "Malicious"]).toContain(result.verdict);
  });
});
