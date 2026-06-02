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

  it("sets typosquatting_type to 'keyword_stuffing' when the brand match flagged a stuffing token", () => {
    const sheridanBrand: BrandMatch = {
      brand_name: "Sheridan College",
      canonical_domain: "sheridancollege.ca",
      confidence: 0.9,
      method: "catalog",
      matched_keywords: ["payment"]
    };
    const normalized = normalizeInputUrl("payment-sheridancollege.ca");
    const lexical = buildLexicalSignals({
      normalizedDomain: normalized.registrableDomain,
      punycodeHostname: normalized.punycodeHostname,
      isIdn: normalized.isIdn,
      tld: normalized.tld,
      isIpLiteral: normalized.isIpLiteral,
      brandMatch: sheridanBrand
    });

    expect(lexical.typosquatting_type).toBe("keyword_stuffing");
  });
});

function blankRiskFactors(): RiskFactors {
  return {
    lexical: {
      is_homoglyph: null, is_idn: false, punycode_domain: null, edit_distance_to_target: null,
      levenshtein_distance: null, damerau_levenshtein_distance: null, jaro_winkler_similarity: null,
      ngram_similarity: null, typosquatting_type: null, character_substitution_pattern: null,
      keyboard_proximity_score: null, dictionary_similarity_score: null, length_difference: null,
      tld_manipulation: null, suspicious_tld: false, tld_risk_score: 0.15, subdomain_structure_risk: 0.18,
      brand_keyword_detected: false, suspicious_keywords: [], hyphenation_pattern: null,
      tokenization_pattern: null, mixed_character_sets: false, url_shortener_detected: false, ip_literal_host: false
    },
    infrastructure: {
      domain_age_days: null, registrar: null, registrant_org: null, registration_length_years: null,
      whois_privacy: null, hidden_ownership: null, registrant_country: null, ssl_valid: null, ssl_error: null,
      certificate_issuer: null, certificate_reputation: null, certificate_age_days: null,
      certificate_domain_mismatch: null, creation_date_anomaly: null, mx_records_present: null,
      dns_records: { a: [], mx: [], txt: [], ns: [] }, dns_history_changes: null, fast_flux_detected: null,
      ip_reputation_score: null, hosting_asn: null, hosting_asn_reputation: null, shared_hosting_risk: null,
      redirect_count: null, final_url: null
    },
    content: {
      page_title: null, html_similarity_score: null, logo_reuse_detected: null, text_reuse_score: null,
      credential_harvesting_detected: null, forms_detected: null, password_fields_detected: null,
      form_submits_to_real_brand: null, hidden_iframes: null, obfuscated_javascript: null,
      suspicious_script_patterns: [], missing_security_headers: [], server_header_exposure: null,
      redirect_chain: [], body_keywords: []
    },
    reputational: {
      blacklisted_in_phishTank: null, blacklisted_in_openPhish: null, google_safe_browsing: null,
      virus_total_detections: null, abuse_ipdb_reports: null, phishing_feed_hits: null
    },
    behavioral: { keyboard_event_listeners: null, http_to_https_mismatch: null, external_form_action: null },
    email_auth: { spf_present: null, dkim_present: null, dmarc_present: null, spf_dkim_dmarc_missing: null },
    passive_history: { passive_dns_observed: null, passive_dns_notes: [], archive_first_seen_days: null, ownership_changes_detected: null },
    machine_learning: { brand_similarity_score: null, visual_similarity_score: null, url_entropy: null, time_based_risk: null }
  };
}

describe("computeThreatScore verdict floors", () => {
  it("floors a Google Safe Browsing hit to Malicious", () => {
    const rf = blankRiskFactors();
    rf.reputational.google_safe_browsing = true;
    const { score, verdict } = computeThreatScore(rf);
    expect(score).toBeGreaterThanOrEqual(90);
    expect(verdict).toBe("Malicious");
  });

  it("floors a phishing-feed hit to Critical even with no other signals", () => {
    const rf = blankRiskFactors();
    rf.reputational.blacklisted_in_openPhish = true;
    rf.reputational.phishing_feed_hits = 1;
    const { score, verdict } = computeThreatScore(rf);
    expect(score).toBeGreaterThanOrEqual(80);
    expect(verdict).toBe("Critical");
  });

  it("floors a confident keyword-stuffing lookalike to High", () => {
    const rf = blankRiskFactors();
    rf.lexical.typosquatting_type = "keyword_stuffing";
    const { score, verdict } = computeThreatScore(rf, { brandConfidence: 0.9 });
    expect(score).toBeGreaterThanOrEqual(65);
    expect(verdict).toBe("High");
  });

  it("floors credential harvesting on a shared host to High", () => {
    const rf = blankRiskFactors();
    rf.content.credential_harvesting_detected = true;
    const { score, verdict } = computeThreatScore(rf, { registrableDomain: "blogspot.com" });
    expect(score).toBeGreaterThanOrEqual(65);
    expect(verdict).toBe("High");
  });

  it("does NOT floor a benign domain (guards against false positives)", () => {
    const rf = blankRiskFactors();
    const { verdict } = computeThreatScore(rf, { brandConfidence: 0 });
    expect(["Safe", "Low"]).toContain(verdict);
  });

  it("does not let a low brand confidence trigger the lookalike floor", () => {
    const rf = blankRiskFactors();
    rf.lexical.typosquatting_type = "keyword_stuffing";
    const { verdict } = computeThreatScore(rf, { brandConfidence: 0.4 });
    expect(["Safe", "Low"]).toContain(verdict);
  });
});
