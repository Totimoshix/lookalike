// Offline evaluation of the lookalike-detection CORE.
//
// For each labeled domain we run the same deterministic path the orchestrator
// uses — normalize → brand resolution (skipping the LLM) → legitimacy check →
// lexical signals → ML signals → computeThreatScore — but with the network-
// dependent categories (reputation feeds, page content, infrastructure/WHOIS)
// left blank. This isolates and measures the project's core contribution: how
// well lexical + brand + structural analysis distinguishes lookalikes from
// legitimate domains, reproducibly and without external API calls.
//
// Reputation-driven detection (OpenPhish/PhishTank/GSB/VirusTotal floors) is
// evaluated separately against the live API; it is intentionally OUT of scope
// here so the score reflects the offline detector, not the upstream feeds.

import { isLegitDomain, normalizeInputUrl } from "@capstone/shared";
import type { RiskFactors } from "@capstone/shared";
import { inferBrandMatch } from "../services/brandMatcher.js";
import { buildLexicalSignals, buildMachineLearningSignals, computeThreatScore } from "../services/scoring.js";
import { EVAL_CORPUS, type EvalEntry, type EvalLabel } from "./corpus.js";

export type Verdict = "Safe" | "Low" | "Medium" | "High" | "Critical" | "Malicious";

export type EvalResult = {
  url: string;
  label: EvalLabel;
  group: string;
  note?: string;
  brand: string;
  method: string;
  confidence: number;
  isLegit: boolean;
  score: number;
  verdict: Verdict;
  flagged: boolean; // verdict >= High
  correct: boolean;
};

// A domain is "flagged" (predicted phishing) when the verdict is High or above
// — i.e. the threshold at which the real-time guard would warn the user.
function isFlagged(verdict: string): boolean {
  return verdict === "High" || verdict === "Critical" || verdict === "Malicious";
}

// Risk factors with every network-derived category blank — only the lexical and
// ML (lexical-derived) categories carry signal in the offline evaluation.
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
    behavioral: { keyboard_event_listeners: null, http_to_https_mismatch: null, external_form_action: null, cross_domain_redirect: null, client_side_redirect: null },
    email_auth: { spf_present: null, dkim_present: null, dmarc_present: null, spf_dkim_dmarc_missing: null },
    passive_history: { passive_dns_observed: null, passive_dns_notes: [], archive_first_seen_days: null, ownership_changes_detected: null },
    machine_learning: { brand_similarity_score: null, visual_similarity_score: null, url_entropy: null, time_based_risk: null }
  };
}

export async function evaluateDomain(entry: EvalEntry): Promise<EvalResult> {
  const normalized = normalizeInputUrl(entry.url);
  const brandMatch = await inferBrandMatch({
    analyzedUrl: normalized.normalizedUrl,
    normalizedDomain: normalized.registrableDomain,
    pageTitle: null,
    bodyText: "",
    skipLlm: true
  });

  const registrable = normalized.registrableDomain.toLowerCase();
  const isLegit =
    (brandMatch.method !== "unknown" && brandMatch.canonical_domain.toLowerCase() === registrable) ||
    isLegitDomain(registrable);

  const lexical = buildLexicalSignals({
    normalizedDomain: normalized.registrableDomain,
    punycodeHostname: normalized.punycodeHostname,
    isIdn: normalized.isIdn,
    tld: normalized.tld,
    isIpLiteral: normalized.isIpLiteral,
    brandMatch,
    isLegit
  });

  const riskFactors = blankRiskFactors();
  riskFactors.lexical = lexical;
  riskFactors.machine_learning = buildMachineLearningSignals({
    normalizedUrl: normalized.normalizedUrl,
    lexical,
    content: riskFactors.content,
    infrastructure: riskFactors.infrastructure
  });

  const { score, verdict } = computeThreatScore(riskFactors, {
    brandConfidence: brandMatch.confidence,
    registrableDomain: normalized.registrableDomain,
    isLegit
  });

  const flagged = isFlagged(verdict);
  const correct = entry.label === "phish" ? flagged : !flagged;

  return {
    url: entry.url,
    label: entry.label,
    group: entry.group,
    note: entry.note,
    brand: brandMatch.brand_name,
    method: brandMatch.method,
    confidence: brandMatch.confidence,
    isLegit,
    score,
    verdict: verdict as Verdict,
    flagged,
    correct
  };
}

export type EvalMetrics = {
  total: number;
  truePositive: number;
  falsePositive: number;
  trueNegative: number;
  falseNegative: number;
  precision: number;
  recall: number;
  f1: number;
  accuracy: number;
  falsePositiveRate: number;
  specificity: number;
  byGroup: Record<string, { total: number; correct: number }>;
  verdictHistogram: Record<string, number>;
  results: EvalResult[];
  misses: EvalResult[];
};

function ratio(numerator: number, denominator: number): number {
  return denominator === 0 ? 1 : Number((numerator / denominator).toFixed(4));
}

export async function runEvaluation(corpus: EvalEntry[] = EVAL_CORPUS): Promise<EvalMetrics> {
  const results = await Promise.all(corpus.map((entry) => evaluateDomain(entry)));

  let tp = 0;
  let fp = 0;
  let tn = 0;
  let fn = 0;
  const byGroup: Record<string, { total: number; correct: number }> = {};
  const verdictHistogram: Record<string, number> = {};

  for (const r of results) {
    if (r.label === "phish") {
      if (r.flagged) tp += 1;
      else fn += 1;
    } else {
      if (r.flagged) fp += 1;
      else tn += 1;
    }
    byGroup[r.group] ??= { total: 0, correct: 0 };
    byGroup[r.group].total += 1;
    if (r.correct) byGroup[r.group].correct += 1;
    verdictHistogram[r.verdict] = (verdictHistogram[r.verdict] ?? 0) + 1;
  }

  const precision = ratio(tp, tp + fp);
  const recall = ratio(tp, tp + fn);
  const f1 = precision + recall === 0 ? 0 : Number(((2 * precision * recall) / (precision + recall)).toFixed(4));

  return {
    total: results.length,
    truePositive: tp,
    falsePositive: fp,
    trueNegative: tn,
    falseNegative: fn,
    precision,
    recall,
    f1,
    accuracy: ratio(tp + tn, results.length),
    falsePositiveRate: ratio(fp, fp + tn),
    specificity: ratio(tn, tn + fp),
    byGroup,
    verdictHistogram,
    results,
    misses: results.filter((r) => !r.correct)
  };
}
