import {
  analysisResultSchema,
  normalizeInputUrl,
  type AnalyzeRequest,
  type AnalysisResult,
  type RiskFactors,
  type SignalDiagnostic
} from "@capstone/shared";
import { inferBrandMatch } from "./brandMatcher.js";
import { collectReputationSignals } from "./reputation.js";
import { buildEvidenceSummary, buildLexicalSignals, buildMachineLearningSignals, computeThreatScore } from "./scoring.js";

const REPUTATION_BUDGET_MS = 2000;

function emptyInfrastructure(): RiskFactors["infrastructure"] {
  return {
    domain_age_days: null,
    registrar: null,
    registrant_org: null,
    registration_length_years: null,
    whois_privacy: null,
    hidden_ownership: null,
    registrant_country: null,
    ssl_valid: null,
    ssl_error: null,
    certificate_issuer: null,
    certificate_reputation: null,
    certificate_age_days: null,
    certificate_domain_mismatch: null,
    creation_date_anomaly: null,
    mx_records_present: null,
    dns_records: { a: [], mx: [], txt: [], ns: [] },
    dns_history_changes: null,
    fast_flux_detected: null,
    ip_reputation_score: null,
    hosting_asn: null,
    hosting_asn_reputation: null,
    shared_hosting_risk: null,
    redirect_count: null,
    final_url: null
  };
}

function emptyContent(): RiskFactors["content"] {
  return {
    page_title: null,
    html_similarity_score: null,
    logo_reuse_detected: null,
    text_reuse_score: null,
    credential_harvesting_detected: null,
    forms_detected: null,
    password_fields_detected: null,
    form_submits_to_real_brand: null,
    hidden_iframes: null,
    obfuscated_javascript: null,
    suspicious_script_patterns: [],
    missing_security_headers: [],
    server_header_exposure: null,
    redirect_chain: [],
    body_keywords: []
  };
}

function emptyReputation(): RiskFactors["reputational"] {
  return {
    blacklisted_in_phishTank: null,
    blacklisted_in_openPhish: null,
    google_safe_browsing: null,
    virus_total_detections: null,
    abuse_ipdb_reports: null,
    phishing_feed_hits: null
  };
}

function withTimeout<T>(promise: Promise<T>, fallback: T, ms: number): Promise<T> {
  return new Promise((resolve) => {
    const timer = setTimeout(() => resolve(fallback), ms);
    promise
      .then((value) => {
        clearTimeout(timer);
        resolve(value);
      })
      .catch(() => {
        clearTimeout(timer);
        resolve(fallback);
      });
  });
}

export async function analyzeUrlFast(request: AnalyzeRequest): Promise<AnalysisResult> {
  const startedAt = Date.now();
  const normalized = normalizeInputUrl(request.url);

  const brandMatch = await inferBrandMatch({
    analyzedUrl: normalized.normalizedUrl,
    normalizedDomain: normalized.registrableDomain,
    pageTitle: null,
    bodyText: "",
    brandOverride: request.brand_override,
    skipLlm: true
  });

  const reputationFallback = {
    reputational: emptyReputation(),
    diagnostics: [
      {
        signal: "reputation",
        provider: "reputation",
        status: "query_failed" as const,
        detail: "Fast-path reputation budget exceeded."
      }
    ]
  };

  const reputationResult = await withTimeout(
    collectReputationSignals(normalized.normalizedUrl, null),
    reputationFallback,
    REPUTATION_BUDGET_MS
  );

  const lexical = buildLexicalSignals({
    normalizedDomain: normalized.registrableDomain,
    punycodeHostname: normalized.punycodeHostname,
    isIdn: normalized.isIdn,
    tld: normalized.tld,
    isIpLiteral: normalized.isIpLiteral,
    brandMatch
  });

  const infrastructure = emptyInfrastructure();
  const content = emptyContent();

  const emailAuth: RiskFactors["email_auth"] = {
    spf_present: null,
    dkim_present: null,
    dmarc_present: null,
    spf_dkim_dmarc_missing: null
  };

  const behavioral: RiskFactors["behavioral"] = {
    keyboard_event_listeners: null,
    http_to_https_mismatch: null,
    external_form_action: null
  };

  const machineLearning = buildMachineLearningSignals({
    normalizedUrl: normalized.normalizedUrl,
    lexical,
    content,
    infrastructure
  });

  const riskFactors: RiskFactors = {
    lexical,
    infrastructure,
    content,
    reputational: reputationResult.reputational,
    behavioral,
    email_auth: emailAuth,
    passive_history: {
      passive_dns_observed: null,
      passive_dns_notes: [],
      archive_first_seen_days: null,
      ownership_changes_detected: null
    },
    machine_learning: machineLearning
  };

  const { score, verdict } = computeThreatScore(riskFactors);

  const diagnostics: SignalDiagnostic[] = [
    {
      signal: "fast_path",
      provider: "fast_orchestrator",
      status: "ok",
      detail: "Skipped page fetch, WHOIS, DNS, and LLM enrichment."
    },
    ...reputationResult.diagnostics
  ];

  const evidenceSummary = buildEvidenceSummary({
    riskFactors,
    threatScore: score,
    verdict,
    signalDiagnostics: diagnostics
  });

  const brandLabel =
    brandMatch.method === "unknown"
      ? `No confident target brand match was identified for ${normalized.registrableDomain}`
      : `Evaluated against ${brandMatch.brand_name} (${brandMatch.canonical_domain})`;
  const reasoning = `${brandLabel}. Fast-path verdict ${verdict} (${score}/100) based on lexical and reputation signals only. Full analysis available via the popup.`;

  return analysisResultSchema.parse({
    schema_version: "analysis-result.v2",
    mode: request.mode,
    analyzed_url: request.url,
    normalized_domain: normalized.registrableDomain,
    normalized_url: normalized.normalizedUrl,
    brand_match: brandMatch,
    threat_score: score,
    verdict,
    reasoning,
    risk_factors: riskFactors,
    evidence_summary: {
      ...evidenceSummary,
      signal_diagnostics: diagnostics
    },
    reporting_contacts: {
      registrar_information: {
        registrar_name: null,
        abuse_contact: null,
        abuse_portal: null,
        whois_lookup_url: null
      },
      brand_protection: {
        brand_contact: null,
        cert_contact: null,
        apwg_contact: null,
        google_safe_browsing_report: null,
        microsoft_submission: null
      },
      local_authorities: {
        anti_fraud: null,
        csirt: null,
        csirt_name: null,
        csirt_country: null,
        csirt_portal: null
      },
      notes: []
    },
    signal_sources: [],
    timings: {
      total_ms: Date.now() - startedAt,
      fetch_ms: null,
      enrichment_ms: Date.now() - startedAt,
      llm_ms: null
    },
    export_metadata: {
      generated_at: new Date().toISOString(),
      generated_by: "Capstone Domain Guardian (fast path)",
      schema_version: "analysis-result.v2",
      sources: []
    },
    partial: true
  });
}
