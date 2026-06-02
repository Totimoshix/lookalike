import { normalizeInputUrl, type AnalysisResult } from "@capstone/shared";
import { analyzeDomainFast } from "../lib/api";
import {
  addSessionBypass,
  getCachedAnalysis,
  getRealtimeProtection,
  getSessionBypass,
  getTrustedDomains,
  putPendingWarning,
  setCachedAnalysis,
  type CachedAnalysis
} from "../lib/storage";
import { isAllowlisted } from "./allowlist";

const BLOCKING_VERDICTS = new Set<AnalysisResult["verdict"]>(["High", "Critical", "Malicious"]);

function makeUuid(): string {
  if (typeof crypto !== "undefined" && typeof crypto.randomUUID === "function") {
    return crypto.randomUUID();
  }
  return `${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 10)}`;
}

function isInternalUrl(url: string): boolean {
  if (!url) return true;
  if (!/^https?:\/\//i.test(url)) return true;
  const ourPrefix = typeof chrome !== "undefined" ? chrome.runtime?.getURL?.("") : "";
  if (ourPrefix && url.startsWith(ourPrefix)) return true;
  return false;
}

async function redirectTabToWarning(tabId: number, originalUrl: string, result: AnalysisResult) {
  const id = makeUuid();
  await putPendingWarning(id, result);
  const params = new URLSearchParams({
    id,
    originalUrl,
    verdict: result.verdict,
    score: String(result.threat_score),
    domain: result.normalized_domain
  });
  const warningUrl = `${chrome.runtime.getURL("warning.html")}?${params.toString()}`;
  try {
    await chrome.tabs.update(tabId, { url: warningUrl });
  } catch {
    // Tab may have closed already — nothing to do.
  }
}

function cachedToResult(cached: CachedAnalysis, fallbackUrl: string): AnalysisResult {
  return {
    schema_version: "analysis-result.v2",
    mode: "manual_entry",
    analyzed_url: cached.normalized_url || fallbackUrl,
    normalized_domain: cached.normalized_url
      ? new URL(cached.normalized_url).hostname
      : fallbackUrl,
    normalized_url: cached.normalized_url || fallbackUrl,
    brand_match: cached.brand_match,
    threat_score: cached.threat_score,
    verdict: cached.verdict,
    reasoning: cached.reasoning,
    risk_factors: {
      lexical: {
        is_homoglyph: null,
        is_idn: false,
        punycode_domain: null,
        edit_distance_to_target: null,
        levenshtein_distance: null,
        damerau_levenshtein_distance: null,
        jaro_winkler_similarity: null,
        ngram_similarity: null,
        typosquatting_type: null,
        character_substitution_pattern: null,
        keyboard_proximity_score: null,
        dictionary_similarity_score: null,
        length_difference: null,
        tld_manipulation: null,
        suspicious_tld: null,
        tld_risk_score: null,
        subdomain_structure_risk: 0,
        brand_keyword_detected: null,
        suspicious_keywords: [],
        hyphenation_pattern: null,
        tokenization_pattern: null,
        mixed_character_sets: null,
        url_shortener_detected: null,
        ip_literal_host: null
      },
      infrastructure: {
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
      },
      content: {
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
      },
      reputational: {
        blacklisted_in_phishTank: null,
        blacklisted_in_openPhish: null,
        google_safe_browsing: null,
        virus_total_detections: null,
        abuse_ipdb_reports: null,
        phishing_feed_hits: null
      },
      behavioral: {
        keyboard_event_listeners: null,
        http_to_https_mismatch: null,
        external_form_action: null,
        cross_domain_redirect: null,
        client_side_redirect: null
      },
      email_auth: {
        spf_present: null,
        dkim_present: null,
        dmarc_present: null,
        spf_dkim_dmarc_missing: null
      },
      passive_history: {
        passive_dns_observed: null,
        passive_dns_notes: [],
        archive_first_seen_days: null,
        ownership_changes_detected: null
      },
      machine_learning: {
        brand_similarity_score: null,
        visual_similarity_score: null,
        url_entropy: null,
        time_based_risk: null
      }
    },
    evidence_summary: cached.evidence_summary,
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
    timings: { total_ms: 0, fetch_ms: null, enrichment_ms: null, llm_ms: null },
    export_metadata: {
      generated_at: new Date().toISOString(),
      generated_by: "Capstone Domain Guardian (cache replay)",
      schema_version: "analysis-result.v2",
      sources: []
    },
    partial: true
  };
}

export async function handleNavigation(details: { tabId: number; url: string; frameId: number }) {
  if (details.frameId !== 0) return;
  if (isInternalUrl(details.url)) return;

  if (!(await getRealtimeProtection())) return;

  let normalizedDomain: string;
  try {
    normalizedDomain = normalizeInputUrl(details.url).registrableDomain;
  } catch {
    return;
  }
  if (!normalizedDomain) return;

  if (isAllowlisted(normalizedDomain)) return;

  const trusted = await getTrustedDomains();
  if (trusted.has(normalizedDomain.toLowerCase())) return;

  const sessionBypass = await getSessionBypass();
  if (sessionBypass.has(normalizedDomain.toLowerCase())) return;

  const cached = await getCachedAnalysis(normalizedDomain);
  if (cached) {
    if (BLOCKING_VERDICTS.has(cached.verdict)) {
      await redirectTabToWarning(details.tabId, details.url, cachedToResult(cached, details.url));
    }
    return;
  }

  let result: AnalysisResult;
  try {
    result = await analyzeDomainFast({ url: details.url, mode: "manual_entry" });
  } catch (error) {
    console.warn("[DomainGuardian] fast analysis failed", error);
    return;
  }

  await setCachedAnalysis(normalizedDomain, result);

  if (BLOCKING_VERDICTS.has(result.verdict)) {
    await redirectTabToWarning(details.tabId, details.url, result);
  }
}

export async function bypassDomainForSession(domain: string) {
  await addSessionBypass(domain);
}
