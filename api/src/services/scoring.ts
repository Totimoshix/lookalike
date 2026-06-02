import {
  baseDomainLabel,
  classifyTyposquatting,
  damerauLevenshtein,
  detectHomoglyphPattern,
  hyphenationPattern,
  isHomoglyphDomain,
  isSharedHost,
  isSuspiciousTld,
  jaroWinkler,
  keyboardProximityScore,
  levenshtein,
  ngramSimilarity,
  safeNumber,
  STUFFING_WORDS,
  suspiciousKeywordsInDomain,
  tokenizationPattern,
  urlEntropy
} from "@capstone/shared";
import type { AnalysisResult, BrandMatch, RiskFactors, SignalDiagnostic } from "@capstone/shared";

function toPercentage(value: number): number {
  return Math.max(0, Math.min(100, Math.round(value)));
}

export function buildLexicalSignals(input: {
  normalizedDomain: string;
  punycodeHostname: string | null;
  isIdn: boolean;
  tld: string | null;
  isIpLiteral: boolean;
  brandMatch: BrandMatch;
  isLegit?: boolean;
}): RiskFactors["lexical"] {
  const sourceLabel = baseDomainLabel(input.normalizedDomain);
  const suspiciousKeywords = suspiciousKeywordsInDomain(input.normalizedDomain);
  // A legitimate domain (it IS the brand's canonical domain, or a top-10k site)
  // cannot be a lookalike of itself — comparing its label to the brand's own
  // label yields jaro=1.0 and spurious homoglyph hits. Treat it as having no
  // target brand so all lookalike/similarity signals stay null.
  const hasTargetBrand =
    input.brandMatch.method !== "unknown" && input.brandMatch.confidence > 0 && input.isLegit !== true;

  if (!hasTargetBrand) {
    return {
      is_homoglyph: null,
      is_idn: input.isIdn,
      punycode_domain: input.punycodeHostname,
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
      suspicious_tld: isSuspiciousTld(input.tld),
      tld_risk_score: input.tld ? (isSuspiciousTld(input.tld) ? 0.82 : 0.15) : null,
      subdomain_structure_risk: input.normalizedDomain.split(".").length > 3 ? 0.66 : 0.18,
      brand_keyword_detected: suspiciousKeywords.length > 0,
      suspicious_keywords: suspiciousKeywords,
      hyphenation_pattern: hyphenationPattern(input.normalizedDomain),
      tokenization_pattern: tokenizationPattern(input.normalizedDomain),
      mixed_character_sets: /[a-z]/i.test(sourceLabel) && /[0-9]/.test(sourceLabel),
      url_shortener_detected: /bit\.ly|tinyurl|lnkd\.in|t\.co/i.test(input.normalizedDomain),
      ip_literal_host: input.isIpLiteral
    };
  }

  const targetLabel = baseDomainLabel(input.brandMatch.canonical_domain);

  return {
    is_homoglyph: isHomoglyphDomain(sourceLabel, targetLabel),
    is_idn: input.isIdn,
    punycode_domain: input.punycodeHostname,
    edit_distance_to_target: levenshtein(sourceLabel, targetLabel),
    levenshtein_distance: levenshtein(sourceLabel, targetLabel),
    damerau_levenshtein_distance: damerauLevenshtein(sourceLabel, targetLabel),
    jaro_winkler_similarity: Number(jaroWinkler(sourceLabel, targetLabel).toFixed(3)),
    ngram_similarity: Number(ngramSimilarity(sourceLabel, targetLabel).toFixed(3)),
    typosquatting_type:
      // When the brand resolver flagged stuffing tokens (e.g. "payment-" or
      // "-login" wrapped around a real brand label), surface that here so the
      // evidence panel and plain-language reasons explain the attack pattern.
      input.brandMatch.matched_keywords.some((kw) =>
        STUFFING_WORDS.has(kw.toLowerCase())
      )
        ? "keyword_stuffing"
        : classifyTyposquatting(sourceLabel, targetLabel),
    character_substitution_pattern: detectHomoglyphPattern(sourceLabel, targetLabel),
    keyboard_proximity_score: keyboardProximityScore(sourceLabel, targetLabel),
    dictionary_similarity_score: Number(jaroWinkler(sourceLabel, targetLabel).toFixed(3)),
    length_difference: Math.abs(sourceLabel.length - targetLabel.length),
    tld_manipulation:
      input.tld !== null &&
      input.brandMatch.canonical_domain.split(".").slice(1).join(".").toLowerCase() !== input.tld.toLowerCase(),
    suspicious_tld: isSuspiciousTld(input.tld),
    tld_risk_score: input.tld ? (isSuspiciousTld(input.tld) ? 0.82 : 0.15) : null,
    subdomain_structure_risk: input.normalizedDomain.split(".").length > 3 ? 0.66 : 0.18,
    brand_keyword_detected: suspiciousKeywords.length > 0,
    suspicious_keywords: suspiciousKeywords,
    hyphenation_pattern: hyphenationPattern(input.normalizedDomain),
    tokenization_pattern: tokenizationPattern(input.normalizedDomain),
    mixed_character_sets: /[a-z]/i.test(sourceLabel) && /[0-9]/.test(sourceLabel),
    url_shortener_detected: /bit\.ly|tinyurl|lnkd\.in|t\.co/i.test(input.normalizedDomain),
    ip_literal_host: input.isIpLiteral
  };
}

function categoryScore(values: Array<number | null | boolean>, weights: number[]): number {
  let numerator = 0;
  let denominator = 0;

  values.forEach((value, index) => {
    const weight = weights[index] ?? 1;
    if (value === null || value === undefined) {
      return;
    }
    const numeric = typeof value === "boolean" ? (value ? 1 : 0) : value;
    numerator += numeric * weight;
    denominator += weight;
  });

  return denominator === 0 ? 0 : numerator / denominator;
}

export function computeThreatScore(
  riskFactors: RiskFactors,
  opts?: { brandConfidence?: number; registrableDomain?: string; isLegit?: boolean; crossDomainRedirect?: boolean }
): { score: number; verdict: AnalysisResult["verdict"] } {
  const lexicalScore = categoryScore(
    [
      riskFactors.lexical.is_homoglyph,
      riskFactors.lexical.is_idn,
      riskFactors.lexical.jaro_winkler_similarity,
      riskFactors.lexical.tld_manipulation,
      riskFactors.lexical.suspicious_tld,
      riskFactors.lexical.subdomain_structure_risk,
      riskFactors.lexical.brand_keyword_detected,
      riskFactors.lexical.mixed_character_sets,
      riskFactors.lexical.url_shortener_detected,
      riskFactors.lexical.ip_literal_host
    ],
    [1.2, 0.7, 1.4, 0.8, 0.8, 0.6, 0.4, 0.5, 0.4, 0.5]
  );

  const infrastructureScore = categoryScore(
    [
      riskFactors.infrastructure.domain_age_days !== null
        ? Math.max(0, 1 - Math.min(riskFactors.infrastructure.domain_age_days, 365) / 365)
        : null,
      riskFactors.infrastructure.whois_privacy,
      riskFactors.infrastructure.hidden_ownership,
      riskFactors.infrastructure.ssl_valid === null ? null : !riskFactors.infrastructure.ssl_valid,
      riskFactors.infrastructure.certificate_domain_mismatch,
      riskFactors.infrastructure.fast_flux_detected,
      riskFactors.infrastructure.shared_hosting_risk
    ],
    [1.1, 0.5, 0.8, 1.0, 0.8, 0.6, 0.4]
  );

  const contentScore = categoryScore(
    [
      riskFactors.content.credential_harvesting_detected,
      riskFactors.content.form_submits_to_real_brand,
      riskFactors.content.hidden_iframes,
      riskFactors.content.obfuscated_javascript,
      riskFactors.content.forms_detected !== null ? Math.min(1, riskFactors.content.forms_detected / 3) : null,
      riskFactors.content.password_fields_detected !== null ? Math.min(1, riskFactors.content.password_fields_detected / 2) : null,
      riskFactors.content.html_similarity_score,
      riskFactors.content.logo_reuse_detected
    ],
    [1.3, 1.1, 0.6, 0.8, 0.4, 0.6, 0.8, 0.6]
  );

  const reputationScore = categoryScore(
    [
      riskFactors.reputational.google_safe_browsing,
      riskFactors.reputational.blacklisted_in_openPhish,
      riskFactors.reputational.blacklisted_in_phishTank,
      riskFactors.reputational.phishing_feed_hits !== null
        ? Math.min(1, riskFactors.reputational.phishing_feed_hits)
        : null,
      riskFactors.reputational.virus_total_detections !== null
        ? Math.min(1, riskFactors.reputational.virus_total_detections / 25)
        : null,
      riskFactors.reputational.abuse_ipdb_reports !== null
        ? Math.min(1, riskFactors.reputational.abuse_ipdb_reports / 75)
        : null
    ],
    [1.2, 1, 1, 1, 0.8, 0.6]
  );

  const behavioralScore = categoryScore(
    [
      riskFactors.behavioral.keyboard_event_listeners,
      riskFactors.behavioral.http_to_https_mismatch,
      riskFactors.behavioral.external_form_action,
      riskFactors.behavioral.cross_domain_redirect,
      riskFactors.behavioral.client_side_redirect
    ],
    [0.8, 0.6, 0.9, 1.0, 0.6]
  );

  const emailAuthScore = categoryScore(
    [riskFactors.email_auth.spf_dkim_dmarc_missing],
    [0.5]
  );

  const passiveHistoryScore = categoryScore(
    [
      riskFactors.passive_history.passive_dns_observed,
      riskFactors.passive_history.archive_first_seen_days !== null
        ? Math.max(0, 1 - Math.min(riskFactors.passive_history.archive_first_seen_days, 3650) / 3650)
        : null,
      riskFactors.passive_history.ownership_changes_detected
    ],
    [0.5, 0.9, 0.6]
  );

  const machineLearningScore = categoryScore(
    [riskFactors.machine_learning.brand_similarity_score, riskFactors.machine_learning.visual_similarity_score],
    [0.7, 0.5]
  );

  const weightedScore =
    lexicalScore * 0.24 +
    infrastructureScore * 0.18 +
    contentScore * 0.19 +
    reputationScore * 0.18 +
    behavioralScore * 0.07 +
    emailAuthScore * 0.05 +
    passiveHistoryScore * 0.04 +
    machineLearningScore * 0.05;

  let criticalBoost = 0;
  if (riskFactors.content.credential_harvesting_detected && riskFactors.content.form_submits_to_real_brand) {
    criticalBoost += 0.05;
  }
  if (riskFactors.reputational.google_safe_browsing) {
    criticalBoost += 0.03;
  }
  if (riskFactors.infrastructure.domain_age_days !== null && riskFactors.infrastructure.domain_age_days < 7) {
    criticalBoost += 0.02;
  }

  const weighted = toPercentage(Math.min(1, weightedScore + criticalBoost) * 100);

  // Verdict floors. The weighted blend above under-counts authoritative
  // signals: a confirmed blacklist hit only nudges an 18%-weighted, internally
  // averaged category, so known phishing can land in "Low". These floors give
  // a guaranteed MINIMUM score when a high-confidence indicator is present —
  // they only ever raise the score, never lower it. Favour catching phishing.
  const rep = riskFactors.reputational;
  const content = riskFactors.content;
  const lexical = riskFactors.lexical;
  const brandConfidence = opts?.brandConfidence ?? 0;
  const onSharedHost = isSharedHost(opts?.registrableDomain);
  // A legitimate domain (its own canonical, or a top-10k site) is never a
  // lookalike — never apply the brand-similarity floors to it. Reputation
  // floors below still apply so a compromised legit domain can be flagged.
  const isLegit = opts?.isLegit === true;

  let floor = 0;
  // Google Safe Browsing is authoritative → treat as malicious.
  if (rep.google_safe_browsing === true) {
    floor = Math.max(floor, 90);
  }
  // Curated phishing feeds (OpenPhish / PhishTank) — confirmed phishing.
  if (
    rep.blacklisted_in_openPhish === true ||
    rep.blacklisted_in_phishTank === true ||
    (rep.phishing_feed_hits ?? 0) > 0
  ) {
    floor = Math.max(floor, 80);
  }
  // Multiple AV engines flagging it.
  if ((rep.virus_total_detections ?? 0) >= 3) {
    floor = Math.max(floor, 70);
  }
  // Credential harvesting that posts to the real brand's domain.
  if (content.credential_harvesting_detected === true && content.form_submits_to_real_brand === true) {
    floor = Math.max(floor, 70);
  }
  // Confident lookalike of a known brand (homoglyph / keyword-stuffing / very
  // high string similarity) — high risk even if the page never resolved.
  // Skipped for legitimate domains (a real site is not a lookalike of itself).
  if (
    !isLegit &&
    brandConfidence >= 0.85 &&
    (lexical.is_homoglyph === true ||
      lexical.typosquatting_type === "keyword_stuffing" ||
      (lexical.jaro_winkler_similarity ?? 0) >= 0.9)
  ) {
    floor = Math.max(floor, 65);
  }
  // Credential-harvesting page hosted on a shared host (blogspot, ipfs, …),
  // where the benign parent domain would otherwise mask the threat.
  if (onSharedHost && content.credential_harvesting_detected === true) {
    floor = Math.max(floor, 65);
  }
  // Off-domain redirect (HTTP / meta / JS) from a non-legitimate source domain
  // to an unrelated registrable domain — classic cloaking. Legit/allowlisted
  // sources legitimately redirect (apex→www, vanity domains) so they're exempt.
  if (!isLegit && (opts?.crossDomainRedirect === true || riskFactors.behavioral.cross_domain_redirect === true)) {
    floor = Math.max(floor, 65);
  }

  const score = Math.max(weighted, floor);

  if (score >= 90) {
    return { score, verdict: "Malicious" };
  }
  if (score >= 75) {
    return { score, verdict: "Critical" };
  }
  if (score >= 60) {
    return { score, verdict: "High" };
  }
  if (score >= 35) {
    return { score, verdict: "Medium" };
  }
  if (score >= 15) {
    return { score, verdict: "Low" };
  }
  return { score, verdict: "Safe" };
}

export function buildMachineLearningSignals(input: {
  normalizedUrl: string;
  lexical: RiskFactors["lexical"];
  content: RiskFactors["content"];
  infrastructure: RiskFactors["infrastructure"];
}): RiskFactors["machine_learning"] {
  const brandSimilarity = Math.max(
    safeNumber(input.lexical.jaro_winkler_similarity),
    safeNumber(input.lexical.ngram_similarity)
  );

  return {
    brand_similarity_score: Number(brandSimilarity.toFixed(3)),
    visual_similarity_score:
      input.content.logo_reuse_detected || (input.content.html_similarity_score ?? 0) > 0.55
        ? Number(Math.max(safeNumber(input.content.html_similarity_score), 0.65).toFixed(3))
        : Number(Math.max(safeNumber(input.content.html_similarity_score), 0.12).toFixed(3)),
    url_entropy: urlEntropy(input.normalizedUrl),
    time_based_risk:
      input.infrastructure.domain_age_days !== null && input.infrastructure.domain_age_days < 14
        ? "recent_registration"
        : "stable_registration"
  };
}

export function buildEvidenceSummary(result: {
  riskFactors: RiskFactors;
  threatScore: number;
  verdict: AnalysisResult["verdict"];
  signalDiagnostics: SignalDiagnostic[];
}) {
  const highlights: string[] = [];
  const evidenceItems: AnalysisResult["evidence_summary"]["evidence_items"] = [];

  const addEvidence = (
    key: string,
    label: string,
    category: string,
    severity: "info" | "low" | "medium" | "high" | "critical",
    value: string | number | boolean | null,
    note?: string
  ) => {
    evidenceItems.push({ key, label, category, severity, value, note });
  };

  if (result.riskFactors.lexical.is_homoglyph) {
    highlights.push("Lookalike character substitution detected in the domain label.");
    addEvidence("homoglyph", "Homoglyph detected", "lexical", "high", true);
  }

  if (result.riskFactors.lexical.typosquatting_type === "keyword_stuffing") {
    highlights.push("Domain combines a phishing word with a real brand name.");
    addEvidence(
      "keyword_stuffing",
      "Keyword stuffing detected",
      "lexical",
      "high",
      true
    );
  }

  if (result.riskFactors.infrastructure.domain_age_days !== null && result.riskFactors.infrastructure.domain_age_days < 30) {
    highlights.push("Domain is recently registered, which increases phishing risk.");
    addEvidence(
      "domain_age",
      "Domain age (days)",
      "infrastructure",
      "high",
      result.riskFactors.infrastructure.domain_age_days
    );
  }

  if (result.riskFactors.content.credential_harvesting_detected) {
    highlights.push("Page contains credential collection elements such as password fields in forms.");
    addEvidence("credential_form", "Credential harvesting indicators", "content", "critical", true);
  }

  if (result.riskFactors.content.form_submits_to_real_brand) {
    highlights.push("Form action references the legitimate brand, a strong phishing signal.");
    addEvidence("form_action", "Form submits to brand domain", "content", "critical", true);
  }

  if (result.riskFactors.reputational.google_safe_browsing) {
    highlights.push("URL matched Google Safe Browsing threat intelligence.");
    addEvidence("gsb", "Google Safe Browsing match", "reputation", "critical", true);
  }

  if ((result.riskFactors.reputational.phishing_feed_hits ?? 0) > 0) {
    highlights.push("The domain matched one or more public phishing feeds.");
    addEvidence(
      "phishing_feed_hits",
      "Public phishing feed hits",
      "reputation",
      "critical",
      result.riskFactors.reputational.phishing_feed_hits
    );
  }

  if (result.riskFactors.infrastructure.ssl_valid === false) {
    addEvidence(
      "ssl_valid",
      "TLS certificate valid",
      "infrastructure",
      "medium",
      false,
      result.riskFactors.infrastructure.ssl_error ?? undefined
    );
  }

  if (result.riskFactors.email_auth.spf_dkim_dmarc_missing === true) {
    addEvidence("email_auth", "Email authentication missing", "email_auth", "medium", true);
  }

  if (result.riskFactors.behavioral.external_form_action) {
    addEvidence("external_form_action", "Form posts to an external destination", "behavioral", "high", true);
  }

  if (result.riskFactors.behavioral.cross_domain_redirect) {
    highlights.push("The site redirects to an unrelated domain — a common cloaking tactic.");
    const dest = result.riskFactors.infrastructure.final_url ?? null;
    addEvidence("redirect_offdomain", "Redirects to an unrelated domain", "behavioral", "high", true, dest ?? undefined);
  }

  if (result.riskFactors.behavioral.client_side_redirect) {
    addEvidence("client_side_redirect", "Hidden script/meta redirect detected", "behavioral", "medium", true);
  }

  if (
    result.riskFactors.passive_history.archive_first_seen_days !== null &&
    result.riskFactors.passive_history.archive_first_seen_days < 30
  ) {
    addEvidence(
      "archive_first_seen",
      "Archive first seen (days)",
      "passive_history",
      "medium",
      result.riskFactors.passive_history.archive_first_seen_days
    );
  }

  if (result.riskFactors.passive_history.passive_dns_notes.length > 0) {
    addEvidence(
      "passive_history_notes",
      "Passive history observations",
      "passive_history",
      "info",
      result.riskFactors.passive_history.passive_dns_notes.length,
      result.riskFactors.passive_history.passive_dns_notes[0]
    );
  }

  if (highlights.length === 0) {
    highlights.push(`Overall verdict is ${result.verdict} with a score of ${result.threatScore}/100.`);
  }

  return {
    highlights,
    evidence_items: evidenceItems,
    signal_diagnostics: result.signalDiagnostics
  };
}
