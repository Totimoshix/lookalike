import { z } from "zod";

export const analysisModeSchema = z.enum(["manual_entry"]);

export const verdictSchema = z.enum(["Safe", "Low", "Medium", "High", "Critical", "Malicious", "Unknown"]);

export const providerStatusSchema = z.enum(["ok", "not_configured", "query_failed", "unsupported"]);

export const signalDiagnosticSchema = z.object({
  signal: z.string(),
  provider: z.string(),
  status: providerStatusSchema,
  detail: z.string().optional()
});

export const providerReadinessSchema = z.object({
  provider: z.string(),
  signals: z.array(z.string()).default([]),
  status: providerStatusSchema,
  detail: z.string().nullable().optional()
});

export const signalSourceSchema = z.object({
  source: z.string(),
  status: z.enum(["ok", "partial", "unavailable"]),
  detail: z.string().optional()
});

export const brandMatchSchema = z.object({
  brand_name: z.string(),
  canonical_domain: z.string(),
  confidence: z.number().min(0).max(1),
  method: z.enum(["override", "catalog", "heuristic", "llm", "unknown"]),
  matched_keywords: z.array(z.string()).default([])
});

export const lexicalRiskSchema = z.object({
  is_homoglyph: z.boolean().nullable(),
  is_idn: z.boolean(),
  punycode_domain: z.string().nullable(),
  edit_distance_to_target: z.number().nullable(),
  levenshtein_distance: z.number().nullable(),
  damerau_levenshtein_distance: z.number().nullable(),
  jaro_winkler_similarity: z.number().nullable(),
  ngram_similarity: z.number().nullable(),
  typosquatting_type: z.string().nullable(),
  character_substitution_pattern: z.string().nullable(),
  keyboard_proximity_score: z.number().nullable(),
  dictionary_similarity_score: z.number().nullable(),
  length_difference: z.number().nullable(),
  tld_manipulation: z.boolean().nullable(),
  suspicious_tld: z.boolean().nullable(),
  tld_risk_score: z.number().nullable(),
  subdomain_structure_risk: z.number().nullable(),
  brand_keyword_detected: z.boolean().nullable(),
  suspicious_keywords: z.array(z.string()).default([]),
  hyphenation_pattern: z.string().nullable(),
  tokenization_pattern: z.string().nullable(),
  mixed_character_sets: z.boolean().nullable(),
  url_shortener_detected: z.boolean().nullable(),
  ip_literal_host: z.boolean().nullable()
});

export const infrastructureRiskSchema = z.object({
  domain_age_days: z.number().nullable(),
  registrar: z.string().nullable(),
  registrant_org: z.string().nullable(),
  registration_length_years: z.number().nullable(),
  whois_privacy: z.boolean().nullable(),
  hidden_ownership: z.boolean().nullable(),
  registrant_country: z.string().nullable(),
  ssl_valid: z.boolean().nullable(),
  ssl_error: z.string().nullable(),
  certificate_issuer: z.string().nullable(),
  certificate_reputation: z.string().nullable(),
  certificate_age_days: z.number().nullable(),
  certificate_domain_mismatch: z.boolean().nullable(),
  creation_date_anomaly: z.boolean().nullable(),
  mx_records_present: z.boolean().nullable(),
  dns_records: z.object({
    a: z.array(z.string()).default([]),
    mx: z.array(z.string()).default([]),
    txt: z.array(z.string()).default([]),
    ns: z.array(z.string()).default([])
  }),
  dns_history_changes: z.number().nullable(),
  fast_flux_detected: z.boolean().nullable(),
  ip_reputation_score: z.number().nullable(),
  hosting_asn: z.string().nullable(),
  hosting_asn_reputation: z.string().nullable(),
  shared_hosting_risk: z.boolean().nullable(),
  redirect_count: z.number().nullable(),
  final_url: z.string().nullable()
});

export const contentRiskSchema = z.object({
  page_title: z.string().nullable(),
  html_similarity_score: z.number().nullable(),
  logo_reuse_detected: z.boolean().nullable(),
  text_reuse_score: z.number().nullable(),
  credential_harvesting_detected: z.boolean().nullable(),
  forms_detected: z.number().nullable(),
  password_fields_detected: z.number().nullable(),
  form_submits_to_real_brand: z.boolean().nullable(),
  hidden_iframes: z.boolean().nullable(),
  obfuscated_javascript: z.boolean().nullable(),
  suspicious_script_patterns: z.array(z.string()).default([]),
  missing_security_headers: z.array(z.string()).default([]),
  server_header_exposure: z.string().nullable(),
  redirect_chain: z.array(z.string()).default([]),
  body_keywords: z.array(z.string()).default([])
});

export const reputationalRiskSchema = z.object({
  blacklisted_in_phishTank: z.boolean().nullable(),
  blacklisted_in_openPhish: z.boolean().nullable(),
  google_safe_browsing: z.boolean().nullable(),
  virus_total_detections: z.number().nullable(),
  abuse_ipdb_reports: z.number().nullable(),
  phishing_feed_hits: z.number().nullable()
});

export const behavioralRiskSchema = z.object({
  keyboard_event_listeners: z.boolean().nullable(),
  http_to_https_mismatch: z.boolean().nullable(),
  external_form_action: z.boolean().nullable()
});

export const emailAuthRiskSchema = z.object({
  spf_present: z.boolean().nullable(),
  dkim_present: z.boolean().nullable(),
  dmarc_present: z.boolean().nullable(),
  spf_dkim_dmarc_missing: z.boolean().nullable()
});

export const passiveHistoryRiskSchema = z.object({
  passive_dns_observed: z.boolean().nullable(),
  passive_dns_notes: z.array(z.string()).default([]),
  archive_first_seen_days: z.number().nullable(),
  ownership_changes_detected: z.boolean().nullable()
});

export const machineLearningRiskSchema = z.object({
  brand_similarity_score: z.number().nullable(),
  visual_similarity_score: z.number().nullable(),
  url_entropy: z.number().nullable(),
  time_based_risk: z.string().nullable()
});

export const riskFactorsSchema = z.object({
  lexical: lexicalRiskSchema,
  infrastructure: infrastructureRiskSchema,
  content: contentRiskSchema,
  reputational: reputationalRiskSchema,
  behavioral: behavioralRiskSchema,
  email_auth: emailAuthRiskSchema,
  passive_history: passiveHistoryRiskSchema,
  machine_learning: machineLearningRiskSchema
});

export const evidenceItemSchema = z.object({
  key: z.string(),
  label: z.string(),
  category: z.string(),
  severity: z.enum(["info", "low", "medium", "high", "critical"]),
  value: z.union([z.string(), z.number(), z.boolean(), z.null()]),
  note: z.string().optional()
});

export const evidenceSummarySchema = z.object({
  highlights: z.array(z.string()).default([]),
  evidence_items: z.array(evidenceItemSchema).default([]),
  signal_diagnostics: z.array(signalDiagnosticSchema).default([])
});

export const reportingContactsSchema = z.object({
  registrar_information: z.object({
    registrar_name: z.string().nullable(),
    abuse_contact: z.string().nullable(),
    abuse_portal: z.string().nullable(),
    whois_lookup_url: z.string().nullable()
  }),
  brand_protection: z.object({
    brand_contact: z.string().nullable(),
    cert_contact: z.string().nullable(),
    apwg_contact: z.string().nullable(),
    google_safe_browsing_report: z.string().nullable(),
    microsoft_submission: z.string().nullable()
  }),
  local_authorities: z.object({
    anti_fraud: z.string().nullable(),
    csirt: z.string().nullable()
  }),
  notes: z.array(z.string()).default([])
});

export const exportMetadataSchema = z.object({
  generated_at: z.string(),
  generated_by: z.string(),
  schema_version: z.string(),
  sources: z.array(signalSourceSchema).default([])
});

export const timingsSchema = z.object({
  total_ms: z.number(),
  fetch_ms: z.number().nullable(),
  enrichment_ms: z.number().nullable(),
  llm_ms: z.number().nullable()
});

export const analysisResultSchema = z.object({
  schema_version: z.literal("analysis-result.v2"),
  mode: analysisModeSchema,
  analyzed_url: z.string(),
  normalized_domain: z.string(),
  normalized_url: z.string(),
  brand_match: brandMatchSchema,
  threat_score: z.number().min(0).max(100),
  verdict: verdictSchema,
  reasoning: z.string(),
  risk_factors: riskFactorsSchema,
  evidence_summary: evidenceSummarySchema,
  reporting_contacts: reportingContactsSchema,
  signal_sources: z.array(signalSourceSchema).default([]),
  timings: timingsSchema,
  export_metadata: exportMetadataSchema,
  partial: z.boolean()
});

export const healthResponseSchema = z.object({
  ok: z.boolean(),
  service: z.string(),
  version: z.string(),
  stage: z.string(),
  region: z.string(),
  timestamp: z.string(),
  providers: z.array(providerReadinessSchema).default([])
});

export const analyzeRequestSchema = z.object({
  url: z.string().min(1),
  mode: analysisModeSchema.default("manual_entry"),
  brand_override: z.string().optional()
});

export const lookalikeCandidateSchema = z.object({
  candidate_domain: z.string(),
  pattern: z.string(),
  notes: z.array(z.string()).default([]),
  lexical_score: z.number().min(0).max(1)
});

export const lookalikeCandidateSetSchema = z.object({
  schema_version: z.literal("lookalike-candidates.v2"),
  canonical_domain: z.string(),
  brand_name: z.string().nullable(),
  generated_at: z.string(),
  source: z.literal("dnstwister"),
  candidates: z.array(lookalikeCandidateSchema)
});

export const generateLookalikesRequestSchema = z.object({
  canonical_domain: z.string().min(1),
  brand_name: z.string().optional(),
  limit: z.number().min(1).max(250).default(50)
});

export type AnalyzeRequest = z.infer<typeof analyzeRequestSchema>;
export type AnalysisResult = z.infer<typeof analysisResultSchema>;
export type BrandMatch = z.infer<typeof brandMatchSchema>;
export type GenerateLookalikesRequest = z.infer<typeof generateLookalikesRequestSchema>;
export type LookalikeCandidate = z.infer<typeof lookalikeCandidateSchema>;
export type LookalikeCandidateSet = z.infer<typeof lookalikeCandidateSetSchema>;
export type RiskFactors = z.infer<typeof riskFactorsSchema>;
export type ReportingContacts = z.infer<typeof reportingContactsSchema>;
export type SignalSource = z.infer<typeof signalSourceSchema>;
export type SignalDiagnostic = z.infer<typeof signalDiagnosticSchema>;
export type ProviderReadiness = z.infer<typeof providerReadinessSchema>;
export type EvidenceSummary = z.infer<typeof evidenceSummarySchema>;
export type HealthResponse = z.infer<typeof healthResponseSchema>;
