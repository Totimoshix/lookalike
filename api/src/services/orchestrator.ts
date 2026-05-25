import {
  analysisResultSchema,
  normalizeInputUrl,
  type AnalyzeRequest,
  type AnalysisResult,
  type GenerateLookalikesRequest,
  type LookalikeCandidateSet,
  type RiskFactors,
  type SignalDiagnostic,
  type SignalSource
} from "@capstone/shared";
import { brandCatalog } from "../data/brandCatalog.js";
import { buildAnalystExplanationPrompt } from "../prompts/analystExplanation.js";
import { inferBrandMatch } from "./brandMatcher.js";
import { callBedrockJson } from "./bedrock.js";
import { AnalysisCache } from "./cache.js";
import { analyzePageContent } from "./contentAnalysis.js";
import { fetchDnsTwisterLookalikes } from "./dnsTwister.js";
import { collectInfrastructureSignals } from "./domainIntelligence.js";
import { fetchPage } from "./pageFetcher.js";
import { collectPassiveHistorySignals } from "./historySignals.js";
import { collectReputationSignals } from "./reputation.js";
import { buildReportingContacts } from "./reportingContacts.js";
import {
  buildEvidenceSummary,
  buildLexicalSignals,
  buildMachineLearningSignals,
  computeThreatScore
} from "./scoring.js";

const cache = new AnalysisCache();

function mergeSignalSources(diagnostics: SignalDiagnostic[]): SignalSource[] {
  const grouped = new Map<string, SignalSource>();

  const statusRank: Record<SignalDiagnostic["status"], number> = {
    ok: 0,
    not_configured: 1,
    unsupported: 2,
    query_failed: 3
  };

  for (const diagnostic of diagnostics) {
    const existing = grouped.get(diagnostic.provider);
    const mappedStatus: SignalSource["status"] =
      diagnostic.status === "ok"
        ? "ok"
        : diagnostic.status === "unsupported"
          ? "unavailable"
          : "partial";

    if (!existing) {
      grouped.set(diagnostic.provider, {
        source: diagnostic.provider,
        status: mappedStatus,
        detail: diagnostic.detail
      });
      continue;
    }

    const currentRank =
      statusRank[
        existing.status === "ok"
          ? "ok"
          : existing.status === "unavailable"
            ? "unsupported"
            : "query_failed"
      ];

    if (statusRank[diagnostic.status] > currentRank) {
      existing.status = mappedStatus;
    }

    if (diagnostic.detail) {
      existing.detail = existing.detail ? `${existing.detail}; ${diagnostic.detail}` : diagnostic.detail;
    }
  }

  return Array.from(grouped.values());
}

export async function analyzeUrl(request: AnalyzeRequest): Promise<AnalysisResult> {
  const normalized = normalizeInputUrl(request.url);
  const cacheKey = JSON.stringify({
    schema_version: "analysis-result.v2",
    url: normalized.normalizedUrl,
    brand_override: request.brand_override ?? null
  });
  const cached = await cache.get(cacheKey);
  if (cached) {
    return cached;
  }

  const startedAt = Date.now();
  const fetchedPage = await fetchPage(normalized.normalizedUrl);
  const bodyText = (fetchedPage.html ?? "").replace(/<[^>]+>/g, " ").replace(/\s+/g, " ");
  const pageTitleMatch = fetchedPage.html?.match(/<title[^>]*>([^<]*)<\/title>/i);
  const pageTitle = pageTitleMatch?.[1]?.trim() ?? null;

  const brandMatch = await inferBrandMatch({
    analyzedUrl: normalized.normalizedUrl,
    normalizedDomain: normalized.registrableDomain,
    pageTitle,
    bodyText,
    brandOverride: request.brand_override
  });

  const infrastructureBase = await collectInfrastructureSignals(
    normalized.registrableDomain,
    fetchedPage.finalUrl ?? normalized.normalizedUrl
  );

  const contentAnalysis = analyzePageContent(
    fetchedPage.html,
    fetchedPage.headers,
    fetchedPage.redirectChain,
    brandMatch,
    fetchedPage.finalUrl ?? normalized.normalizedUrl
  );

  const [reputationResult, passiveHistoryResult] = await Promise.all([
    collectReputationSignals(
      fetchedPage.finalUrl ?? normalized.normalizedUrl,
      infrastructureBase.dns_records.a[0] ?? null
    ),
    collectPassiveHistorySignals({
      domain: normalized.registrableDomain,
      ownershipChangesDetected: infrastructureBase.ownership_changes_detected
    })
  ]);

  const lexical = buildLexicalSignals({
    normalizedDomain: normalized.registrableDomain,
    punycodeHostname: normalized.punycodeHostname,
    isIdn: normalized.isIdn,
    tld: normalized.tld,
    isIpLiteral: normalized.isIpLiteral,
    brandMatch
  });

  const infrastructure: RiskFactors["infrastructure"] = {
    domain_age_days: infrastructureBase.domain_age_days,
    registrar: infrastructureBase.registrar,
    registrant_org: infrastructureBase.registrant_org,
    registration_length_years: infrastructureBase.registration_length_years,
    whois_privacy: infrastructureBase.whois_privacy,
    hidden_ownership: infrastructureBase.hidden_ownership,
    registrant_country: infrastructureBase.registrant_country,
    ssl_valid: infrastructureBase.ssl_valid,
    ssl_error: infrastructureBase.ssl_error,
    certificate_issuer: infrastructureBase.certificate_issuer,
    certificate_reputation: infrastructureBase.certificate_reputation,
    certificate_age_days: infrastructureBase.certificate_age_days,
    certificate_domain_mismatch: infrastructureBase.certificate_domain_mismatch,
    creation_date_anomaly: infrastructureBase.creation_date_anomaly,
    mx_records_present: infrastructureBase.mx_records_present,
    dns_records: infrastructureBase.dns_records,
    dns_history_changes: passiveHistoryResult.dnsHistoryChanges,
    fast_flux_detected: infrastructureBase.fast_flux_detected,
    ip_reputation_score: reputationResult.reputational.abuse_ipdb_reports,
    hosting_asn: infrastructureBase.hosting_asn,
    hosting_asn_reputation: infrastructureBase.hosting_asn_reputation,
    shared_hosting_risk: infrastructureBase.shared_hosting_risk,
    redirect_count: fetchedPage.redirectChain.length,
    final_url: fetchedPage.finalUrl
  };

  const emailAuth: RiskFactors["email_auth"] = {
    spf_present: infrastructure.dns_records.txt.some((record) => record.toLowerCase().includes("spf1")),
    dkim_present: infrastructure.dns_records.txt.some((record) => /dkim/i.test(record)),
    dmarc_present: infrastructure.dns_records.txt.some((record) => /v=dmarc1/i.test(record)),
    spf_dkim_dmarc_missing: !infrastructure.dns_records.txt.some((record) =>
      /(spf1|dkim|dmarc1)/i.test(record)
    )
  };

  const behavioral: RiskFactors["behavioral"] = {
    keyboard_event_listeners: contentAnalysis.content.suspicious_script_patterns.includes("keyboard_capture"),
    http_to_https_mismatch:
      Boolean(fetchedPage.finalUrl) &&
      fetchedPage.finalUrl.startsWith("http://") &&
      normalized.normalizedUrl.startsWith("https://"),
    external_form_action: contentAnalysis.externalFormAction
  };

  const machineLearning = buildMachineLearningSignals({
    normalizedUrl: normalized.normalizedUrl,
    lexical,
    content: contentAnalysis.content,
    infrastructure
  });

  const riskFactors: RiskFactors = {
    lexical,
    infrastructure,
    content: contentAnalysis.content,
    reputational: reputationResult.reputational,
    behavioral,
    email_auth: emailAuth,
    passive_history: passiveHistoryResult.passiveHistory,
    machine_learning: machineLearning
  };

  const { score, verdict } = computeThreatScore(riskFactors);

  const preLlmDiagnostics: SignalDiagnostic[] = [
    {
      signal: "page_fetch",
      provider: "page_fetch",
      status: fetchedPage.error ? "query_failed" : "ok",
      detail: fetchedPage.error ?? undefined
    },
    {
      signal: "registrar_metadata",
      provider: "rdap",
      status:
        infrastructure.registrar !== null ||
        infrastructure.domain_age_days !== null ||
        infrastructure.registrant_org !== null
          ? "ok"
          : "query_failed",
      detail:
        infrastructure.registrar !== null ||
        infrastructure.domain_age_days !== null ||
        infrastructure.registrant_org !== null
          ? undefined
          : "RDAP registrar metadata was unavailable."
    },
    ...reputationResult.diagnostics,
    ...passiveHistoryResult.diagnostics
  ];

  const evidenceSummary = buildEvidenceSummary({
    riskFactors,
    threatScore: score,
    verdict,
    signalDiagnostics: preLlmDiagnostics
  });

  const reportingContacts = await buildReportingContacts({
    brandMatch,
    registrarName: infrastructure.registrar,
    registrantCountry: infrastructure.registrant_country,
    tld: normalized.tld
  });

  const llmStartedAt = Date.now();
  const llmReasoning = await callBedrockJson<{ reasoning: string; verdict: AnalysisResult["verdict"] }>({
    promptName: "analyst_explanation",
    prompt: buildAnalystExplanationPrompt({
      analyzed_url: normalized.normalizedUrl,
      normalized_domain: normalized.registrableDomain,
      brand_match: brandMatch,
      threat_score: score,
      verdict,
      risk_factors: riskFactors,
      evidence_highlights: evidenceSummary.highlights
    }),
    validator: (value) => {
      if (!value || typeof value !== "object") {
        return null;
      }
      const candidate = value as { reasoning?: unknown; verdict?: unknown };
      if (typeof candidate.reasoning !== "string") {
        return null;
      }
      return {
        reasoning: candidate.reasoning,
        verdict: typeof candidate.verdict === "string" ? (candidate.verdict as AnalysisResult["verdict"]) : verdict
      };
    }
  });
  const llmDuration = Date.now() - llmStartedAt;

  const finalDiagnostics = [
    ...preLlmDiagnostics,
    {
      signal: "analyst_explanation",
      provider: "bedrock",
      status: llmReasoning ? "ok" : "not_configured",
      detail: llmReasoning ? undefined : "Bedrock explanation unavailable or skipped."
    } satisfies SignalDiagnostic
  ];

  const fallbackReasoning = [
    brandMatch.method === "unknown"
      ? `No confident target brand match was identified for ${normalized.registrableDomain}, so the score was based on generic lexical, infrastructure, content, and reputation signals.`
      : `The domain was evaluated against ${brandMatch.brand_name} (${brandMatch.canonical_domain}) with a threat score of ${score}/100.`,
    brandMatch.method === "unknown"
      ? "Brand-specific similarity metrics were withheld until a stronger target match was established."
      : lexical.is_homoglyph
        ? "The lexical analysis found lookalike character or typosquatting behavior."
        : "The lexical similarity was weighted alongside non-lexical evidence.",
    contentAnalysis.content.credential_harvesting_detected
      ? "Page analysis identified credential harvesting indicators."
      : "No direct credential harvesting form was confirmed from the fetched page.",
    passiveHistoryResult.passiveHistory.archive_first_seen_days !== null &&
    passiveHistoryResult.passiveHistory.archive_first_seen_days < 30
      ? "Historical evidence suggests the domain appeared recently, increasing suspicion."
      : "Historical and infrastructure signals were mixed and were weighted with available page evidence."
  ].join(" ");

  const result: AnalysisResult = analysisResultSchema.parse({
    schema_version: "analysis-result.v2",
    mode: request.mode,
    analyzed_url: request.url,
    normalized_domain: normalized.registrableDomain,
    normalized_url: normalized.normalizedUrl,
    brand_match: brandMatch,
    threat_score: score,
    verdict: llmReasoning?.verdict ?? verdict,
    reasoning: llmReasoning?.reasoning ?? fallbackReasoning,
    risk_factors: riskFactors,
    evidence_summary: {
      ...evidenceSummary,
      signal_diagnostics: finalDiagnostics
    },
    reporting_contacts: reportingContacts,
    signal_sources: mergeSignalSources(finalDiagnostics),
    timings: {
      total_ms: Date.now() - startedAt,
      fetch_ms: fetchedPage.fetchMs,
      enrichment_ms: Date.now() - startedAt - fetchedPage.fetchMs - llmDuration,
      llm_ms: llmReasoning ? llmDuration : null
    },
    export_metadata: {
      generated_at: new Date().toISOString(),
      generated_by: "Capstone Domain Guardian",
      schema_version: "analysis-result.v2",
      sources: mergeSignalSources(finalDiagnostics)
    },
    partial: false
  });

  await cache.set(cacheKey, result);
  return result;
}

export async function generateLookalikeSet(
  request: GenerateLookalikesRequest
): Promise<LookalikeCandidateSet> {
  const normalized = normalizeInputUrl(request.canonical_domain);
  const candidates = await fetchDnsTwisterLookalikes(normalized.registrableDomain, request.limit);

  return {
    schema_version: "lookalike-candidates.v2",
    canonical_domain: normalized.registrableDomain,
    brand_name: request.brand_name ?? null,
    generated_at: new Date().toISOString(),
    source: "dnstwister",
    candidates
  };
}
