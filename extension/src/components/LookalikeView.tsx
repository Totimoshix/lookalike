import { useState, type FormEvent } from "react";
import type { AnalysisResult, LookalikeCandidateSet } from "@capstone/shared";
import { analyzeDomainFast, generateLookalikes } from "../lib/api";
import { JsonExportButton } from "./JsonExportButton";

type BatchResult = {
  domain: string;
  result: AnalysisResult | null;
  error: string | null;
};

export function LookalikeView() {
  const [canonicalDomain, setCanonicalDomain] = useState("");
  const [brandName, setBrandName] = useState("");
  const [limit, setLimit] = useState("25");
  const [candidateSet, setCandidateSet] = useState<LookalikeCandidateSet | null>(null);
  const [batchResults, setBatchResults] = useState<BatchResult[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [isGenerating, setIsGenerating] = useState(false);
  const [isBatchScoring, setIsBatchScoring] = useState(false);

  const handleGenerate = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setError(null);
    setIsGenerating(true);
    setBatchResults([]);

    try {
      const response = await generateLookalikes({
        canonical_domain: canonicalDomain,
        brand_name: brandName.trim() || undefined,
        limit: Number(limit)
      });
      setCandidateSet(response);
    } catch (caughtError) {
      setError(caughtError instanceof Error ? caughtError.message : "Generation failed");
    } finally {
      setIsGenerating(false);
    }
  };

  const handleAnalyzeTop = async () => {
    if (!candidateSet) {
      return;
    }

    setIsBatchScoring(true);
    setBatchResults([]);
    const topCandidates = candidateSet.candidates.slice(0, 5);
    const brandOverride = candidateSet.brand_name ?? candidateSet.canonical_domain;

    // Score all five concurrently via the fast path (brand + lexical + a
    // budgeted reputation check; no page fetch / WHOIS / LLM). Sequential full
    // scans took 20s+ — most typosquat candidates don't resolve, so the full
    // pipeline's enrichment was pure wait. This returns in a couple of seconds.
    const results = await Promise.all(
      topCandidates.map(async (candidate): Promise<BatchResult> => {
        try {
          const result = await analyzeDomainFast({
            url: candidate.candidate_domain,
            mode: "manual_entry",
            brand_override: brandOverride
          });
          return { domain: candidate.candidate_domain, result, error: null };
        } catch (caughtError) {
          return {
            domain: candidate.candidate_domain,
            result: null,
            error: caughtError instanceof Error ? caughtError.message : "Analysis failed"
          };
        }
      })
    );

    setBatchResults(results);
    setIsBatchScoring(false);
  };

  return (
    <div className="view-shell">
      <form className="hero-form alt" onSubmit={handleGenerate}>
        <div>
          <p className="eyebrow">Lookalike Generation</p>
          <h1>Generate likely typosquat candidates</h1>
          <p className="lede">
            Start from the legitimate domain, pull lookalike candidates from DNSTwister, then score the highest-risk
            matches.
          </p>
        </div>
        <label className="input-block">
          <span>Canonical domain</span>
          <input
            onChange={(event) => setCanonicalDomain(event.target.value)}
            placeholder="amazon.com"
            value={canonicalDomain}
          />
        </label>
        <div className="dual-grid">
          <label className="input-block">
            <span>Brand name (optional)</span>
            <input onChange={(event) => setBrandName(event.target.value)} placeholder="Amazon" value={brandName} />
          </label>
          <label className="input-block">
            <span>Candidate limit</span>
            <input onChange={(event) => setLimit(event.target.value)} type="number" value={limit} />
          </label>
        </div>
        <div className="action-row">
          <button className="primary-button" disabled={isGenerating || canonicalDomain.trim().length === 0} type="submit">
            {isGenerating ? "Generating..." : "Generate Candidates"}
          </button>
          {candidateSet ? (
            <JsonExportButton filename={`${candidateSet.canonical_domain}-lookalikes.json`} payload={candidateSet} />
          ) : null}
        </div>
        {error ? <p className="error-banner">{error}</p> : null}
      </form>

      {batchResults.length > 0 ? (
        <section className="panel">
          <div className="panel-head">
            <h3>Top Candidate Scoring</h3>
          </div>
          <div className="candidate-list">
            {batchResults.map((entry) => (
              <article className="candidate-item" key={entry.domain}>
                <div>
                  <strong>{entry.domain}</strong>
                  <p>{entry.error ?? `${entry.result?.verdict} · ${entry.result?.threat_score}/100`}</p>
                </div>
              </article>
            ))}
          </div>
        </section>
      ) : null}

      {candidateSet ? (
        <section className="panel">
          <div className="panel-head">
            <h3>DNSTwister Candidate Queue</h3>
            <button className="ghost-button" disabled={isBatchScoring} onClick={handleAnalyzeTop} type="button">
              {isBatchScoring ? "Scoring Top 5..." : "Analyze Top 5"}
            </button>
          </div>
          <div className="candidate-list">
            {candidateSet.candidates.map((candidate) => (
              <article className="candidate-item" key={candidate.candidate_domain}>
                <div>
                  <strong>{candidate.candidate_domain}</strong>
                  <p>{candidate.pattern}</p>
                </div>
                <span>{Math.round(candidate.lexical_score * 100)}%</span>
              </article>
            ))}
          </div>
        </section>
      ) : null}
    </div>
  );
}
