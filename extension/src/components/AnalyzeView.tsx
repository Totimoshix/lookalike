import { useState, type FormEvent } from "react";
import type { AnalysisResult } from "@capstone/shared";
import { analyzeDomain } from "../lib/api";
import { CategoryCard } from "./CategoryCard";
import { EvidencePanel } from "./EvidencePanel";
import { JsonExportButton } from "./JsonExportButton";
import { ReportingContactsCard } from "./ReportingContactsCard";
import { ScoreCard } from "./ScoreCard";

export function AnalyzeView() {
  const [url, setUrl] = useState("");
  const [brandOverride, setBrandOverride] = useState("");
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const degradedSignalCount = result
    ? result.evidence_summary.signal_diagnostics.filter((diagnostic) => diagnostic.status !== "ok").length
    : 0;

  const handleAnalyze = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setIsLoading(true);
    setError(null);

    try {
      const response = await analyzeDomain({
        url,
        mode: "manual_entry",
        brand_override: brandOverride.trim() || undefined
      });
      setResult(response);
    } catch (caughtError) {
      setError(caughtError instanceof Error ? caughtError.message : "Analysis failed");
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="view-shell">
      <form className="hero-form" onSubmit={handleAnalyze}>
        <div>
          <p className="eyebrow">Manual URL Analysis</p>
          <h1>Analyst-grade lookalike domain triage</h1>
          <p className="lede">
            Paste a URL or bare domain, optionally force the target brand, and get structured evidence you can export.
          </p>
        </div>
        <label className="input-block">
          <span>Suspicious URL or domain</span>
          <input
            autoComplete="off"
            onChange={(event) => setUrl(event.target.value)}
            placeholder="https://amaz0on-login-support.com"
            value={url}
          />
        </label>
        <label className="input-block">
          <span>Brand override (optional)</span>
          <input
            autoComplete="off"
            onChange={(event) => setBrandOverride(event.target.value)}
            placeholder="Amazon or amazon.com"
            value={brandOverride}
          />
        </label>
        <div className="action-row">
          <button className="primary-button" disabled={isLoading || url.trim().length === 0} type="submit">
            {isLoading ? "Analyzing..." : "Analyze Domain"}
          </button>
          {result ? (
            <JsonExportButton filename={`${result.normalized_domain}-analysis.json`} payload={result} />
          ) : null}
        </div>
        {error ? <p className="error-banner">{error}</p> : null}
      </form>

      {result ? (
        <>
          <ScoreCard result={result} />
          <section className="brand-strip">
            <article className="summary-card summary-target">
              <p className="eyebrow">Matched Brand</p>
              <strong>{result.brand_match.brand_name}</strong>
              <span>{result.brand_match.canonical_domain}</span>
            </article>
            <article className="summary-card summary-confidence">
              <p className="eyebrow">Confidence</p>
              <strong>{Math.round(result.brand_match.confidence * 100)}%</strong>
              <span>{result.brand_match.method}</span>
            </article>
            <article className="summary-card summary-evidence">
              <p className="eyebrow">Evidence Hits</p>
              <strong>{result.evidence_summary.evidence_items.length}</strong>
              <span>{degradedSignalCount} provider gaps</span>
            </article>
          </section>
          <EvidencePanel result={result} />
          <div className="panel-grid">
            <CategoryCard title="Lexical" fields={result.risk_factors.lexical} />
            <CategoryCard title="Infrastructure" fields={result.risk_factors.infrastructure} />
            <CategoryCard title="Content" fields={result.risk_factors.content} />
            <CategoryCard title="Reputational" fields={result.risk_factors.reputational} />
            <CategoryCard title="Behavioral" fields={result.risk_factors.behavioral} />
            <CategoryCard title="Email Auth" fields={result.risk_factors.email_auth} />
            <CategoryCard title="Passive History" fields={result.risk_factors.passive_history} />
            <CategoryCard title="Machine Learning" fields={result.risk_factors.machine_learning} />
          </div>
          <ReportingContactsCard result={result} />
        </>
      ) : null}
    </div>
  );
}
