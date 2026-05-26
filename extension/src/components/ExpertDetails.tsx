import type { AnalysisResult } from "@capstone/shared";
import { CategoryCard } from "./CategoryCard";
import { EvidencePanel } from "./EvidencePanel";
import { JsonExportButton } from "./JsonExportButton";
import { ReportingContactsCard } from "./ReportingContactsCard";
import { ScoreCard } from "./ScoreCard";
import { PdfExportButton } from "./PdfExportButton";

type ExpertDetailsProps = {
  result: AnalysisResult;
};

export function ExpertDetails({ result }: ExpertDetailsProps) {
  const degradedSignalCount = result.evidence_summary.signal_diagnostics.filter(
    (diagnostic) => diagnostic.status !== "ok"
  ).length;

  return (
    <div className="expert-details">
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
      <div className="expert-details-actions">
        <JsonExportButton
          filename={`${result.normalized_domain}-analysis.json`}
          payload={result}
        />
        <PdfExportButton result={result} />
      </div>
    </div>
  );
}
