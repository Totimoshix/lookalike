import type { AnalysisResult } from "@capstone/shared";

type EvidencePanelProps = {
  result: AnalysisResult;
};

export function EvidencePanel({ result }: EvidencePanelProps) {
  const degradedDiagnostics = result.evidence_summary.signal_diagnostics.filter((diagnostic) => diagnostic.status !== "ok");
  const healthyDiagnostics = result.evidence_summary.signal_diagnostics.filter((diagnostic) => diagnostic.status === "ok");

  return (
    <section className="panel">
      <div className="panel-head">
        <h3>Evidence Summary</h3>
      </div>
      <div className="highlight-list">
        {result.evidence_summary.highlights.map((highlight) => (
          <p key={highlight} className="highlight-chip">
            {highlight}
          </p>
        ))}
      </div>
      <div className="evidence-table">
        {result.evidence_summary.evidence_items.map((item) => (
          <article key={item.key} className={`evidence-item ${item.severity}`}>
            <strong>{item.label}</strong>
            <span>{String(item.value)}</span>
            <small>{item.note ?? item.category}</small>
          </article>
        ))}
      </div>
      {result.evidence_summary.signal_diagnostics.length > 0 ? (
        <div className="diagnostic-list">
          {result.evidence_summary.signal_diagnostics.map((diagnostic) => (
            <article className={`diagnostic-item ${diagnostic.status}`} key={`${diagnostic.provider}:${diagnostic.signal}`}>
              <div>
                <strong>{diagnostic.signal.replace(/_/g, " ")}</strong>
                <small>{diagnostic.provider}</small>
              </div>
              <span>{diagnostic.status.replace(/_/g, " ")}</span>
            </article>
          ))}
        </div>
      ) : null}
      {degradedDiagnostics.length > 0 ? (
        <div className="missing-block">
          <p className="eyebrow">Provider Diagnostics</p>
          <ul>
            {degradedDiagnostics.map((diagnostic) => (
              <li key={`${diagnostic.provider}:${diagnostic.signal}:detail`}>
                <strong>{diagnostic.signal.replace(/_/g, " ")}</strong>: {diagnostic.status.replace(/_/g, " ")}
                {diagnostic.detail ? ` · ${diagnostic.detail}` : ` · ${diagnostic.provider}`}
              </li>
            ))}
          </ul>
        </div>
      ) : null}
      {healthyDiagnostics.length > 0 ? (
        <p className="diagnostic-summary">
          {healthyDiagnostics.length} provider checks completed successfully for this analysis.
        </p>
      ) : null}
    </section>
  );
}
