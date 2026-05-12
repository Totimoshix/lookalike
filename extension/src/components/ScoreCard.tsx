import type { AnalysisResult } from "@capstone/shared";

type ScoreCardProps = {
  result: AnalysisResult;
};

function scoreTone(verdict: AnalysisResult["verdict"]) {
  switch (verdict) {
    case "Malicious":
    case "Critical":
      return "score-card danger";
    case "High":
      return "score-card warning";
    case "Medium":
      return "score-card caution";
    default:
      return "score-card safe";
  }
}

export function ScoreCard({ result }: ScoreCardProps) {
  return (
    <section className={scoreTone(result.verdict)}>
      <div className="score-main">
        <div className="score-heading">
          <div aria-hidden="true" className="score-icon">
            !
          </div>
          <div>
            <p className="eyebrow">Threat Posture</p>
            <h2>{result.verdict}</h2>
          </div>
        </div>
        <p className="score-copy">{result.reasoning}</p>
        <div aria-hidden="true" className="score-meter">
          <span style={{ width: `${Math.max(result.threat_score, 6)}%` }} />
        </div>
      </div>
      <div className="score-pill">
        <span>{result.threat_score}</span>
        <small>/100</small>
      </div>
    </section>
  );
}
