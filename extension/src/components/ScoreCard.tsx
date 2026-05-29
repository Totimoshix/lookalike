import { useEffect, useRef, useState } from "react";
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

function useAnimatedCount(target: number, duration = 900) {
  const [count, setCount] = useState(0);
  const rafRef = useRef<number>(0);

  useEffect(() => {
    setCount(0);
    const start = performance.now();
    const animate = (now: number) => {
      const elapsed = now - start;
      const progress = Math.min(elapsed / duration, 1);
      const eased = 1 - Math.pow(1 - progress, 3);
      setCount(Math.round(eased * target));
      if (progress < 1) {
        rafRef.current = requestAnimationFrame(animate);
      }
    };
    rafRef.current = requestAnimationFrame(animate);
    return () => cancelAnimationFrame(rafRef.current);
  }, [target, duration]);

  return count;
}

const RING_SIZE = 88;
const STROKE = 7;
const RADIUS = (RING_SIZE - STROKE) / 2;
const CIRCUMFERENCE = 2 * Math.PI * RADIUS;

export function ScoreCard({ result }: ScoreCardProps) {
  const displayScore = useAnimatedCount(result.threat_score);
  const offset = CIRCUMFERENCE - (displayScore / 100) * CIRCUMFERENCE;

  return (
    <section className={scoreTone(result.verdict)}>
      <div className="score-main">
        <div className="score-heading">
          <div aria-hidden="true" className="score-icon">!</div>
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
      <div
        className="score-ring"
        aria-label={`Threat score: ${result.threat_score} out of 100`}
      >
        <svg
          width={RING_SIZE}
          height={RING_SIZE}
          viewBox={`0 0 ${RING_SIZE} ${RING_SIZE}`}
        >
          <circle
            cx={RING_SIZE / 2}
            cy={RING_SIZE / 2}
            r={RADIUS}
            fill="none"
            className="score-ring-track"
            strokeWidth={STROKE}
          />
          <circle
            cx={RING_SIZE / 2}
            cy={RING_SIZE / 2}
            r={RADIUS}
            fill="none"
            className="score-ring-progress"
            strokeWidth={STROKE}
            strokeLinecap="round"
            strokeDasharray={CIRCUMFERENCE}
            strokeDashoffset={offset}
            transform={`rotate(-90 ${RING_SIZE / 2} ${RING_SIZE / 2})`}
          />
        </svg>
        <div className="score-ring-center">
          <span className="score-ring-number">{displayScore}</span>
          <small className="score-ring-denom">/100</small>
        </div>
      </div>
    </section>
  );
}
