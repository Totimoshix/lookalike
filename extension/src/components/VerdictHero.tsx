import type { AnalysisResult } from "@capstone/shared";
import {
  headlineForVerdict,
  pickTopReasons,
  shortSummary,
  toneForVerdict,
  type VerdictTone
} from "../lib/plainLanguage";

type VerdictHeroProps = {
  result: AnalysisResult;
  detailsOpen: boolean;
  onToggleDetails: () => void;
  onTrustSite: () => void;
  trusted: boolean;
};

const ICONS: Record<VerdictTone, string> = {
  safe: "✓",
  caution: "⚠",
  warning: "⚠",
  danger: "✕",
  unknown: "?"
};

export function VerdictHero({ result, detailsOpen, onToggleDetails, onTrustSite, trusted }: VerdictHeroProps) {
  const tone = toneForVerdict(result.verdict);
  const reasons = pickTopReasons(result);
  const summary = shortSummary(result);
  const canTrust = tone !== "safe" && tone !== "unknown";

  return (
    <section className={`verdict-hero tone-${tone}`}>
      <div className="verdict-hero-head">
        <span aria-hidden="true" className="verdict-hero-icon">{ICONS[tone]}</span>
        <div>
          <p className="verdict-hero-headline">{headlineForVerdict(result.verdict)}</p>
          <p className="verdict-hero-domain">{result.normalized_domain}</p>
        </div>
      </div>

      <p className="verdict-hero-summary">{summary}</p>

      {reasons.length > 0 ? (
        <div className="verdict-hero-reasons">
          <p className="eyebrow">Why</p>
          <ul>
            {reasons.map((reason) => (
              <li key={reason}>{reason}</li>
            ))}
          </ul>
        </div>
      ) : null}

      <div className="verdict-hero-actions">
        {canTrust ? (
          <button
            className="ghost-button"
            disabled={trusted}
            onClick={onTrustSite}
            type="button"
          >
            {trusted ? "Trusted" : "Trust site"}
          </button>
        ) : null}
        <button className="link-button" onClick={onToggleDetails} type="button">
          {detailsOpen ? "Hide details ▴" : "Show details ▾"}
        </button>
      </div>
    </section>
  );
}
