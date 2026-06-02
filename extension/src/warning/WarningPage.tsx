import { useEffect, useState } from "react";
import type { AnalysisResult } from "@capstone/shared";
import { ExpertDetails } from "../components/ExpertDetails";
import { addSessionBypass, addTrustedDomain, takePendingWarning } from "../lib/storage";
import {
  headlineForVerdict,
  pickTopReasons,
  shortSummary,
  toneForVerdict,
  type VerdictTone
} from "../lib/plainLanguage";

const ICONS: Record<VerdictTone, string> = {
  safe: "✓",
  caution: "⚠",
  warning: "⚠",
  danger: "✕",
  unknown: "?"
};

type WarningParams = {
  id: string | null;
  originalUrl: string | null;
  verdict: string | null;
  domain: string | null;
};

function readParams(): WarningParams {
  const params = new URLSearchParams(window.location.search);
  return {
    id: params.get("id"),
    originalUrl: params.get("originalUrl"),
    verdict: params.get("verdict"),
    domain: params.get("domain")
  };
}

function safelyGoBack() {
  if (typeof window !== "undefined") {
    if (window.history.length > 1) {
      window.history.back();
    } else {
      window.location.href = "about:blank";
    }
  }
}

export function WarningPage() {
  const [params] = useState<WarningParams>(readParams);
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [loading, setLoading] = useState(true);
  const [detailsOpen, setDetailsOpen] = useState(false);
  const [showContinueConfirm, setShowContinueConfirm] = useState(false);

  useEffect(() => {
    if (!params.id) {
      setLoading(false);
      return;
    }
    takePendingWarning(params.id)
      .then((payload) => setResult(payload))
      .finally(() => setLoading(false));
  }, [params.id]);

  const tone: VerdictTone = result
    ? toneForVerdict(result.verdict)
    : params.verdict === "Medium"
      ? "caution"
      : params.verdict === "High"
        ? "warning"
        : params.verdict === "Critical" || params.verdict === "Malicious"
          ? "danger"
          : "unknown";

  const headline = result
    ? headlineForVerdict(result.verdict)
    : params.verdict
      ? headlineForVerdict(params.verdict as AnalysisResult["verdict"])
      : "Warning";

  const domain = result?.normalized_domain ?? params.domain ?? "this site";
  const summary = result
    ? shortSummary(result)
    : `Domain Guardian flagged ${domain} as potentially deceptive.`;
  const reasons = result ? pickTopReasons(result) : [];

  const handleContinue = async () => {
    if (!showContinueConfirm) {
      setShowContinueConfirm(true);
      return;
    }
    if (result) {
      await addSessionBypass(result.normalized_domain);
    } else if (params.domain) {
      await addSessionBypass(params.domain);
    }
    if (params.originalUrl) {
      window.location.href = params.originalUrl;
    }
  };

  const handleTrustPermanently = async () => {
    if (result) {
      await addTrustedDomain(result.normalized_domain);
    } else if (params.domain) {
      await addTrustedDomain(params.domain);
    }
    if (params.originalUrl) {
      window.location.href = params.originalUrl;
    }
  };

  return (
    <main className={`warning-shell tone-${tone}`}>
      <section className="warning-card">
        <div className="warning-icon-row">
          <span aria-hidden="true" className="warning-icon-shield">🛡</span>
          <span aria-hidden="true" className="warning-icon-alert">{ICONS[tone]}</span>
        </div>

        <h1 className="warning-headline">{headline}</h1>

        <p className="warning-domain">{domain}</p>

        <p className="warning-summary">{summary}</p>

        {loading ? (
          <p className="warning-hint">
            <span aria-hidden="true" className="spinner" /> Loading detailed evidence…
          </p>
        ) : reasons.length > 0 ? (
          <div className="warning-reasons">
            <p className="eyebrow">Why we flagged it</p>
            <ul>
              {reasons.map((reason) => (
                <li key={reason}>{reason}</li>
              ))}
            </ul>
          </div>
        ) : null}

        <div className="warning-actions">
          <button className="primary-button" onClick={safelyGoBack} type="button">
            ← Go back to safety
          </button>
          <button className="ghost-button warning-continue" onClick={handleContinue} type="button">
            {showContinueConfirm ? "Click again to confirm" : "Continue anyway"}
          </button>
        </div>

        {showContinueConfirm ? (
          <p className="warning-confirm-hint">
            This site may try to steal your information. You'll only bypass for this browser session.
          </p>
        ) : null}

        {result ? (
          <details
            className="warning-details"
            open={detailsOpen}
            onToggle={(event) => setDetailsOpen((event.target as HTMLDetailsElement).open)}
          >
            <summary>Show full analysis</summary>
            <div className="warning-details-body">
              <ExpertDetails result={result} />
              <button className="link-button" onClick={handleTrustPermanently} type="button">
                Trust this site permanently
              </button>
            </div>
          </details>
        ) : null}
      </section>
      <p className="warning-attribution">Domain Guardian · automatic phishing protection</p>
    </main>
  );
}
