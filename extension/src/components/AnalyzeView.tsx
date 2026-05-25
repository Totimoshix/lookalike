import { useEffect, useState } from "react";
import type { AnalysisResult } from "@capstone/shared";
import { analyzeDomain } from "../lib/api";
import { addTrustedDomain, useTrustedDomains } from "../lib/storage";
import { ExpertDetails } from "./ExpertDetails";
import { UrlInputCard } from "./UrlInputCard";
import { VerdictHero } from "./VerdictHero";

type AnalyzeViewProps = {
  expertMode: boolean;
};

export function AnalyzeView({ expertMode }: AnalyzeViewProps) {
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [detailsOpen, setDetailsOpen] = useState(false);
  const [trustedDomains] = useTrustedDomains();

  useEffect(() => {
    // Reset per-result expansion when expert mode toggles.
    if (expertMode) setDetailsOpen(true);
    else setDetailsOpen(false);
  }, [expertMode]);

  const handleAnalyze = async (url: string, brandOverride: string | undefined) => {
    setIsLoading(true);
    setError(null);
    setResult(null);
    setDetailsOpen(expertMode);

    try {
      const response = await analyzeDomain({
        url,
        mode: "manual_entry",
        brand_override: brandOverride
      });
      setResult(response);
    } catch (caughtError) {
      setError(caughtError instanceof Error ? caughtError.message : "Analysis failed");
    } finally {
      setIsLoading(false);
    }
  };

  const handleTrust = async () => {
    if (!result) return;
    await addTrustedDomain(result.normalized_domain);
  };

  const trusted = result ? trustedDomains.has(result.normalized_domain.toLowerCase()) : false;

  return (
    <div className="view-shell">
      <UrlInputCard expertMode={expertMode} isLoading={isLoading} onSubmit={handleAnalyze} />

      {error ? <p className="error-banner">{error}</p> : null}

      {result ? (
        <>
          <VerdictHero
            result={result}
            detailsOpen={detailsOpen}
            onToggleDetails={() => setDetailsOpen((open) => !open)}
            onTrustSite={handleTrust}
            trusted={trusted}
          />
          {detailsOpen ? <ExpertDetails result={result} /> : null}
        </>
      ) : null}
    </div>
  );
}
