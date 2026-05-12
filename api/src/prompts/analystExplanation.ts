import type { AnalysisResult, RiskFactors } from "@capstone/shared";

export function buildAnalystExplanationPrompt(input: {
  analyzed_url: string;
  normalized_domain: string;
  brand_match: AnalysisResult["brand_match"];
  threat_score: number;
  verdict: string;
  risk_factors: RiskFactors;
  evidence_highlights: string[];
}) {
  return `
You are producing an analyst-facing phishing assessment summary.
Use only the supplied evidence and never invent signals.
Keep the tone factual and action-oriented.
Return valid JSON only.

Evidence:
${JSON.stringify(input, null, 2)}

Return JSON:
{
  "reasoning": "2-5 sentence explanation of the primary risk drivers and why the score was assigned.",
  "verdict": "Safe|Low|Medium|High|Critical|Malicious|Unknown"
}
`.trim();
}

