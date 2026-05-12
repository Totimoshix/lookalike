export function buildBrandInferencePrompt(input: {
  analyzedUrl: string;
  normalizedDomain: string;
  pageTitle: string | null;
  domainKeywords: string[];
  candidateBrands: Array<{ brand_name: string; canonical_domain: string; confidence: number; why: string }>;
}) {
  return `
You are assisting an analyst-first phishing investigation workflow.
Infer the most likely legitimate brand that the suspicious domain is imitating.

Rules:
- Use only the provided evidence.
- Prefer lexical similarity and brand keywords.
- If confidence is weak, respond with method "unknown".
- Return valid JSON only.

Evidence:
${JSON.stringify(input, null, 2)}

Return JSON:
{
  "brand_name": "string",
  "canonical_domain": "string",
  "confidence": 0.0,
  "method": "llm|unknown",
  "matched_keywords": ["string"]
}
`.trim();
}

