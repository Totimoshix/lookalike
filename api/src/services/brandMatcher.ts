import {
  baseDomainLabel,
  damerauLevenshtein,
  jaroWinkler,
  levenshtein,
  normalizeInputUrl,
  suspiciousKeywordsInDomain
} from "@capstone/shared";
import type { BrandMatch } from "@capstone/shared";
import { brandCatalog } from "../data/brandCatalog.js";
import { buildBrandInferencePrompt } from "../prompts/brandInference.js";
import { callBedrockJson } from "./bedrock.js";

function normalize(value: string): string {
  return value.trim().toLowerCase();
}

function canonicalizeLabel(value: string): string {
  return value
    .toLowerCase()
    .normalize("NFKD")
    .replace(/[\u0300-\u036f]/g, "")
    .replace(/[@]/g, "a")
    .replace(/[0]/g, "o")
    .replace(/[1|!]/g, "l")
    .replace(/[3]/g, "e")
    .replace(/[5$]/g, "s")
    .replace(/[7]/g, "t")
    .replace(/[^a-z0-9]/g, "");
}

function normalizeConfusableSource(value: string): string {
  return value
    .trim()
    .toLowerCase()
    .normalize("NFKD")
    .replace(/[\u0300-\u036f]/g, "")
    .replace(/[^a-z0-9@$!|]/g, "");
}

const confusableCharacterMap: Record<string, string[]> = {
  "0": ["o"],
  "1": ["a", "i", "l"],
  "3": ["e"],
  "4": ["a"],
  "5": ["s"],
  "7": ["t"],
  "8": ["b"],
  "9": ["g"],
  "@": ["a"],
  "$": ["s"],
  "!": ["i", "l"],
  "|": ["i", "l"]
};

function expandConfusableVariants(value: string, maxVariants = 24): string[] {
  const normalized = normalizeConfusableSource(value);
  const variants = new Set<string>([normalized]);
  let frontier = [normalized];

  for (let depth = 0; depth < 2 && variants.size < maxVariants; depth += 1) {
    const nextFrontier: string[] = [];

    for (const current of frontier) {
      for (let index = 0; index < current.length; index += 1) {
        const substitutions = confusableCharacterMap[current[index]];
        if (!substitutions) {
          continue;
        }

        for (const replacement of substitutions) {
          const candidate = `${current.slice(0, index)}${replacement}${current.slice(index + 1)}`;
          if (variants.has(candidate)) {
            continue;
          }

          variants.add(candidate);
          nextFrontier.push(candidate);

          if (variants.size >= maxVariants) {
            break;
          }
        }

        if (variants.size >= maxVariants) {
          break;
        }
      }

      if (variants.size >= maxVariants) {
        break;
      }
    }

    frontier = nextFrontier;
    if (frontier.length === 0) {
      break;
    }
  }

  return Array.from(variants, (variant) => canonicalizeLabel(variant));
}

type CandidateScore = {
  brand_name: string;
  canonical_domain: string;
  confidence: number;
  why: string;
  matched_keywords: string[];
  exact_label_match: boolean;
  confusable_brand_match: boolean;
  embedded_brand_match: boolean;
  lexical_similarity: number;
  edit_distance: number;
};

function scoreAgainstCandidate(
  inputDomain: string,
  bodyText: string,
  pageTitle: string | null,
  candidate: typeof brandCatalog[number]
): CandidateScore {
  const sourceLabel = baseDomainLabel(inputDomain);
  const targetLabel = baseDomainLabel(candidate.canonicalDomain);
  const canonicalSource = canonicalizeLabel(sourceLabel);
  const canonicalTarget = canonicalizeLabel(targetLabel);
  const sourceVariants = Array.from(new Set([canonicalSource, ...expandConfusableVariants(sourceLabel)]));
  const sourceText = `${sourceLabel} ${pageTitle ?? ""} ${bodyText}`.toLowerCase();

  const keywordHits = candidate.keywords.filter((keyword) => sourceText.includes(keyword.toLowerCase()));
  const aliasHits = candidate.aliases.filter((alias) =>
    sourceVariants.some((variant) => variant.includes(canonicalizeLabel(alias))) || sourceText.includes(alias.toLowerCase())
  );
  const domainKeywordHits = suspiciousKeywordsInDomain(inputDomain).filter((keyword) =>
    candidate.keywords.includes(keyword)
  );

  let bestVariant = canonicalSource;
  let bestEditDistance = Number.POSITIVE_INFINITY;
  let lexicalSimilarity = 0;

  for (const variant of sourceVariants) {
    const maxLength = Math.max(variant.length, canonicalTarget.length, 1);
    const currentEditDistance = levenshtein(variant, canonicalTarget);
    const editSimilarity = 1 - currentEditDistance / maxLength;
    const damerauDistance = damerauLevenshtein(variant, canonicalTarget);
    const damerauSimilarity = 1 - damerauDistance / maxLength;
    const jaroSimilarity = jaroWinkler(variant, canonicalTarget);
    const candidateSimilarity = Math.max(jaroSimilarity, editSimilarity, damerauSimilarity);

    if (
      candidateSimilarity > lexicalSimilarity ||
      (candidateSimilarity === lexicalSimilarity && currentEditDistance < bestEditDistance)
    ) {
      lexicalSimilarity = candidateSimilarity;
      bestEditDistance = currentEditDistance;
      bestVariant = variant;
    }
  }

  const exactLabelMatch = canonicalSource === canonicalTarget;
  const confusableBrandMatch = !exactLabelMatch && bestVariant === canonicalTarget;
  const embeddedBrandMatch =
    sourceVariants.some((variant) => variant.includes(canonicalTarget) || canonicalTarget.includes(variant)) ||
    aliasHits.length > 0;

  let confidence = lexicalSimilarity * 0.44;
  if (exactLabelMatch) {
    confidence += 0.48;
  }
  if (confusableBrandMatch) {
    confidence += 0.32;
  }
  if (embeddedBrandMatch) {
    confidence += 0.22;
  }
  confidence += Math.min(0.18, keywordHits.length * 0.05);
  confidence += Math.min(0.1, domainKeywordHits.length * 0.04);

  if (
    !exactLabelMatch &&
    !confusableBrandMatch &&
    !embeddedBrandMatch &&
    keywordHits.length === 0 &&
    lexicalSimilarity < 0.7
  ) {
    confidence *= 0.35;
  }

  if (exactLabelMatch) {
    confidence = Math.max(confidence, 0.96);
  } else if (confusableBrandMatch && bestEditDistance <= 1) {
    confidence = Math.max(confidence, 0.88);
  } else if (embeddedBrandMatch && lexicalSimilarity >= 0.7) {
    confidence = Math.max(confidence, 0.84);
  } else if (lexicalSimilarity >= 0.91 && bestEditDistance <= 1) {
    confidence = Math.max(confidence, 0.77);
  }

  confidence = Math.min(0.99, Math.max(0, confidence));

  return {
    brand_name: candidate.brandName,
    canonical_domain: candidate.canonicalDomain,
    confidence: Number(confidence.toFixed(3)),
    why: `lexical=${lexicalSimilarity.toFixed(3)} edit_distance=${bestEditDistance} exact=${exactLabelMatch} confusable=${confusableBrandMatch} embedded=${embeddedBrandMatch} keyword_hits=${keywordHits.length} alias_hits=${aliasHits.length} domain_keyword_hits=${domainKeywordHits.length}`,
    matched_keywords: Array.from(new Set([...keywordHits, ...aliasHits, ...domainKeywordHits])),
    exact_label_match: exactLabelMatch,
    confusable_brand_match: confusableBrandMatch,
    embedded_brand_match: embeddedBrandMatch,
    lexical_similarity: Number(lexicalSimilarity.toFixed(3)),
    edit_distance: bestEditDistance
  };
}

function fromOverride(override: string): BrandMatch {
  const normalizedOverride = normalize(override);
  const match = brandCatalog.find(
    (entry) =>
      normalize(entry.brandName) === normalizedOverride ||
      normalize(entry.canonicalDomain) === normalizedOverride ||
      entry.aliases.some((alias) => normalize(alias) === normalizedOverride)
  );

  if (match) {
    return {
      brand_name: match.brandName,
      canonical_domain: match.canonicalDomain,
      confidence: 1,
      method: "override",
      matched_keywords: match.keywords
    };
  }

  const looksLikeDomain = normalizedOverride.includes(".");
  return {
    brand_name: looksLikeDomain ? baseDomainLabel(normalizedOverride) : override,
    canonical_domain: looksLikeDomain ? normalizeInputUrl(normalizedOverride).registrableDomain : `${normalizedOverride.replace(/\s+/g, "")}.com`,
    confidence: 0.95,
    method: "override",
    matched_keywords: []
  };
}

export async function inferBrandMatch(input: {
  analyzedUrl: string;
  normalizedDomain: string;
  pageTitle: string | null;
  bodyText: string;
  brandOverride?: string;
  skipLlm?: boolean;
}): Promise<BrandMatch> {
  if (input.brandOverride) {
    return fromOverride(input.brandOverride);
  }

  const candidates = brandCatalog
    .map((entry) => scoreAgainstCandidate(input.normalizedDomain, input.bodyText, input.pageTitle, entry))
    .sort((left, right) => right.confidence - left.confidence)
    .slice(0, 3);

  const bestCandidate = candidates[0];
  const secondCandidate = candidates[1];
  const confidenceGap = bestCandidate ? bestCandidate.confidence - (secondCandidate?.confidence ?? 0) : 0;
  const hasStrongSignal =
    bestCandidate?.exact_label_match ||
    bestCandidate?.confusable_brand_match ||
    bestCandidate?.embedded_brand_match ||
    (bestCandidate?.matched_keywords.length ?? 0) > 0;
  const strongLexicalLookalike =
    Boolean(bestCandidate) &&
    (bestCandidate!.confusable_brand_match ||
      (bestCandidate!.lexical_similarity >= 0.9 && bestCandidate!.edit_distance <= 1) ||
      (bestCandidate!.lexical_similarity >= 0.83 && bestCandidate!.edit_distance <= 1 && confidenceGap >= 0.08));

  if (
    bestCandidate &&
    (
      bestCandidate.exact_label_match ||
      strongLexicalLookalike ||
      (hasStrongSignal && bestCandidate.confidence >= 0.74) ||
      (bestCandidate.confidence >= 0.82 && confidenceGap >= 0.1)
    )
  ) {
      return {
        brand_name: bestCandidate.brand_name,
        canonical_domain: bestCandidate.canonical_domain,
        confidence: bestCandidate.confidence,
        method:
          bestCandidate.exact_label_match ||
          (bestCandidate.embedded_brand_match && !bestCandidate.confusable_brand_match)
            ? "catalog"
            : "heuristic",
        matched_keywords: bestCandidate.matched_keywords
      };
  }

  if (input.skipLlm) {
    return {
      brand_name: "Unknown",
      canonical_domain: input.normalizedDomain,
      confidence: 0,
      method: "unknown",
      matched_keywords: []
    };
  }

  const llmResult = await callBedrockJson<BrandMatch>({
    promptName: "brand_inference",
    prompt: buildBrandInferencePrompt({
      analyzedUrl: input.analyzedUrl,
      normalizedDomain: input.normalizedDomain,
      pageTitle: input.pageTitle,
      domainKeywords: suspiciousKeywordsInDomain(input.normalizedDomain),
      candidateBrands: candidates
    }),
    validator: (value) => {
      if (!value || typeof value !== "object") {
        return null;
      }
      const candidate = value as Partial<BrandMatch>;
      if (!candidate.brand_name || !candidate.canonical_domain || typeof candidate.confidence !== "number") {
        return null;
      }
      return {
        brand_name: candidate.brand_name,
        canonical_domain: candidate.canonical_domain,
        confidence: candidate.confidence,
        method: candidate.method === "llm" ? "llm" : "unknown",
        matched_keywords: Array.isArray(candidate.matched_keywords) ? candidate.matched_keywords : []
      };
    }
  });

  if (llmResult && llmResult.confidence >= 0.72) {
    return llmResult;
  }

  return {
    brand_name: "Unknown",
    canonical_domain: input.normalizedDomain,
    confidence: 0,
    method: "unknown",
    matched_keywords: []
  };
}
