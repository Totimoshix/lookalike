import {
  baseDomainLabel,
  damerauLevenshtein,
  isLegitDomain,
  isSharedHost,
  jaroWinkler,
  levenshtein,
  normalizeInputUrl,
  stripStuffingTokens,
  suspiciousKeywordsInDomain,
  tokenizeDomainLabel,
  trancoLabelMap
} from "@capstone/shared";
import type { BrandMatch } from "@capstone/shared";
import { brandCatalog } from "../data/brandCatalog.js";
import { buildBrandInferencePrompt } from "../prompts/brandInference.js";
import { callBedrockJson } from "./bedrock.js";

// Display-name overrides for Tranco-only matches whose label doesn't title-case
// nicely (the label is all we have for non-catalogued brands).
const BRAND_DISPLAY_NAMES: Record<string, string> = {
  nytimes: "NY Times",
  latimes: "LA Times",
  wsj: "WSJ",
  bbc: "BBC",
  cnn: "CNN",
  espn: "ESPN",
  hsbc: "HSBC",
  ups: "UPS",
  usps: "USPS",
  irs: "IRS",
  paypal: "PayPal",
  github: "GitHub",
  gitlab: "GitLab",
  youtube: "YouTube",
  linkedin: "LinkedIn",
  tiktok: "TikTok",
  whatsapp: "WhatsApp",
  icloud: "iCloud",
  iphone: "iPhone"
};

function capitalizeLabel(token: string): string {
  if (token.length === 0) return token;
  const override = BRAND_DISPLAY_NAMES[token.toLowerCase()];
  if (override) return override;
  // Title-case across hyphen/space/underscore segments.
  return token
    .split(/[-_\s]+/)
    .filter(Boolean)
    .map((seg) => seg.charAt(0).toUpperCase() + seg.slice(1))
    .join(" ");
}

/**
 * Universal brand resolver. Tokenizes the registrable label, strips phishing
 * stuffing words (payment-, secure-, login-, etc.), then for each remaining
 * candidate token checks:
 *   1. brandCatalog — entry where the canonicalDomain label, brandName, or
 *      any alias matches the token. Highest confidence; uses method "catalog".
 *   2. trancoLabelMap — the bundled Tranco top-10k list as a "known popular
 *      domains" lookup. Catches uncatalogued brands like Wikipedia or any
 *      small regional brand that happens to be in the top-10k. Method
 *      "heuristic", confidence 0.8 (exact-label match in a 10k list is a
 *      strong signal).
 *
 * Returns null when no candidate matches anywhere; existing heuristic
 * scoring + LLM fallback then take over.
 *
 * Honest disclaimer: this catches catalog ∪ Tranco. Brand-new typosquats not
 * yet indexed by Tranco and non-distinctive brand labels (e.g. "Inc") will
 * still slip through. "Flawless" is not achievable; this gets coverage from
 * ~10% (catalog-only) to majority (catalog ∪ Tranco).
 */
function resolveClaimedBrand(input: { normalizedDomain: string }):
  | { match: BrandMatch; stuffingDetected: boolean }
  | null {
  // On a shared host (blogspot.com, github.io, …) the registrable label is the
  // host itself, not an impersonated brand — don't claim "Blogspot" as the
  // victim. Let the verdict come from reputation/content floors instead.
  if (isSharedHost(input.normalizedDomain)) return null;

  const label = baseDomainLabel(input.normalizedDomain);
  if (!label) return null;
  const tokens = tokenizeDomainLabel(label);
  if (tokens.length === 0) return null;
  const { brandCandidates, stuffingTokens } = stripStuffingTokens(tokens);
  if (brandCandidates.length === 0) return null;
  const stuffingDetected = stuffingTokens.length > 0;

  // Sort longest first — more distinctive tokens win over short ones like "my".
  const ordered = [...brandCandidates].sort((a, b) => b.length - a.length);

  for (const token of ordered) {
    if (token.length < 3) continue; // skip noise like "my", "ny", "us"

    // 1. Catalog probe — exact-match on canonical label, brand name, or alias.
    const catalogHit = brandCatalog.find((entry) => {
      const entryLabel = baseDomainLabel(entry.canonicalDomain);
      if (entryLabel === token) return true;
      if (entry.brandName.toLowerCase().replace(/[^a-z0-9]/g, "") === token) return true;
      return entry.aliases.some(
        (alias) => alias.toLowerCase().replace(/[^a-z0-9]/g, "") === token
      );
    });
    if (catalogHit) {
      return {
        stuffingDetected,
        match: {
          brand_name: catalogHit.brandName,
          canonical_domain: catalogHit.canonicalDomain,
          confidence: stuffingDetected ? 0.9 : 0.95,
          method: "catalog",
          matched_keywords: stuffingTokens
        }
      };
    }

    // 2. Tranco probe — exact label match in the top-10k known-popular set.
    // Require ≥5 chars: the Tranco list is full of generic short labels
    // ("biz", "app", "web", "api", "cdn", "dev", "vpn", "now", …) that are
    // ordinary words, not impersonation targets — matching them turns random
    // domains (e.g. "…-biz-…") into bogus brand hits. The curated catalog above
    // already covers legitimately short brands (UPS, BMO, TD, CIBC).
    const trancoMatches = token.length >= 5 ? trancoLabelMap.get(token) : undefined;
    if (trancoMatches && trancoMatches.length > 0) {
      // Prefer a Tranco entry whose TLD matches the analyzed domain's TLD.
      const analyzedTld = input.normalizedDomain.split(".").slice(1).join(".");
      const sameTld = trancoMatches.find(
        (d) => d.split(".").slice(1).join(".") === analyzedTld
      );
      const chosen = sameTld ?? trancoMatches[0];
      return {
        stuffingDetected,
        match: {
          brand_name: capitalizeLabel(token),
          canonical_domain: chosen,
          confidence: 0.8,
          method: "heuristic",
          matched_keywords: stuffingTokens
        }
      };
    }
  }

  // 3. Fuzzy catalog probe — catch near-miss typosquats of a catalogued brand
  // that aren't exact matches (e.g. "sherdiancollege" ↔ "sheridancollege", a
  // single transposition). Damerau-Levenshtein handles transpositions. Tight
  // thresholds keep false positives low: token ≥5 chars, length within 2 of
  // the brand label, distance 1 (or 2 only for long labels ≥8). Skipped when
  // the source is itself a legitimate popular domain.
  if (!isLegitDomain(input.normalizedDomain)) {
    let best: { entry: (typeof brandCatalog)[number]; dist: number } | null = null;
    for (const token of ordered) {
      if (token.length < 5) continue;
      for (const entry of brandCatalog) {
        const entryLabel = baseDomainLabel(entry.canonicalDomain);
        if (entryLabel.length < 5) continue;
        if (Math.abs(entryLabel.length - token.length) > 2) continue;
        if (entryLabel === token) continue; // exact handled above
        const dist = damerauLevenshtein(token, entryLabel);
        const acceptable = dist === 1 || (dist === 2 && token.length >= 8 && entryLabel.length >= 8);
        if (acceptable && (best === null || dist < best.dist)) {
          best = { entry, dist };
        }
      }
    }
    if (best) {
      return {
        stuffingDetected,
        match: {
          brand_name: best.entry.brandName,
          canonical_domain: best.entry.canonicalDomain,
          confidence: best.dist === 1 ? 0.9 : 0.87,
          method: "heuristic",
          matched_keywords: stuffingTokens
        }
      };
    }

    // 4. Fuzzy Tranco probe — broad coverage for brands NOT in the curated
    // catalog (e.g. "faceboook" ↔ "facebook"). Stricter than the catalog fuzzy
    // pass to keep false positives down across 10k labels: token & label ≥6
    // chars, Damerau-Levenshtein exactly 1, Jaro-Winkler ≥0.92, ±1 length.
    const analyzedTld = input.normalizedDomain.split(".").slice(1).join(".");
    let trancoBest: { domain: string } | null = null;
    for (const token of ordered) {
      if (token.length < 6) continue;
      for (const [tlabel, domains] of trancoLabelMap) {
        if (tlabel.length < 6 || Math.abs(tlabel.length - token.length) > 1) continue;
        if (tlabel === token) continue; // exact handled by the Tranco probe above
        if (damerauLevenshtein(token, tlabel) !== 1) continue;
        if (jaroWinkler(token, tlabel) < 0.92) continue;
        const chosen = domains.find((d) => d.split(".").slice(1).join(".") === analyzedTld) ?? domains[0];
        trancoBest = { domain: chosen };
        break;
      }
      if (trancoBest) break;
    }
    if (trancoBest) {
      return {
        stuffingDetected,
        match: {
          brand_name: capitalizeLabel(trancoBest.domain.split(".")[0]),
          canonical_domain: trancoBest.domain,
          confidence: 0.85,
          method: "heuristic",
          matched_keywords: stuffingTokens
        }
      };
    }
  }

  return null;
}

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
  // Require canonical target ≥ 3 chars before substring-matching. Otherwise
  // brands with short canonical labels (e.g. Twitter at "x.com") false-match
  // any domain containing that letter.
  const embeddedBrandMatch =
    (canonicalTarget.length >= 3 &&
      sourceVariants.some(
        (variant) =>
          variant.includes(canonicalTarget) ||
          (variant.length >= 3 && canonicalTarget.includes(variant))
      )) ||
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
      // Deliberately NOT the catalog entry's SEO keyword list ("signin",
      // "delivery", …): matched_keywords means "tokens found in the analyzed
      // domain". Copying catalog keywords here made the scorer relabel plain
      // typos (cmazon) as keyword_stuffing for every override-scored domain.
      matched_keywords: []
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

  // Universal brand resolver: tokenize the label, strip stuffing words like
  // "payment-" / "-login", then look up the remaining candidate token in the
  // catalog AND in the Tranco top-10k. Runs in <1 ms and catches uncatalogued
  // brands the heuristic scoring loop can't reach.
  const claimed = resolveClaimedBrand({ normalizedDomain: input.normalizedDomain });
  if (claimed && claimed.match.confidence >= 0.8) {
    return claimed.match;
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
