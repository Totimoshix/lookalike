import { getDomain, parse } from "tldts";
import type { LookalikeCandidate } from "./schema.js";

const suspiciousTlds = new Set([
  "biz",
  "click",
  "country",
  "gq",
  "info",
  "live",
  "monster",
  "online",
  "pw",
  "ru",
  "shop",
  "support",
  "top",
  "vip",
  "work",
  "xyz"
]);

const brandKeywords = ["account", "billing", "confirm", "login", "portal", "secure", "signin", "unlock", "update", "verify"];

const keyboardAdjacency: Record<string, string[]> = {
  a: ["q", "s", "w", "z"],
  b: ["f", "g", "h", "n", "v"],
  c: ["d", "f", "v", "x"],
  d: ["c", "e", "f", "r", "s", "x"],
  e: ["d", "r", "s", "w"],
  g: ["b", "f", "h", "t", "v", "y"],
  i: ["j", "k", "o", "u"],
  l: ["k", "o", "p"],
  m: ["j", "k", "n"],
  n: ["b", "h", "j", "m"],
  o: ["i", "k", "l", "p"],
  p: ["l", "o"],
  r: ["d", "e", "f", "t"],
  s: ["a", "d", "e", "w", "x", "z"],
  t: ["f", "g", "r", "y"],
  u: ["h", "i", "j", "y"],
  v: ["b", "c", "f", "g"],
  w: ["a", "e", "q", "s"],
  x: ["c", "d", "s", "z"],
  y: ["g", "h", "t", "u"],
  z: ["a", "s", "x"]
};

const homoglyphMap: Record<string, string[]> = {
  a: ["@", "à", "á", "а"],
  c: ["ç", "с"],
  e: ["3", "é", "е"],
  g: ["9"],
  i: ["1", "l", "í", "і"],
  l: ["1", "i", "|"],
  o: ["0", "ó", "о"],
  s: ["5", "$"],
  u: ["ü"],
  y: ["ý"]
};

export type NormalizedInput = {
  originalInput: string;
  normalizedUrl: string;
  hostname: string;
  registrableDomain: string;
  subdomain: string | null;
  isIdn: boolean;
  punycodeHostname: string | null;
  tld: string | null;
  isIpLiteral: boolean;
};

export function normalizeInputUrl(input: string): NormalizedInput {
  const trimmed = input.trim();
  const candidate = /^https?:\/\//i.test(trimmed) ? trimmed : `https://${trimmed}`;
  const url = new URL(candidate);
  const registrableDomain = getDomain(url.hostname, { allowPrivateDomains: true }) ?? url.hostname;
  const parsed = parse(url.hostname);
  const punycodeHostname = url.hostname.startsWith("xn--") || url.hostname.includes(".xn--") ? url.hostname : null;

  return {
    originalInput: input,
    normalizedUrl: url.toString(),
    hostname: url.hostname.toLowerCase(),
    registrableDomain: registrableDomain.toLowerCase(),
    subdomain: parsed.subdomain ?? null,
    isIdn: punycodeHostname !== null,
    punycodeHostname,
    tld: parsed.publicSuffix ?? null,
    isIpLiteral: Boolean(parsed.isIp)
  };
}

export function baseDomainLabel(domain: string): string {
  const registrable = getDomain(domain, { allowPrivateDomains: true }) ?? domain;
  return registrable.split(".")[0] ?? registrable;
}

export function levenshtein(a: string, b: string): number {
  const matrix = Array.from({ length: a.length + 1 }, () => new Array<number>(b.length + 1).fill(0));

  for (let i = 0; i <= a.length; i += 1) {
    matrix[i][0] = i;
  }
  for (let j = 0; j <= b.length; j += 1) {
    matrix[0][j] = j;
  }

  for (let i = 1; i <= a.length; i += 1) {
    for (let j = 1; j <= b.length; j += 1) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      matrix[i][j] = Math.min(
        matrix[i - 1][j] + 1,
        matrix[i][j - 1] + 1,
        matrix[i - 1][j - 1] + cost
      );
    }
  }

  return matrix[a.length][b.length];
}

export function damerauLevenshtein(a: string, b: string): number {
  const da = new Map<string, number>();
  const maxDistance = a.length + b.length;
  const d = Array.from({ length: a.length + 2 }, () => new Array<number>(b.length + 2).fill(0));

  d[0][0] = maxDistance;
  for (let i = 0; i <= a.length; i += 1) {
    d[i + 1][0] = maxDistance;
    d[i + 1][1] = i;
  }
  for (let j = 0; j <= b.length; j += 1) {
    d[0][j + 1] = maxDistance;
    d[1][j + 1] = j;
  }

  for (let i = 1; i <= a.length; i += 1) {
    let db = 0;
    for (let j = 1; j <= b.length; j += 1) {
      const i1 = da.get(b[j - 1]) ?? 0;
      const j1 = db;
      let cost = 1;

      if (a[i - 1] === b[j - 1]) {
        cost = 0;
        db = j;
      }

      d[i + 1][j + 1] = Math.min(
        d[i][j] + cost,
        d[i + 1][j] + 1,
        d[i][j + 1] + 1,
        d[i1][j1] + (i - i1 - 1) + 1 + (j - j1 - 1)
      );
    }
    da.set(a[i - 1], i);
  }

  return d[a.length + 1][b.length + 1];
}

export function jaroWinkler(a: string, b: string): number {
  if (a === b) {
    return 1;
  }

  const matchDistance = Math.floor(Math.max(a.length, b.length) / 2) - 1;
  const aMatches = new Array<boolean>(a.length).fill(false);
  const bMatches = new Array<boolean>(b.length).fill(false);
  let matches = 0;

  for (let i = 0; i < a.length; i += 1) {
    const start = Math.max(0, i - matchDistance);
    const end = Math.min(i + matchDistance + 1, b.length);

    for (let j = start; j < end; j += 1) {
      if (bMatches[j] || a[i] !== b[j]) {
        continue;
      }
      aMatches[i] = true;
      bMatches[j] = true;
      matches += 1;
      break;
    }
  }

  if (matches === 0) {
    return 0;
  }

  let transpositions = 0;
  let k = 0;
  for (let i = 0; i < a.length; i += 1) {
    if (!aMatches[i]) {
      continue;
    }
    while (!bMatches[k]) {
      k += 1;
    }
    if (a[i] !== b[k]) {
      transpositions += 1;
    }
    k += 1;
  }

  const jaro =
    (matches / a.length + matches / b.length + (matches - transpositions / 2) / matches) /
    3;

  let prefix = 0;
  for (let i = 0; i < Math.min(4, a.length, b.length); i += 1) {
    if (a[i] === b[i]) {
      prefix += 1;
    } else {
      break;
    }
  }

  return jaro + prefix * 0.1 * (1 - jaro);
}

export function ngramSimilarity(a: string, b: string, size = 2): number {
  const grams = (value: string) => {
    const set = new Set<string>();
    for (let index = 0; index <= value.length - size; index += 1) {
      set.add(value.slice(index, index + size));
    }
    return set;
  };

  const aGrams = grams(a);
  const bGrams = grams(b);
  if (aGrams.size === 0 || bGrams.size === 0) {
    return 0;
  }
  let overlap = 0;
  for (const gram of aGrams) {
    if (bGrams.has(gram)) {
      overlap += 1;
    }
  }
  return overlap / new Set([...aGrams, ...bGrams]).size;
}

export function urlEntropy(value: string): number {
  const counts = new Map<string, number>();
  for (const char of value) {
    counts.set(char, (counts.get(char) ?? 0) + 1);
  }
  let entropy = 0;
  for (const count of counts.values()) {
    const probability = count / value.length;
    entropy -= probability * Math.log2(probability);
  }
  return Number(entropy.toFixed(3));
}

export function detectHomoglyphPattern(input: string, target: string): string | null {
  for (const [canonical, variants] of Object.entries(homoglyphMap)) {
    for (const variant of variants) {
      if (input.includes(variant) && target.includes(canonical)) {
        return `${variant}->${canonical}`;
      }
    }
  }
  return null;
}

export function isHomoglyphDomain(input: string, target: string): boolean {
  return detectHomoglyphPattern(input, target) !== null;
}

export function keyboardProximityScore(input: string, target: string): number {
  const maxLength = Math.max(input.length, target.length);
  if (maxLength === 0) {
    return 0;
  }
  let nearby = 0;
  for (let index = 0; index < Math.min(input.length, target.length); index += 1) {
    const current = input[index];
    const expected = target[index];
    if (current === expected) {
      nearby += 1;
      continue;
    }
    if (keyboardAdjacency[expected]?.includes(current)) {
      nearby += 0.75;
    }
  }
  return Number((nearby / maxLength).toFixed(3));
}

export function classifyTyposquatting(input: string, target: string): string | null {
  if (input === target) {
    return "exact_match";
  }
  if (input.length === target.length) {
    for (let index = 0; index < input.length - 1; index += 1) {
      const swapped =
        input.slice(0, index) +
        input[index + 1] +
        input[index] +
        input.slice(index + 2);
      if (swapped === target) {
        return "transposition";
      }
    }
    return "substitution";
  }
  if (input.length > target.length) {
    return input.includes(target) ? "keyword_stuffing" : "insertion";
  }
  return "deletion";
}

export function suspiciousKeywordsInDomain(domain: string): string[] {
  const normalized = domain.toLowerCase();
  return brandKeywords.filter((keyword) => normalized.includes(keyword));
}

export function isSuspiciousTld(tld: string | null): boolean {
  return tld ? suspiciousTlds.has(tld.toLowerCase()) : false;
}

export function hyphenationPattern(domain: string): string | null {
  if (domain.includes("--")) {
    return "multiple_hyphens";
  }
  if (domain.includes("-")) {
    return "single_hyphen";
  }
  return null;
}

export function tokenizationPattern(domain: string): string | null {
  if (/[0-9]/.test(domain) && /[a-z]/i.test(domain)) {
    return "alpha_numeric_mix";
  }
  if (domain.includes(".")) {
    return "multi_label";
  }
  return null;
}

export function generateLookalikeCandidates(canonicalDomain: string, limit = 50): LookalikeCandidate[] {
  const registrable = normalizeInputUrl(canonicalDomain).registrableDomain;
  const baseLabel = baseDomainLabel(registrable);
  const tld = registrable.split(".").slice(1).join(".");
  const candidates = new Map<string, LookalikeCandidate>();

  const patternPriority: Record<string, number> = {
    homoglyph: 1,
    transposition: 0.95,
    substitution: 0.8,
    deletion: 0.76,
    insertion: 0.72,
    token_append: 0.9
  };

  const addCandidate = (candidateLabel: string, pattern: string, notes: string[] = []) => {
    const candidateDomain = `${candidateLabel}.${tld}`;
    if (candidateDomain === registrable || candidates.has(candidateDomain)) {
      return;
    }
    candidates.set(candidateDomain, {
      candidate_domain: candidateDomain,
      pattern,
      notes,
      lexical_score: Number(jaroWinkler(candidateLabel, baseLabel).toFixed(3))
    });
  };

  for (let index = 0; index < baseLabel.length; index += 1) {
    addCandidate(baseLabel.slice(0, index) + baseLabel.slice(index + 1), "deletion");
  }

  for (let index = 0; index < baseLabel.length - 1; index += 1) {
    addCandidate(
      baseLabel.slice(0, index) + baseLabel[index + 1] + baseLabel[index] + baseLabel.slice(index + 2),
      "transposition"
    );
  }

  const alphabet = "abcdefghijklmnopqrstuvwxyz0123456789";
  for (let index = 0; index < baseLabel.length; index += 1) {
    for (const char of alphabet) {
      if (char === baseLabel[index]) {
        continue;
      }
      addCandidate(baseLabel.slice(0, index) + char + baseLabel.slice(index + 1), "substitution");
    }
  }

  for (let index = 0; index <= baseLabel.length; index += 1) {
    for (const char of alphabet) {
      addCandidate(baseLabel.slice(0, index) + char + baseLabel.slice(index), "insertion");
    }
  }

  for (const [char, variants] of Object.entries(homoglyphMap)) {
    if (!baseLabel.includes(char)) {
      continue;
    }
    for (const variant of variants) {
      addCandidate(baseLabel.replace(char, variant), "homoglyph", [`${variant} mimics ${char}`]);
    }
  }

  addCandidate(`${baseLabel}-secure`, "token_append", ["Contains suspicious security keyword"]);
  addCandidate(`${baseLabel}-login`, "token_append", ["Contains suspicious login keyword"]);
  addCandidate(`${baseLabel}support`, "token_append", ["Appends support keyword"]);

  return Array.from(candidates.values())
    .sort((left, right) => {
      const rightWeighted = right.lexical_score + (patternPriority[right.pattern] ?? 0);
      const leftWeighted = left.lexical_score + (patternPriority[left.pattern] ?? 0);
      return rightWeighted - leftWeighted;
    })
    .slice(0, limit);
}

export function safeNumber(input: number | null | undefined, fallback = 0): number {
  return Number.isFinite(input) ? Number(input) : fallback;
}

export function summarizeBoolean(value: boolean | null, truthy: string, falsy: string, unknown: string): string {
  if (value === null) {
    return unknown;
  }
  return value ? truthy : falsy;
}
