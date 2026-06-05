import {
  baseDomainLabel,
  jaroWinkler,
  lookalikeCandidateSchema,
  normalizeInputUrl,
  type LookalikeCandidate
} from "@capstone/shared";

type DnsTwisterFuzzyDomain = {
  domain?: unknown;
  fuzzer?: unknown;
};

type DnsTwisterFuzzResponse = {
  fuzzy_domains?: unknown;
};

const defaultApiBaseUrl = "https://dnstwister.report/api";
const defaultTimeoutMs = 10_000;

const patternMap: Record<string, string> = {
  Bitsquatting: "bitsquatting",
  Homoglyph: "homoglyph",
  Hyphenation: "hyphenation",
  Insertion: "insertion",
  Omission: "omission",
  Original: "original",
  Repetition: "repetition",
  Replacement: "replacement",
  Subdomain: "subdomain",
  Transposition: "transposition",
  Various: "various",
  "Vowel swap": "vowel_swap"
};

function normalizeDnsTwisterPattern(fuzzer: string): string {
  return patternMap[fuzzer] ?? fuzzer.trim().toLowerCase().replace(/\s+/g, "_");
}

function candidateComparisonLabel(candidateDomain: string, canonicalTld: string): string {
  const normalizedCandidate = candidateDomain.toLowerCase();
  const tldSuffix = canonicalTld.length > 0 ? `.${canonicalTld.toLowerCase()}` : "";

  if (tldSuffix && normalizedCandidate.endsWith(tldSuffix)) {
    return normalizedCandidate.slice(0, -tldSuffix.length).replace(/[.-]/g, "");
  }

  return normalizedCandidate.split(".").slice(0, -1).join("").replace(/-/g, "");
}

function lexicalScoreForCandidate(candidateDomain: string, canonicalDomain: string): number {
  const canonicalLabel = baseDomainLabel(canonicalDomain).toLowerCase();
  const canonicalTld = canonicalDomain.split(".").slice(1).join(".");
  const candidateLabel = candidateComparisonLabel(candidateDomain, canonicalTld);

  return Number(jaroWinkler(candidateLabel, canonicalLabel).toFixed(3));
}

function parseFuzzyDomains(payload: unknown): DnsTwisterFuzzyDomain[] {
  if (!payload || typeof payload !== "object") {
    return [];
  }

  const fuzzyDomains = (payload as DnsTwisterFuzzResponse).fuzzy_domains;
  if (!Array.isArray(fuzzyDomains)) {
    return [];
  }

  return fuzzyDomains.filter((entry) => entry && typeof entry === "object") as DnsTwisterFuzzyDomain[];
}

export async function fetchDnsTwisterLookalikes(
  canonicalDomain: string,
  limit = 50
): Promise<LookalikeCandidate[]> {
  const normalized = normalizeInputUrl(canonicalDomain);
  const apiBaseUrl = (process.env.DNSTWISTER_API_BASE_URL ?? defaultApiBaseUrl).replace(/\/+$/, "");
  const timeoutMs = Number(process.env.DNSTWISTER_TIMEOUT_MS ?? defaultTimeoutMs);
  const domainHex = Buffer.from(normalized.registrableDomain, "utf8").toString("hex");
  const response = await fetch(`${apiBaseUrl}/fuzz/${domainHex}`, {
    headers: {
      accept: "application/json"
    },
    signal: AbortSignal.timeout(Number.isFinite(timeoutMs) ? timeoutMs : defaultTimeoutMs)
  });

  if (!response.ok) {
    throw new Error(`DNSTwister lookup failed with status ${response.status}`);
  }

  const payload = parseFuzzyDomains(await response.json());
  const uniqueCandidates = new Map<string, LookalikeCandidate>();

  for (const entry of payload) {
    if (typeof entry.domain !== "string" || typeof entry.fuzzer !== "string") {
      continue;
    }

    const candidateDomain = entry.domain.trim().toLowerCase();
    if (!candidateDomain || candidateDomain === normalized.registrableDomain) {
      continue;
    }

    if (uniqueCandidates.has(candidateDomain)) {
      continue;
    }

    const candidate = lookalikeCandidateSchema.parse({
      candidate_domain: candidateDomain,
      pattern: normalizeDnsTwisterPattern(entry.fuzzer),
      notes: [`Source: DNSTwister`, `DNSTwister fuzzer: ${entry.fuzzer}`],
      lexical_score: lexicalScoreForCandidate(candidateDomain, normalized.registrableDomain)
    });

    uniqueCandidates.set(candidateDomain, candidate);
  }

  return Array.from(uniqueCandidates.values()).slice(0, limit);
}
