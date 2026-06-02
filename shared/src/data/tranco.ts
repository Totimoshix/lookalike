// Bundled Tranco top-10k registrable domains. Two consumers:
//   - extension service worker uses it as the "popular sites" allowlist
//     to skip /analyze/fast calls (extension/src/background/allowlistData.ts).
//   - API brand matcher uses it as a known-good registrable-domains lookup
//     for universal brand identification (resolveClaimedBrand in
//     api/src/services/brandMatcher.ts).
//
// Raw array lives in trancoTop10k.generated.ts so both Vite and Node can
// import it identically. Regenerate with `npm run build:allowlist`.

import { TRANCO_DOMAINS_RAW } from "./trancoTop10k.generated.js";

export const TRANCO_DOMAINS: readonly string[] = TRANCO_DOMAINS_RAW;

export const trancoDomainSet: ReadonlySet<string> = new Set(
  TRANCO_DOMAINS.map((d) => d.toLowerCase())
);

/**
 * A registrable domain is treated as legitimate (not a lookalike of anything)
 * if it is itself a top-10k popular domain — a domain cannot impersonate
 * itself. Used to suppress lookalike scoring for real sites. Reputation
 * signals (Safe Browsing, phishing feeds) are checked separately and still
 * apply, so a genuinely compromised popular domain can still be flagged.
 */
export function isLegitDomain(registrableDomain: string | null | undefined): boolean {
  if (!registrableDomain) return false;
  return trancoDomainSet.has(registrableDomain.toLowerCase());
}

// label → list of registrable domains that have that exact label.
// e.g. "google" → ["google.com", "google.co.uk", "google.de", ...]
//      "sheridancollege" → ["sheridancollege.ca"]
// Used by the universal brand resolver to look up uncatalogued brands.
export const trancoLabelMap: ReadonlyMap<string, readonly string[]> = (() => {
  const map = new Map<string, string[]>();
  for (const domain of TRANCO_DOMAINS) {
    const lower = domain.toLowerCase();
    // Take the first dot-separated label. For most popular sites this is the
    // recognizable brand label (google, wikipedia, sheridancollege).
    const label = lower.split(".")[0];
    if (!label) continue;
    const list = map.get(label);
    if (list) {
      list.push(lower);
    } else {
      map.set(label, [lower]);
    }
  }
  return map;
})();
