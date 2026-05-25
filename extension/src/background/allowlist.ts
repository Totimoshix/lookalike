import { ALLOWLIST_DOMAINS } from "./allowlistData";

const allowSet = new Set(ALLOWLIST_DOMAINS.map((d) => d.toLowerCase()));

export function isAllowlisted(domain: string): boolean {
  return allowSet.has(domain.toLowerCase());
}
