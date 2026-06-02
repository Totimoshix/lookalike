import type { AnalysisResult, EvidenceSummary } from "@capstone/shared";

type EvidenceItem = EvidenceSummary["evidence_items"][number];

const SEVERITY_ORDER: Record<EvidenceItem["severity"], number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4
};

type Translator = (item: EvidenceItem, brand: string) => string;

const TRANSLATIONS: Record<string, Translator> = {
  homoglyph: (_, brand) =>
    brand && brand !== "Unknown"
      ? `Spelled with lookalike characters (e.g. '0' for 'o') to copy ${brand}`
      : "Spelled with lookalike characters meant to mimic a real brand",
  keyword_stuffing: (_, brand) =>
    brand && brand !== "Unknown"
      ? `Combines a phishing word (like 'payment-' or 'login-') with the real ${brand} name`
      : "Combines a phishing word (like 'payment-' or 'login-') with a real brand name",
  redirect_offdomain: (item) => {
    const dest = typeof item.value === "string" && item.value ? item.value : item.note ?? null;
    let host: string | null = null;
    if (dest) {
      try {
        host = new URL(dest).hostname;
      } catch {
        host = dest;
      }
    }
    return host
      ? `Secretly sends you to ${host}, an unrelated site`
      : "Secretly redirects you to an unrelated site";
  },
  client_side_redirect: () => "Uses a hidden script to redirect you somewhere else",
  domain_age: (item) => {
    const days = typeof item.value === "number" ? item.value : null;
    if (days === null) return "Registered very recently";
    if (days < 1) return "Registered less than a day ago";
    if (days === 1) return "Registered yesterday";
    return `Registered only ${days} days ago`;
  },
  credential_form: () => "Page asks you to enter a password",
  form_action: (_, brand) =>
    brand && brand !== "Unknown"
      ? `Form sends data to ${brand}'s real domain — a classic phishing pattern`
      : "Form sends data to a different site than the one you're on",
  gsb: () => "Google has flagged this site as dangerous",
  phishing_feed_hits: (item) => {
    const n = typeof item.value === "number" ? item.value : null;
    return n && n > 0
      ? `Listed on ${n} public phishing report${n === 1 ? "" : "s"}`
      : "Listed on a public phishing report";
  },
  ssl_valid: (item) =>
    `The site's security certificate is invalid${item.note ? ` (${item.note})` : ""}`,
  email_auth: () => "The domain has no email authentication set up",
  external_form_action: () => "Form on this page submits data to an outside server",
  archive_first_seen: (item) => {
    const days = typeof item.value === "number" ? item.value : null;
    return days === null
      ? "Recently first observed on the web"
      : `First seen on the web only ${days} days ago`;
  },
  passive_history_notes: (item) => item.note ?? "Unusual historical activity for this domain"
};

function brandLabel(result: AnalysisResult): string {
  return result.brand_match.brand_name === "Unknown" ? "" : result.brand_match.brand_name;
}

export function toPlainBullet(item: EvidenceItem, result: AnalysisResult): string {
  const translate = TRANSLATIONS[item.key];
  if (translate) return translate(item, brandLabel(result));
  return item.note ?? item.label;
}

export function pickTopReasons(result: AnalysisResult, max = 3): string[] {
  const items = [...result.evidence_summary.evidence_items].sort((a, b) => {
    const sev = SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity];
    if (sev !== 0) return sev;
    return 0;
  });
  const seen = new Set<string>();
  const bullets: string[] = [];
  for (const item of items) {
    const text = toPlainBullet(item, result);
    if (seen.has(text)) continue;
    seen.add(text);
    bullets.push(text);
    if (bullets.length >= max) break;
  }
  if (bullets.length === 0 && result.evidence_summary.highlights.length > 0) {
    return result.evidence_summary.highlights.slice(0, max);
  }
  return bullets;
}

export type VerdictTone = "safe" | "caution" | "warning" | "danger" | "unknown";

export function toneForVerdict(verdict: AnalysisResult["verdict"]): VerdictTone {
  switch (verdict) {
    case "Safe":
    case "Low":
      return "safe";
    case "Medium":
      return "caution";
    case "High":
      return "warning";
    case "Critical":
    case "Malicious":
      return "danger";
    default:
      return "unknown";
  }
}

export function headlineForVerdict(verdict: AnalysisResult["verdict"]): string {
  switch (verdict) {
    case "Safe":
      return "Looks safe";
    case "Low":
      return "Probably safe";
    case "Medium":
      return "Be careful";
    case "High":
      return "High risk";
    case "Critical":
      return "Likely phishing";
    case "Malicious":
      return "Known malicious site";
    default:
      return "Couldn't verify";
  }
}

export function shortSummary(result: AnalysisResult): string {
  const brand = brandLabel(result);
  const reasoning = result.reasoning ?? "";
  const firstSentence = reasoning.split(/(?<=[.!?])\s+/)[0] ?? reasoning;
  if (firstSentence) return firstSentence;
  if (result.verdict === "Safe" || result.verdict === "Low") {
    return `No major risk indicators found for ${result.normalized_domain}.`;
  }
  return brand
    ? `This site appears to impersonate ${brand}.`
    : `This site shows several phishing risk indicators.`;
}
