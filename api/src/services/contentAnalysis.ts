import { load } from "cheerio";
import { baseDomainLabel } from "@capstone/shared";
import type { BrandMatch, RiskFactors } from "@capstone/shared";

type PageContentAnalysis = {
  content: RiskFactors["content"];
  externalFormAction: boolean | null;
  // A script- or meta-based redirect target extracted from the page (absolute
  // URL), when it's a static string literal. null if none or built dynamically.
  clientSideRedirectTarget: string | null;
};

// JS redirect via location assignment: location(.href|.replace|.assign) = "URL"
// or window/top.location[.href] = "URL". Captures the first string-literal URL.
const JS_REDIRECT_RE =
  /(?:window\.|top\.|self\.|document\.)?location(?:\.href|\.replace|\.assign)?\s*(?:=|\(\s*)["']([^"']+)["']/i;
const META_REFRESH_RE = /<meta[^>]+http-equiv=["']?refresh["']?[^>]*url=([^"'>\s]+)/i;

function extractClientSideRedirect(html: string, baseUrl: string | null): string | null {
  const raw = JS_REDIRECT_RE.exec(html)?.[1] ?? META_REFRESH_RE.exec(html)?.[1] ?? null;
  if (!raw) return null;
  try {
    return new URL(raw, baseUrl ?? "https://example.invalid").toString();
  } catch {
    return raw; // keep the raw token even if it isn't absolute-resolvable
  }
}

const COMMON_STOP_WORDS = new Set([
  "and",
  "are",
  "com",
  "for",
  "from",
  "http",
  "https",
  "login",
  "page",
  "secure",
  "signin",
  "that",
  "the",
  "this",
  "with",
  "www"
]);

function tokenizeText(value: string): string[] {
  return value
    .toLowerCase()
    .split(/[^a-z0-9]+/g)
    .map((token) => token.trim())
    .filter((token) => token.length >= 3 && !COMMON_STOP_WORDS.has(token));
}

function normalizedOverlap(left: Iterable<string>, right: Iterable<string>): number {
  const leftSet = new Set(left);
  const rightSet = new Set(right);
  if (leftSet.size === 0 || rightSet.size === 0) {
    return 0;
  }

  let intersection = 0;
  for (const value of leftSet) {
    if (rightSet.has(value)) {
      intersection += 1;
    }
  }

  return intersection / Math.max(leftSet.size, rightSet.size);
}

function buildBrandTokens(brandMatch: BrandMatch | null): string[] {
  if (!brandMatch || brandMatch.method === "unknown") {
    return [];
  }

  const rawTokens = [
    brandMatch.brand_name,
    baseDomainLabel(brandMatch.canonical_domain),
    ...brandMatch.matched_keywords
  ];

  return Array.from(new Set(rawTokens.flatMap((token) => tokenizeText(token))));
}

export function analyzePageContent(
  html: string | null,
  headers: Record<string, string>,
  redirectChain: string[],
  brandMatch: BrandMatch | null,
  pageUrl: string | null
): PageContentAnalysis {
  if (!html) {
    return {
      content: {
        page_title: null,
        html_similarity_score: null,
        logo_reuse_detected: null,
        text_reuse_score: null,
        credential_harvesting_detected: null,
        forms_detected: null,
        password_fields_detected: null,
        form_submits_to_real_brand: null,
        hidden_iframes: null,
        obfuscated_javascript: null,
        suspicious_script_patterns: [],
        missing_security_headers: [],
        server_header_exposure: headers.server ?? null,
        redirect_chain: redirectChain,
        body_keywords: []
      },
      externalFormAction: null,
      clientSideRedirectTarget: null
    };
  }

  const $ = load(html);
  const pageTitle = $("title").first().text().trim() || null;
  const forms = $("form");
  const passwordFields = $("input[type='password']");
  const hiddenIframes = $("iframe").filter((_: number, element: any) => {
    const style = ($(element).attr("style") ?? "").toLowerCase();
    return style.includes("display:none") || style.includes("visibility:hidden") || $(element).attr("hidden") !== undefined;
  });
  const suspiciousPatterns = new Set<string>();
  const pageHostname = pageUrl ? new URL(pageUrl).hostname.toLowerCase() : null;
  const brandDomain = brandMatch?.canonical_domain.toLowerCase() ?? null;
  const brandLabel = brandMatch ? baseDomainLabel(brandMatch.canonical_domain).toLowerCase() : null;

  $("script").each((_: number, element: any) => {
    const content = $(element).html() ?? "";
    if (/eval\(|atob\(|fromcharcode|unescape\(/i.test(content)) {
      suspiciousPatterns.add("script_obfuscation");
    }
    if (/addEventListener\(['"]keydown|keyup|keypress/i.test(content)) {
      suspiciousPatterns.add("keyboard_capture");
    }
    if (/fetch\(|xmlhttprequest|navigator\.sendBeacon/i.test(content)) {
      suspiciousPatterns.add("network_postback");
    }
  });

  // Client-side redirect (JS location assignment or <meta refresh>). These
  // bounce a visitor elsewhere without an HTTP 30x — a common cloaking vector.
  const clientSideRedirectTarget = extractClientSideRedirect(html, pageUrl);
  const hasClientSideRedirect =
    clientSideRedirectTarget !== null || JS_REDIRECT_RE.test(html) || META_REFRESH_RE.test(html);
  if (hasClientSideRedirect) {
    suspiciousPatterns.add("client_side_redirect");
  }

  const missingSecurityHeaders = ["content-security-policy", "x-frame-options", "strict-transport-security"].filter(
    (header) => !headers[header]
  );
  const bodyText = $("body").text().replace(/\s+/g, " ").trim();
  const normalizedBodyText = bodyText.toLowerCase();
  const brandTokens = buildBrandTokens(brandMatch);
  const bodyTokens = tokenizeText(bodyText);
  const titleTokens = tokenizeText(pageTitle ?? "");
  const textReuse = brandTokens.length > 0 ? normalizedOverlap(brandTokens, bodyTokens) : 0;
  const titleReuse = brandTokens.length > 0 ? normalizedOverlap(brandTokens, titleTokens) : 0;
  const logoReuseDetected = brandMatch
    ? $("img, link[rel*='icon']")
        .toArray()
        .some((asset: any) => {
          const src = ($(asset).attr("src") ?? $(asset).attr("href") ?? "").toLowerCase();
          const alt = ($(asset).attr("alt") ?? "").toLowerCase();
          if (!src && !alt) {
            return false;
          }

          const assetHost = src.startsWith("http://") || src.startsWith("https://") ? new URL(src).hostname.toLowerCase() : null;
          return (
            (brandLabel !== null && (src.includes(brandLabel) || alt.includes(brandLabel))) ||
            (brandDomain !== null && assetHost !== null && assetHost.endsWith(brandDomain))
          );
        })
    : null;

  const formActions = forms
    .toArray()
    .map((form: any) => ($(form).attr("action") ?? "").trim())
    .filter(Boolean);

  const formSubmitsToRealBrand =
    brandDomain && formActions.length > 0
      ? formActions.some((action) => {
          try {
            const host = new URL(action, pageUrl ?? "https://example.invalid").hostname.toLowerCase();
            return host.endsWith(brandDomain);
          } catch {
            return false;
          }
        })
      : brandLabel && formActions.length > 0
        ? formActions.some((action) => action.toLowerCase().includes(brandLabel))
        : null;

  const externalFormAction =
    formActions.length > 0 && pageHostname
      ? formActions.some((action) => {
          try {
            const targetHost = new URL(action, pageUrl ?? `https://${pageHostname}`).hostname.toLowerCase();
            return targetHost !== pageHostname;
          } catch {
            return false;
          }
        })
      : null;

  const bodyKeywords = Array.from(
    new Set(
      ["account", "billing", "confirm", "password", "secure", "signin", "unlock", "verify"].filter((keyword) =>
        normalizedBodyText.includes(keyword)
      )
    )
  );

  const htmlSimilarityScore =
    brandTokens.length > 0
      ? Number(Math.min(1, textReuse * 0.6 + titleReuse * 0.25 + (logoReuseDetected ? 0.15 : 0)).toFixed(2))
      : null;

  return {
    content: {
      page_title: pageTitle,
      html_similarity_score: htmlSimilarityScore,
      logo_reuse_detected: logoReuseDetected,
      text_reuse_score: brandTokens.length > 0 ? Number(textReuse.toFixed(2)) : null,
      credential_harvesting_detected: forms.length > 0 && passwordFields.length > 0,
      forms_detected: forms.length,
      password_fields_detected: passwordFields.length,
      form_submits_to_real_brand: formSubmitsToRealBrand,
      hidden_iframes: hiddenIframes.length > 0,
      obfuscated_javascript: suspiciousPatterns.has("script_obfuscation"),
      suspicious_script_patterns: Array.from(suspiciousPatterns),
      missing_security_headers: missingSecurityHeaders,
      server_header_exposure: headers.server ?? null,
      redirect_chain: redirectChain,
      body_keywords: bodyKeywords
    },
    externalFormAction,
    clientSideRedirectTarget
  };
}
