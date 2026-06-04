import { isBlockedFetchTarget } from "@capstone/shared";

export type FetchedPage = {
  requestedUrl: string;
  finalUrl: string;
  redirectChain: string[];
  statusCode: number | null;
  html: string | null;
  headers: Record<string, string>;
  fetchMs: number;
  error: string | null;
};

const MAX_REDIRECTS = 5;
const MAX_HTML_BYTES = 250_000;
const FETCH_TIMEOUT_MS = 8_000;
// Hard ceiling across ALL hops (initial request + every redirect). Without this
// a 5-redirect chain could spend 6 × per-hop timeout (~48s) and blow the API
// Gateway 29s limit. Each hop is given whichever is smaller: the per-hop
// timeout or the budget remaining.
const TOTAL_FETCH_BUDGET_MS = 15_000;
// A realistic browser UA so user-agent cloakers don't trivially serve our
// scanner a clean page (many phishing/cloaking hosts return benign content to
// obvious bots). We still never execute JS.
const BROWSER_UA =
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36";

function headersToObject(headers: Headers): Record<string, string> {
  const result: Record<string, string> = {};
  headers.forEach((value, key) => {
    result[key.toLowerCase()] = value;
  });
  return result;
}

// Pull a meta-refresh target out of HTML: <meta http-equiv="refresh"
// content="0; url=https://...">. Returns the absolute URL or null.
function extractMetaRefresh(html: string, baseUrl: string): string | null {
  const tag = html.match(/<meta[^>]+http-equiv=["']?refresh["']?[^>]*>/i)?.[0];
  if (!tag) return null;
  const content = tag.match(/content=["']?[^"'>]*url=([^"'>\s]+)/i)?.[1];
  if (!content) return null;
  try {
    return new URL(content, baseUrl).toString();
  } catch {
    return null;
  }
}

export async function fetchPage(url: string): Promise<FetchedPage> {
  const redirectChain: string[] = [];
  const startedAt = Date.now();
  let currentUrl = url;

  try {
    for (let redirectCount = 0; redirectCount <= MAX_REDIRECTS; redirectCount += 1) {
      // SSRF guard before every hop (initial + each redirect target).
      if (isBlockedFetchTarget(currentUrl)) {
        return {
          requestedUrl: url,
          finalUrl: currentUrl,
          redirectChain,
          statusCode: null,
          html: null,
          headers: {},
          fetchMs: Date.now() - startedAt,
          error: "Refused to fetch a blocked or private address."
        };
      }

      // Give this hop the smaller of the per-hop timeout and the budget left;
      // if the budget is already spent, stop here rather than start another hop.
      const remainingBudget = TOTAL_FETCH_BUDGET_MS - (Date.now() - startedAt);
      if (remainingBudget <= 0) {
        return {
          requestedUrl: url,
          finalUrl: currentUrl,
          redirectChain,
          statusCode: null,
          html: null,
          headers: {},
          fetchMs: Date.now() - startedAt,
          error: "Fetch budget exceeded"
        };
      }

      const response = await fetch(currentUrl, {
        method: "GET",
        redirect: "manual",
        headers: {
          "user-agent": BROWSER_UA,
          accept: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
        },
        signal: AbortSignal.timeout(Math.min(FETCH_TIMEOUT_MS, remainingBudget))
      });

      if (response.status >= 300 && response.status < 400) {
        const location = response.headers.get("location");
        if (!location) {
          break;
        }
        const nextUrl = new URL(location, currentUrl).toString();
        redirectChain.push(nextUrl);
        currentUrl = nextUrl;
        continue;
      }

      const headers = headersToObject(response.headers);
      const body = (await response.text()).slice(0, MAX_HTML_BYTES);

      // Follow ONE meta-refresh hop (still within the redirect budget) so a
      // landing page that bounces via <meta refresh> reveals its destination.
      if (redirectCount < MAX_REDIRECTS) {
        const metaTarget = extractMetaRefresh(body, currentUrl);
        if (metaTarget && metaTarget !== currentUrl && !isBlockedFetchTarget(metaTarget)) {
          redirectChain.push(metaTarget);
          currentUrl = metaTarget;
          continue;
        }
      }

      return {
        requestedUrl: url,
        finalUrl: currentUrl,
        redirectChain,
        statusCode: response.status,
        html: body,
        headers,
        fetchMs: Date.now() - startedAt,
        error: null
      };
    }

    return {
      requestedUrl: url,
      finalUrl: currentUrl,
      redirectChain,
      statusCode: null,
      html: null,
      headers: {},
      fetchMs: Date.now() - startedAt,
      error: "Too many redirects"
    };
  } catch (error) {
    return {
      requestedUrl: url,
      finalUrl: currentUrl,
      redirectChain,
      statusCode: null,
      html: null,
      headers: {},
      fetchMs: Date.now() - startedAt,
      error: error instanceof Error ? error.message : "Unknown fetch error"
    };
  }
}
