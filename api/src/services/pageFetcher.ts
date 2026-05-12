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

function headersToObject(headers: Headers): Record<string, string> {
  const result: Record<string, string> = {};
  headers.forEach((value, key) => {
    result[key.toLowerCase()] = value;
  });
  return result;
}

export async function fetchPage(url: string): Promise<FetchedPage> {
  const redirectChain: string[] = [];
  const startedAt = Date.now();
  let currentUrl = url;

  try {
    for (let redirectCount = 0; redirectCount <= MAX_REDIRECTS; redirectCount += 1) {
      const response = await fetch(currentUrl, {
        method: "GET",
        redirect: "manual",
        headers: {
          "user-agent": "CapstoneDomainGuardian/0.1"
        }
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
      const body = await response.text();

      return {
        requestedUrl: url,
        finalUrl: currentUrl,
        redirectChain,
        statusCode: response.status,
        html: body.slice(0, MAX_HTML_BYTES),
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

