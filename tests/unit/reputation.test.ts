import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { collectReputationSignals, matchesPhishingFeed } from "../../api/src/services/reputation";

describe("matchesPhishingFeed — multi-tenant host suppression", () => {
  it("does NOT condemn a legit apex when a feed lists an abused path on it", () => {
    // Phishers submit google.com open-redirects / hosted paths to feeds. The
    // real homepage must not be flagged by a feed-listed deep link.
    const feed = ["https://google.com/url?q=https://evil.example/login"];
    expect(matchesPhishingFeed("https://google.com", feed)).toBe(false);
  });

  it("DOES flag the exact feed-listed URL even on a legit apex", () => {
    const feed = ["https://google.com/url?q=https://evil.example/login"];
    expect(matchesPhishingFeed("https://google.com/url?q=https://evil.example/login", feed)).toBe(true);
  });

  it("flags the specific malicious subdomain of a shared host (not the apex)", () => {
    const feed = ["https://evilphish.blogspot.com/login"];
    expect(matchesPhishingFeed("https://evilphish.blogspot.com/login", feed)).toBe(true);
    expect(matchesPhishingFeed("https://blogspot.com", feed)).toBe(false);
  });

  it("matches an ordinary (non-legit, non-shared) domain by registrable domain", () => {
    const feed = ["https://phish.example/login"];
    expect(matchesPhishingFeed("https://phish.example/other-path", feed)).toBe(true);
  });
});

describe("collectReputationSignals", () => {
  const originalEnv = {
    VT_API_KEY: process.env.VT_API_KEY,
    ABUSEIPDB_API_KEY: process.env.ABUSEIPDB_API_KEY,
    GOOGLE_SAFE_BROWSING_API_KEY: process.env.GOOGLE_SAFE_BROWSING_API_KEY
  };

  beforeEach(() => {
    delete process.env.VT_API_KEY;
    delete process.env.ABUSEIPDB_API_KEY;
    delete process.env.GOOGLE_SAFE_BROWSING_API_KEY;
  });

  afterEach(() => {
    vi.restoreAllMocks();
    vi.unstubAllGlobals();

    process.env.VT_API_KEY = originalEnv.VT_API_KEY;
    process.env.ABUSEIPDB_API_KEY = originalEnv.ABUSEIPDB_API_KEY;
    process.env.GOOGLE_SAFE_BROWSING_API_KEY = originalEnv.GOOGLE_SAFE_BROWSING_API_KEY;
  });

  it("returns configured-state diagnostics and feed hits without placeholder null messaging", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL) => {
        const url = String(input);

        if (url.includes("openphish")) {
          return new Response("https://phish.example/login\n", {
            status: 200,
            headers: {
              "content-type": "text/plain"
            }
          });
        }

        if (url.includes("phishtank")) {
          return new Response(
            JSON.stringify([
              {
                url: "https://phish.example/login"
              }
            ]),
            {
              status: 200,
              headers: {
                "content-type": "application/json"
              }
            }
          );
        }

        throw new Error(`Unexpected fetch to ${url}`);
      })
    );

    const result = await collectReputationSignals("https://phish.example/login", "203.0.113.20");

    expect(result.reputational.blacklisted_in_openPhish).toBe(true);
    expect(result.reputational.blacklisted_in_phishTank).toBe(true);
    expect(result.reputational.phishing_feed_hits).toBe(2);
    expect(result.diagnostics.find((diagnostic) => diagnostic.provider === "virustotal")?.status).toBe("not_configured");
    expect(result.diagnostics.find((diagnostic) => diagnostic.provider === "abuseipdb")?.status).toBe("not_configured");
    expect(result.diagnostics.find((diagnostic) => diagnostic.provider === "google_safe_browsing")?.status).toBe(
      "not_configured"
    );
    expect(result.diagnostics.find((diagnostic) => diagnostic.provider === "openphish")?.status).toBe("ok");
    expect(result.diagnostics.find((diagnostic) => diagnostic.provider === "phishtank")?.status).toBe("ok");
  });
});
