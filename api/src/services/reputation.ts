import { isLegitDomain, isSharedHost, normalizeInputUrl, type RiskFactors, type SignalDiagnostic } from "@capstone/shared";
import { withTtlCache } from "./feedCache.js";
import { getRuntimeConfig } from "./runtimeConfig.js";

type ReputationResult = RiskFactors["reputational"];

type ReputationCollectionResult = {
  reputational: ReputationResult;
  diagnostics: SignalDiagnostic[];
};

type ProviderCheckResult<T> = {
  value: T | null;
  diagnostic: SignalDiagnostic;
};

type PhishTankEntry = {
  url?: unknown;
};

const FEED_TTL_MS = 15 * 60 * 1000;
const PROVIDER_TIMEOUT_MS = 8000;

function okDiagnostic(signal: string, provider: string): SignalDiagnostic {
  return {
    signal,
    provider,
    status: "ok"
  };
}

function queryFailedDiagnostic(signal: string, provider: string, detail: string): SignalDiagnostic {
  return {
    signal,
    provider,
    status: "query_failed",
    detail
  };
}

function notConfiguredDiagnostic(signal: string, provider: string, detail: string): SignalDiagnostic {
  return {
    signal,
    provider,
    status: "not_configured",
    detail
  };
}

function normalizeMatchTargets(url: string) {
  const normalized = normalizeInputUrl(url);

  return {
    normalizedUrl: normalized.normalizedUrl.replace(/\/$/, ""),
    hostname: normalized.hostname,
    registrableDomain: normalized.registrableDomain
  };
}

async function checkAbuseIpDb(ipAddress: string | null): Promise<ProviderCheckResult<number>> {
  const config = await getRuntimeConfig();
  if (!config.abuseIpDbApiKey) {
    return {
      value: null,
      diagnostic: notConfiguredDiagnostic("abuse_ipdb_reports", "abuseipdb", "ABUSEIPDB_API_KEY is not configured.")
    };
  }

  if (!ipAddress) {
    return {
      value: null,
      diagnostic: queryFailedDiagnostic("abuse_ipdb_reports", "abuseipdb", "No resolved IP address was available.")
    };
  }

  try {
    const response = await fetch(`https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(ipAddress)}`, {
      headers: {
        Key: config.abuseIpDbApiKey,
        Accept: "application/json"
      },
      signal: AbortSignal.timeout(PROVIDER_TIMEOUT_MS)
    });
    if (!response.ok) {
      return {
        value: null,
        diagnostic: queryFailedDiagnostic(
          "abuse_ipdb_reports",
          "abuseipdb",
          `HTTP ${response.status} returned from AbuseIPDB.`
        )
      };
    }
    const payload = (await response.json()) as { data?: { abuseConfidenceScore?: number } };
    return {
      value: payload.data?.abuseConfidenceScore ?? 0,
      diagnostic: okDiagnostic("abuse_ipdb_reports", "abuseipdb")
    };
  } catch (error) {
    return {
      value: null,
      diagnostic: queryFailedDiagnostic(
        "abuse_ipdb_reports",
        "abuseipdb",
        error instanceof Error ? error.message : "AbuseIPDB lookup failed."
      )
    };
  }
}

async function checkVirusTotal(url: string): Promise<ProviderCheckResult<number>> {
  const config = await getRuntimeConfig();
  if (!config.virusTotalApiKey) {
    return {
      value: null,
      diagnostic: notConfiguredDiagnostic("virus_total_detections", "virustotal", "VT_API_KEY is not configured.")
    };
  }

  try {
    const encoded = Buffer.from(url).toString("base64url");
    const response = await fetch(`https://www.virustotal.com/api/v3/urls/${encoded}`, {
      headers: {
        "x-apikey": config.virusTotalApiKey
      },
      signal: AbortSignal.timeout(PROVIDER_TIMEOUT_MS)
    });
    if (!response.ok) {
      return {
        value: null,
        diagnostic: queryFailedDiagnostic(
          "virus_total_detections",
          "virustotal",
          `HTTP ${response.status} returned from VirusTotal.`
        )
      };
    }
    const payload = (await response.json()) as {
      data?: { attributes?: { last_analysis_stats?: { malicious?: number; suspicious?: number } } };
    };
    const stats = payload.data?.attributes?.last_analysis_stats;

    return {
      value: stats ? (stats.malicious ?? 0) + (stats.suspicious ?? 0) : 0,
      diagnostic: okDiagnostic("virus_total_detections", "virustotal")
    };
  } catch (error) {
    return {
      value: null,
      diagnostic: queryFailedDiagnostic(
        "virus_total_detections",
        "virustotal",
        error instanceof Error ? error.message : "VirusTotal lookup failed."
      )
    };
  }
}

async function checkGoogleSafeBrowsing(url: string): Promise<ProviderCheckResult<boolean>> {
  const config = await getRuntimeConfig();
  if (!config.googleSafeBrowsingApiKey) {
    return {
      value: null,
      diagnostic: notConfiguredDiagnostic(
        "google_safe_browsing",
        "google_safe_browsing",
        "GOOGLE_SAFE_BROWSING_API_KEY is not configured."
      )
    };
  }

  try {
    const response = await fetch(
      `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${config.googleSafeBrowsingApiKey}`,
      {
        method: "POST",
        headers: {
          "content-type": "application/json"
        },
        body: JSON.stringify({
          client: {
            clientId: "capstone-domain-guardian",
            clientVersion: "1.0.0"
          },
          threatInfo: {
            threatTypes: ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
            platformTypes: ["ANY_PLATFORM"],
            threatEntryTypes: ["URL"],
            threatEntries: [{ url }]
          }
        }),
        signal: AbortSignal.timeout(PROVIDER_TIMEOUT_MS)
      }
    );
    if (!response.ok) {
      return {
        value: null,
        diagnostic: queryFailedDiagnostic(
          "google_safe_browsing",
          "google_safe_browsing",
          `HTTP ${response.status} returned from Google Safe Browsing.`
        )
      };
    }
    const payload = (await response.json()) as { matches?: unknown[] };
    return {
      value: Array.isArray(payload.matches) ? payload.matches.length > 0 : false,
      diagnostic: okDiagnostic("google_safe_browsing", "google_safe_browsing")
    };
  } catch (error) {
    return {
      value: null,
      diagnostic: queryFailedDiagnostic(
        "google_safe_browsing",
        "google_safe_browsing",
        error instanceof Error ? error.message : "Google Safe Browsing lookup failed."
      )
    };
  }
}

async function loadOpenPhishFeed(): Promise<string[]> {
  const config = await getRuntimeConfig();
  return withTtlCache("openphish-feed", FEED_TTL_MS, async () => {
    const response = await fetch(config.openPhishFeedUrl, {
      headers: {
        accept: "text/plain"
      },
      signal: AbortSignal.timeout(PROVIDER_TIMEOUT_MS)
    });
    if (!response.ok) {
      throw new Error(`HTTP ${response.status} returned from OpenPhish.`);
    }

    return (await response.text())
      .split(/\r?\n/)
      .map((line) => line.trim())
      .filter(Boolean);
  });
}

async function loadPhishTankFeed(): Promise<string[]> {
  const config = await getRuntimeConfig();
  return withTtlCache("phishtank-feed", FEED_TTL_MS, async () => {
    const response = await fetch(config.phishTankFeedUrl, {
      headers: {
        accept: "application/json"
      },
      signal: AbortSignal.timeout(PROVIDER_TIMEOUT_MS)
    });
    if (!response.ok) {
      throw new Error(`HTTP ${response.status} returned from PhishTank.`);
    }

    const payload = (await response.json()) as PhishTankEntry[];
    return Array.isArray(payload)
      ? payload
          .map((entry) => (typeof entry.url === "string" ? entry.url.trim() : null))
          .filter((value): value is string => Boolean(value))
      : [];
  });
}

async function checkPhishTankDirect(url: string): Promise<boolean> {
  const config = await getRuntimeConfig();
  const body = new URLSearchParams({
    url,
    format: "json"
  });

  const response = await fetch(config.phishTankCheckUrl, {
    method: "POST",
    headers: {
      "content-type": "application/x-www-form-urlencoded",
      "user-agent": "CapstoneDomainGuardian/1.0"
    },
    body: body.toString(),
    signal: AbortSignal.timeout(PROVIDER_TIMEOUT_MS)
  });

  if (!response.ok) {
    throw new Error(`HTTP ${response.status} returned from PhishTank direct lookup.`);
  }

  const payload = (await response.json()) as {
    results?: {
      in_database?: boolean;
      valid?: boolean | string;
    };
  };

  return Boolean(
    payload.results?.in_database &&
      (payload.results.valid === true || payload.results.valid === "y" || payload.results.valid === "yes")
  );
}

export function matchesPhishingFeed(url: string, candidates: string[]): boolean {
  const target = normalizeMatchTargets(url);
  // A known-legitimate apex (google.com, …) hosts BOTH real content and abused
  // paths/redirectors that phishers submit to feeds (e.g. google.com/url?q=…).
  // Its hostname is therefore NOT a safe match key — only an exact full-URL hit
  // counts, so the real homepage is never condemned by a feed-listed deep link.
  const isLegit = isLegitDomain(target.registrableDomain);
  // A shared host (blogspot.com, …) carries phishing on distinct SUBDOMAINS, so
  // a hostname match flags the specific malicious host without tainting the
  // apex or its siblings. It must NOT match by registrable domain.
  const isShared = isSharedHost(target.registrableDomain);

  return candidates.some((candidateUrl) => {
    try {
      const candidate = normalizeMatchTargets(candidateUrl);
      // Exact full-URL match always counts — even for a legit apex it means the
      // user is on the exact feed-listed page.
      if (candidate.normalizedUrl === target.normalizedUrl) {
        return true;
      }
      // Legit apex: do not fall through to hostname/registrable matching.
      if (isLegit) {
        return false;
      }
      if (candidate.hostname === target.hostname) {
        return true;
      }
      // Ordinary domains match by registrable domain; shared hosts do not.
      return !isShared && candidate.registrableDomain === target.registrableDomain;
    } catch {
      return false;
    }
  });
}

async function checkOpenPhish(url: string): Promise<ProviderCheckResult<boolean>> {
  try {
    const feed = await loadOpenPhishFeed();
    return {
      value: matchesPhishingFeed(url, feed),
      diagnostic: okDiagnostic("blacklisted_in_openPhish", "openphish")
    };
  } catch (error) {
    return {
      value: null,
      diagnostic: queryFailedDiagnostic(
        "blacklisted_in_openPhish",
        "openphish",
        error instanceof Error ? error.message : "OpenPhish feed lookup failed."
      )
    };
  }
}

async function checkPhishTank(url: string): Promise<ProviderCheckResult<boolean>> {
  try {
    const feed = await loadPhishTankFeed();
    return {
      value: matchesPhishingFeed(url, feed),
      diagnostic: okDiagnostic("blacklisted_in_phishTank", "phishtank")
    };
  } catch {
    try {
      return {
        value: await checkPhishTankDirect(url),
        diagnostic: okDiagnostic("blacklisted_in_phishTank", "phishtank")
      };
    } catch {
      // PhishTank shut off anonymous access (the feed/direct endpoints now
      // redirect / 403 without a registered API key, which PhishTank rarely
      // issues). This isn't a pipeline error and OpenPhish already covers the
      // same "is this URL blacklisted" signal — report it as not-configured
      // (neutral) rather than a red failure.
      return {
        value: null,
        diagnostic: notConfiguredDiagnostic(
          "blacklisted_in_phishTank",
          "phishtank",
          "PhishTank requires a registered API key (anonymous access is gated); OpenPhish covers this signal."
        )
      };
    }
  }
}

export async function collectReputationSignals(url: string, ipAddress: string | null): Promise<ReputationCollectionResult> {
  const [virusTotal, abuseIpDb, safeBrowsing, openPhish, phishTank] = await Promise.all([
    checkVirusTotal(url),
    checkAbuseIpDb(ipAddress),
    checkGoogleSafeBrowsing(url),
    checkOpenPhish(url),
    checkPhishTank(url)
  ]);

  const blacklistHits = [openPhish.value, phishTank.value].filter((value) => value === true).length;
  const diagnostics = [
    virusTotal.diagnostic,
    abuseIpDb.diagnostic,
    safeBrowsing.diagnostic,
    openPhish.diagnostic,
    phishTank.diagnostic
  ];

  return {
    reputational: {
      blacklisted_in_phishTank: phishTank.value,
      blacklisted_in_openPhish: openPhish.value,
      google_safe_browsing: safeBrowsing.value,
      virus_total_detections: virusTotal.value,
      abuse_ipdb_reports: abuseIpDb.value,
      phishing_feed_hits:
        openPhish.value === null && phishTank.value === null
          ? null
          : blacklistHits
    },
    diagnostics
  };
}
