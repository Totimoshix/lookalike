import type { RiskFactors, SignalDiagnostic } from "@capstone/shared";
import { withTtlCache } from "./feedCache.js";
import { getRuntimeConfig } from "./runtimeConfig.js";

type PassiveHistoryResult = {
  passiveHistory: RiskFactors["passive_history"];
  dnsHistoryChanges: number | null;
  diagnostics: SignalDiagnostic[];
};

type CrtShEntry = {
  issuer_name?: unknown;
  common_name?: unknown;
  name_value?: unknown;
  not_before?: unknown;
};

type CdxRow = [string, string, string?, string?];

const HISTORY_TTL_MS = 6 * 60 * 60 * 1000;
// crt.sh and the Internet Archive CDX are free, no-SLA services that are
// frequently slow (crt.sh routinely takes 6–10s). 8s was too tight; 12s
// recovers most borderline responses while staying well under the 30s
// analyze-Lambda budget. These signals are passive-history enrichment only.
const PROVIDER_TIMEOUT_MS = 12000;

function okDiagnostic(signal: string, provider: string): SignalDiagnostic {
  return {
    signal,
    provider,
    status: "ok"
  };
}

// These are optional best-effort enrichment sources. When they time out or are
// briefly unavailable it is NOT an error in our pipeline — surface it as
// "unsupported" (renders as a neutral/amber "unavailable" rather than a red
// failure) so the expert panel doesn't look broken. Verdicts don't depend on
// these (passive history is ~4% of the score).
function unavailableDiagnostic(signal: string, provider: string, detail: string): SignalDiagnostic {
  return {
    signal,
    provider,
    status: "unsupported",
    detail
  };
}

function parseCrtShEntries(payload: unknown): CrtShEntry[] {
  if (!Array.isArray(payload)) {
    return [];
  }

  return payload.filter((entry) => entry && typeof entry === "object") as CrtShEntry[];
}

function parseCdxRows(payload: unknown): CdxRow[] {
  if (!Array.isArray(payload) || payload.length < 2) {
    return [];
  }

  return payload
    .slice(1)
    .filter((row): row is CdxRow => Array.isArray(row) && typeof row[0] === "string" && typeof row[1] === "string")
    .map((row) => [row[0], row[1], typeof row[2] === "string" ? row[2] : undefined, typeof row[3] === "string" ? row[3] : undefined]);
}

function daysSince(date: Date | null): number | null {
  if (!date) {
    return null;
  }

  return Math.max(0, Math.floor((Date.now() - date.getTime()) / 86_400_000));
}

function parseCdxTimestamp(timestamp: string): Date | null {
  if (!/^\d{14}$/.test(timestamp)) {
    return null;
  }

  const iso = `${timestamp.slice(0, 4)}-${timestamp.slice(4, 6)}-${timestamp.slice(6, 8)}T${timestamp.slice(8, 10)}:${timestamp.slice(10, 12)}:${timestamp.slice(12, 14)}Z`;
  const parsed = new Date(iso);
  return Number.isNaN(parsed.getTime()) ? null : parsed;
}

async function loadCrtShHistory(domain: string): Promise<CrtShEntry[]> {
  const config = await getRuntimeConfig();
  return withTtlCache(`crtsh:${domain}`, HISTORY_TTL_MS, async () => {
    const url = `${config.crtShBaseUrl.replace(/\/+$/, "")}?q=${encodeURIComponent(`%.${domain}`)}&output=json`;
    const response = await fetch(url, {
      headers: {
        accept: "application/json"
      },
      signal: AbortSignal.timeout(PROVIDER_TIMEOUT_MS)
    });
    if (!response.ok) {
      throw new Error(`HTTP ${response.status} returned from crt.sh.`);
    }

    return parseCrtShEntries(await response.json());
  });
}

async function loadInternetArchiveHistory(domain: string): Promise<CdxRow[]> {
  const config = await getRuntimeConfig();
  return withTtlCache(`internet-archive:${domain}`, HISTORY_TTL_MS, async () => {
    const query = new URL(config.internetArchiveCdxUrl);
    query.searchParams.set("url", domain);
    query.searchParams.set("matchType", "domain");
    query.searchParams.set("output", "json");
    query.searchParams.set("fl", "timestamp,original,statuscode,mimetype");
    query.searchParams.set("limit", "1");
    query.searchParams.set("from", "1996");
    query.searchParams.set("filter", "statuscode:200");

    const response = await fetch(query, {
      headers: {
        accept: "application/json"
      },
      signal: AbortSignal.timeout(PROVIDER_TIMEOUT_MS)
    });
    if (!response.ok) {
      throw new Error(`HTTP ${response.status} returned from Internet Archive CDX.`);
    }

    return parseCdxRows(await response.json());
  });
}

export async function collectPassiveHistorySignals(input: {
  domain: string;
  ownershipChangesDetected: boolean | null;
}): Promise<PassiveHistoryResult> {
  const [crtShResult, archiveResult] = await Promise.allSettled([
    loadCrtShHistory(input.domain),
    loadInternetArchiveHistory(input.domain)
  ]);

  const diagnostics: SignalDiagnostic[] = [
    crtShResult.status === "fulfilled"
      ? okDiagnostic("passive_dns_observed", "crt.sh")
      : unavailableDiagnostic(
          "passive_dns_observed",
          "crt.sh",
          "Optional source: crt.sh did not respond in time (free service, no SLA). Verdict unaffected."
        ),
    archiveResult.status === "fulfilled"
      ? okDiagnostic("archive_first_seen_days", "internet_archive")
      : unavailableDiagnostic(
          "archive_first_seen_days",
          "internet_archive",
          "Optional source: Internet Archive did not respond in time (free service, no SLA). Verdict unaffected."
        )
  ];

  const crtEntries = crtShResult.status === "fulfilled" ? crtShResult.value : [];
  const archiveRows = archiveResult.status === "fulfilled" ? archiveResult.value : [];

  const uniqueNames = new Set<string>();
  const uniqueIssuers = new Set<string>();
  let oldestCertificateDate: Date | null = null;

  for (const entry of crtEntries) {
    const commonName = typeof entry.common_name === "string" ? entry.common_name.trim().toLowerCase() : null;
    if (commonName) {
      uniqueNames.add(commonName);
    }

    if (typeof entry.name_value === "string") {
      entry.name_value
        .split(/\s+/)
        .map((value) => value.trim().toLowerCase())
        .filter(Boolean)
        .forEach((value) => uniqueNames.add(value));
    }

    const issuerName = typeof entry.issuer_name === "string" ? entry.issuer_name.trim() : null;
    if (issuerName) {
      uniqueIssuers.add(issuerName);
    }

    const notBefore = typeof entry.not_before === "string" ? new Date(entry.not_before) : null;
    if (notBefore && !Number.isNaN(notBefore.getTime()) && (!oldestCertificateDate || notBefore < oldestCertificateDate)) {
      oldestCertificateDate = notBefore;
    }
  }

  const oldestArchiveDate = archiveRows
    .map((row) => parseCdxTimestamp(row[0]))
    .filter((date): date is Date => Boolean(date))
    .sort((left, right) => left.getTime() - right.getTime())[0] ?? null;

  const notes: string[] = [];
  if (uniqueNames.size > 0) {
    notes.push(`crt.sh found ${uniqueNames.size} unique certificate hostnames for the target domain.`);
  }
  if (uniqueIssuers.size > 0) {
    notes.push(`Certificate history spans ${uniqueIssuers.size} unique issuing organizations.`);
  }
  if (oldestCertificateDate) {
    notes.push(`Oldest certificate transparency record observed on ${oldestCertificateDate.toISOString().slice(0, 10)}.`);
  }
  if (oldestArchiveDate) {
    notes.push(`Internet Archive first-seen record observed on ${oldestArchiveDate.toISOString().slice(0, 10)}.`);
  }

  const anyProviderSucceeded = crtShResult.status === "fulfilled" || archiveResult.status === "fulfilled";
  const passiveDnsObserved = anyProviderSucceeded
    ? uniqueNames.size > 0 || archiveRows.length > 0
    : null;
  const dnsHistoryChanges =
    uniqueNames.size > 1 || uniqueIssuers.size > 1
      ? Math.max(uniqueNames.size - 1, uniqueIssuers.size - 1)
      : 0;

  return {
    passiveHistory: {
      passive_dns_observed: passiveDnsObserved,
      passive_dns_notes: notes,
      archive_first_seen_days: daysSince(oldestArchiveDate ?? oldestCertificateDate),
      ownership_changes_detected: input.ownershipChangesDetected
    },
    dnsHistoryChanges: anyProviderSucceeded ? dnsHistoryChanges : null,
    diagnostics
  };
}
