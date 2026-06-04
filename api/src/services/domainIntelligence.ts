import dns from "node:dns/promises";
import tls from "node:tls";
import { parse } from "tldts";
import type { RiskFactors } from "@capstone/shared";

type DnsResult = RiskFactors["infrastructure"]["dns_records"];

type RdapResult = {
  registrar: string | null;
  registrantOrg: string | null;
  registrantCountry: string | null;
  whoisPrivacy: boolean | null;
  hiddenOwnership: boolean | null;
  domainAgeDays: number | null;
  registrationLengthYears: number | null;
  ownershipChangesDetected: boolean | null;
};

function safeArray<T>(value: T[] | null | undefined): T[] {
  return value ?? [];
}

// Hard upper bounds for each enrichment probe. API Gateway kills the request at
// 29s, so every network call MUST be individually time-boxed — a single
// non-resolving / firewalled phishing host (e.g. a registered domain that drops
// :443) would otherwise hang the whole analysis until the gateway 504s. With
// these caps + the parallel fan-out below, infrastructure collection is bounded
// at roughly max(DNS, RDAP, TLS) + ASN ≈ 9s even in the worst case.
const DNS_TIMEOUT_MS = 4000;
const RDAP_TIMEOUT_MS = 5000;
const TLS_TIMEOUT_MS = 5000;
const ASN_TIMEOUT_MS = 4000;

// Race a promise against a timer; resolve with `fallback` if it doesn't settle
// in time (and swallow rejections to the same fallback). Never rejects.
function withTimeout<T>(promise: Promise<T>, ms: number, fallback: T): Promise<T> {
  return new Promise<T>((resolve) => {
    const timer = setTimeout(() => resolve(fallback), ms);
    promise.then(
      (value) => {
        clearTimeout(timer);
        resolve(value);
      },
      () => {
        clearTimeout(timer);
        resolve(fallback);
      }
    );
  });
}

async function lookupDns(domain: string): Promise<DnsResult> {
  const empty: DnsResult = { a: [], mx: [], txt: [], ns: [] };
  return withTimeout(
    (async () => {
      const [aRecords, mxRecords, txtRecords, nsRecords] = await Promise.allSettled([
        dns.resolve4(domain),
        dns.resolveMx(domain),
        dns.resolveTxt(domain),
        dns.resolveNs(domain)
      ]);

      return {
        a: aRecords.status === "fulfilled" ? aRecords.value : [],
        mx: mxRecords.status === "fulfilled" ? mxRecords.value.map((record) => record.exchange) : [],
        txt:
          txtRecords.status === "fulfilled"
            ? txtRecords.value.map((value) => value.join(""))
            : [],
        ns: nsRecords.status === "fulfilled" ? nsRecords.value : []
      };
    })(),
    DNS_TIMEOUT_MS,
    empty
  );
}

async function lookupRdap(domain: string): Promise<RdapResult> {
  try {
    const response = await fetch(`https://rdap.org/domain/${domain}`, {
      headers: {
        "accept": "application/json",
        "user-agent": "CapstoneDomainGuardian/0.1"
      },
      signal: AbortSignal.timeout(RDAP_TIMEOUT_MS)
    });
    if (!response.ok) {
      throw new Error(`RDAP lookup failed with status ${response.status}`);
    }

    const payload = (await response.json()) as {
      events?: Array<Record<string, string>>;
      entities?: Array<{ roles?: string[]; vcardArray?: unknown[] }>;
    };
    const events = Array.isArray(payload.events) ? payload.events : [];
    const entities = Array.isArray(payload.entities) ? payload.entities : [];
    const registrar = entities.find((entity) => entity.roles?.includes("registrar"))?.vcardArray as
      | [string, Array<[string, unknown, string, unknown]>]
      | undefined;

    const registrant = entities.find((entity) => entity.roles?.includes("registrant"))?.vcardArray as
      | [string, Array<[string, unknown, string, unknown]>]
      | undefined;
    const registrantCard = Array.isArray(registrant?.[1]) ? registrant[1] : [];
    const registrantOrg = registrantCard.find((entry) => entry[0] === "org")?.[3];
    const registrantCountry = registrantCard.find((entry) => entry[0] === "adr")?.[3];

    const created = events.find((event) => event.eventAction === "registration")?.eventDate;
    const expires = events.find((event) => event.eventAction === "expiration")?.eventDate;
    const createdDate = created ? new Date(created) : null;
    const expiryDate = expires ? new Date(expires) : null;
    const now = Date.now();

    const vcardEntries = Array.isArray(registrar?.[1]) ? registrar[1] : [];
    const registrarNameEntry = vcardEntries.find((entry) => entry[0] === "fn")?.[3];
    const registrarName = typeof registrarNameEntry === "string" ? registrarNameEntry : null;
    const registrantOrgText = typeof registrantOrg === "string" ? registrantOrg : null;
    const registrantCountryText =
      typeof registrantCountry === "string"
        ? registrantCountry
        : Array.isArray(registrantCountry)
          ? registrantCountry.filter((value) => typeof value === "string").join(", ")
          : null;

    return {
      registrar: registrarName,
      registrantOrg: registrantOrgText,
      registrantCountry: registrantCountryText,
      whoisPrivacy: registrantOrgText ? /privacy|redacted|proxy/i.test(registrantOrgText) : null,
      hiddenOwnership: registrantOrgText ? /privacy|redacted|proxy|whoisguard/i.test(registrantOrgText) : null,
      domainAgeDays: createdDate ? Math.max(0, Math.floor((now - createdDate.getTime()) / 86_400_000)) : null,
      registrationLengthYears:
        createdDate && expiryDate
          ? Number(((expiryDate.getTime() - createdDate.getTime()) / (86_400_000 * 365)).toFixed(2))
          : null,
      ownershipChangesDetected: events.length > 4 ? true : null
    };
  } catch {
    return {
      registrar: null,
      registrantOrg: null,
      registrantCountry: null,
      whoisPrivacy: null,
      hiddenOwnership: null,
      domainAgeDays: null,
      registrationLengthYears: null,
      ownershipChangesDetected: null
    };
  }
}

async function lookupTls(hostname: string) {
  try {
    const socket = await new Promise<tls.TLSSocket>((resolve, reject) => {
      const connection = tls.connect(
        {
          host: hostname,
          port: 443,
          servername: hostname,
          rejectUnauthorized: false
        },
        () => resolve(connection)
      );
      connection.once("error", reject);
      // A host that accepts the TCP connection but never completes the TLS
      // handshake (common with cloaking / tarpitting phishing infra) would hang
      // this promise forever without a timeout. Tear the socket down and reject.
      connection.setTimeout(TLS_TIMEOUT_MS, () => {
        connection.destroy();
        reject(new Error("TLS handshake timed out"));
      });
    });

    const certificate = socket.getPeerCertificate();
    const altNames = typeof certificate.subjectaltname === "string" ? certificate.subjectaltname : "";
    const issuerValue = certificate.issuer?.O ?? certificate.issuer?.CN ?? null;
    const issuer = typeof issuerValue === "string" ? issuerValue : Array.isArray(issuerValue) ? issuerValue.join(", ") : null;
    const validFrom = certificate.valid_from ? new Date(certificate.valid_from) : null;
    const validTo = certificate.valid_to ? new Date(certificate.valid_to) : null;
    const now = Date.now();
    socket.end();

    return {
      sslValid: Boolean(validTo && validTo.getTime() > now),
      sslError: null,
      certificateIssuer: issuer,
      certificateReputation:
        issuer && /let's encrypt|amazon|digicert|sectigo|globalsign/i.test(issuer)
          ? "known_issuer"
          : issuer
            ? "unknown_issuer"
            : null,
      certificateAgeDays: validFrom ? Math.max(0, Math.floor((now - validFrom.getTime()) / 86_400_000)) : null,
      certificateDomainMismatch: altNames ? !altNames.toLowerCase().includes(hostname.toLowerCase()) : null
    };
  } catch (error) {
    return {
      sslValid: false,
      sslError: error instanceof Error ? error.message : "TLS handshake failed",
      certificateIssuer: null,
      certificateReputation: null,
      certificateAgeDays: null,
      certificateDomainMismatch: null
    };
  }
}

async function lookupAsn(ipAddress: string | null) {
  if (!ipAddress) {
    return {
      asn: null,
      asnReputation: null
    };
  }

  try {
    const response = await fetch(`https://ipwho.is/${ipAddress}`, {
      signal: AbortSignal.timeout(ASN_TIMEOUT_MS)
    });
    if (!response.ok) {
      throw new Error(`ASN lookup failed with status ${response.status}`);
    }
    const payload = (await response.json()) as { connection?: { asn?: number; org?: string } };
    const org = payload.connection?.org ?? null;
    return {
      asn: payload.connection?.asn ? `${payload.connection.asn} ${org ?? ""}`.trim() : org,
      asnReputation: org && /aws|azure|cloudflare|akamai|google/i.test(org) ? "mainstream_hosting" : org ? "unclassified" : null
    };
  } catch {
    return {
      asn: null,
      asnReputation: null
    };
  }
}

export async function collectInfrastructureSignals(domain: string, finalUrl: string | null) {
  const inferredHost =
    finalUrl && /^https?:\/\//i.test(finalUrl) ? new URL(finalUrl).hostname : parse(finalUrl ?? domain).hostname ?? domain;

  // Fan out the independent probes concurrently — DNS, RDAP and TLS don't
  // depend on one another, so running them in parallel turns a sum-of-latencies
  // into a max-of-latencies (≈5s instead of ≈14s). ASN needs the resolved A
  // record, so it runs once DNS lands.
  const [dnsRecords, rdap, tlsSignals] = await Promise.all([
    lookupDns(domain),
    lookupRdap(domain),
    lookupTls(inferredHost)
  ]);
  const asn = await lookupAsn(safeArray(dnsRecords.a)[0] ?? null);
  const parsed = parse(domain);

  return {
    domain_age_days: rdap.domainAgeDays,
    registrar: rdap.registrar,
    registrant_org: rdap.registrantOrg,
    registration_length_years: rdap.registrationLengthYears,
    whois_privacy: rdap.whoisPrivacy,
    hidden_ownership: rdap.hiddenOwnership,
    registrant_country: rdap.registrantCountry,
    ssl_valid: tlsSignals.sslValid,
    ssl_error: tlsSignals.sslError,
    certificate_issuer: tlsSignals.certificateIssuer,
    certificate_reputation: tlsSignals.certificateReputation,
    certificate_age_days: tlsSignals.certificateAgeDays,
    certificate_domain_mismatch: tlsSignals.certificateDomainMismatch,
    creation_date_anomaly: rdap.domainAgeDays !== null ? rdap.domainAgeDays < 30 : null,
    mx_records_present: dnsRecords.mx.length > 0,
    dns_records: dnsRecords,
    dns_history_changes: null,
    fast_flux_detected: dnsRecords.a.length > 4 ? true : null,
    ip_reputation_score: null,
    hosting_asn: asn.asn,
    hosting_asn_reputation: asn.asnReputation,
    shared_hosting_risk:
      asn.asnReputation === "mainstream_hosting" && dnsRecords.a.length > 1 ? true : null,
    redirect_count: null,
    final_url: finalUrl,
    tld: parsed.publicSuffix ?? null,
    ownership_changes_detected: rdap.ownershipChangesDetected
  };
}
