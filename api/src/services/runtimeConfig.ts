import { GetSecretValueCommand, SecretsManagerClient } from "@aws-sdk/client-secrets-manager";
import type { ProviderReadiness } from "@capstone/shared";

type SecretPayload = Partial<Record<string, string>>;

export type RuntimeConfig = {
  appVersion: string;
  stage: string;
  region: string;
  providerSecretName: string | null;
  bedrockModelId: string | null;
  bedrockRegion: string;
  virusTotalApiKey: string | null;
  abuseIpDbApiKey: string | null;
  googleSafeBrowsingApiKey: string | null;
  dnstwisterApiBaseUrl: string;
  dnstwisterTimeoutMs: number;
  openPhishFeedUrl: string;
  phishTankFeedUrl: string;
  phishTankCheckUrl: string;
  crtShBaseUrl: string;
  internetArchiveCdxUrl: string;
};

let secretClient: SecretsManagerClient | null = null;
let secretCache: Promise<SecretPayload> | null = null;

function getSecretClient(): SecretsManagerClient {
  if (!secretClient) {
    secretClient = new SecretsManagerClient({
      region: process.env.AWS_REGION ?? process.env.AWS_DEFAULT_REGION ?? process.env.BEDROCK_REGION ?? "ca-central-1"
    });
  }
  return secretClient;
}

async function loadSecretPayload(secretName: string | null): Promise<SecretPayload> {
  if (!secretName) {
    return {};
  }

  try {
    const response = await getSecretClient().send(
      new GetSecretValueCommand({
        SecretId: secretName
      })
    );
    const secretString = response.SecretString;
    if (!secretString) {
      return {};
    }

    const parsed = JSON.parse(secretString) as Record<string, unknown>;
    return Object.fromEntries(
      Object.entries(parsed).filter((entry): entry is [string, string] => typeof entry[1] === "string")
    );
  } catch {
    return {};
  }
}

function resolveConfigValue(key: string, secretPayload: SecretPayload): string | null {
  const envValue = process.env[key];
  if (envValue && envValue.trim().length > 0) {
    return envValue.trim();
  }

  const secretValue = secretPayload[key];
  return secretValue && secretValue.trim().length > 0 ? secretValue.trim() : null;
}

export async function getRuntimeConfig(): Promise<RuntimeConfig> {
  const providerSecretName = process.env.PROVIDER_CONFIG_SECRET_NAME?.trim() || null;
  secretCache ??= loadSecretPayload(providerSecretName);
  const secretPayload = await secretCache;

  return {
    appVersion: process.env.APP_VERSION?.trim() || "1.0.0",
    stage: process.env.APP_STAGE?.trim() || "dev",
    region: process.env.AWS_REGION?.trim() || process.env.AWS_DEFAULT_REGION?.trim() || "ca-central-1",
    providerSecretName,
    bedrockModelId: resolveConfigValue("BEDROCK_MODEL_ID", secretPayload),
    bedrockRegion: process.env.BEDROCK_REGION?.trim() || "ca-central-1",
    virusTotalApiKey: resolveConfigValue("VT_API_KEY", secretPayload),
    abuseIpDbApiKey: resolveConfigValue("ABUSEIPDB_API_KEY", secretPayload),
    googleSafeBrowsingApiKey: resolveConfigValue("GOOGLE_SAFE_BROWSING_API_KEY", secretPayload),
    dnstwisterApiBaseUrl: process.env.DNSTWISTER_API_BASE_URL?.trim() || "https://dnstwister.report/api",
    dnstwisterTimeoutMs: Number(process.env.DNSTWISTER_TIMEOUT_MS ?? 10_000),
    openPhishFeedUrl:
      process.env.OPENPHISH_FEED_URL?.trim() ||
      "https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt",
    phishTankFeedUrl: process.env.PHISHTANK_FEED_URL?.trim() || "http://data.phishtank.com/data/online-valid.json",
    phishTankCheckUrl: process.env.PHISHTANK_CHECK_URL?.trim() || "http://checkurl.phishtank.com/checkurl/",
    crtShBaseUrl: process.env.CRTSH_BASE_URL?.trim() || "https://crt.sh/",
    internetArchiveCdxUrl:
      process.env.INTERNET_ARCHIVE_CDX_URL?.trim() || "https://web.archive.org/cdx/search/cdx"
  };
}

export async function getProviderReadiness(): Promise<ProviderReadiness[]> {
  const config = await getRuntimeConfig();

  return [
    {
      provider: "dnstwister",
      signals: ["lookalike_generation"],
      status: "ok",
      detail: null
    },
    {
      provider: "rdap",
      signals: ["registrar_metadata", "ownership_history"],
      status: "ok",
      detail: null
    },
    {
      provider: "crt.sh",
      signals: ["certificate_history", "passive_history"],
      status: "ok",
      detail: null
    },
    {
      provider: "internet_archive",
      signals: ["archive_first_seen"],
      status: "ok",
      detail: null
    },
    {
      provider: "openphish",
      signals: ["blacklisted_in_openPhish", "phishing_feed_hits"],
      status: "ok",
      detail: null
    },
    {
      provider: "phishtank",
      signals: ["blacklisted_in_phishTank", "phishing_feed_hits"],
      status: "ok",
      detail: null
    },
    {
      provider: "virustotal",
      signals: ["virus_total_detections"],
      status: config.virusTotalApiKey ? "ok" : "not_configured",
      detail: config.virusTotalApiKey ? null : "VT_API_KEY is not configured."
    },
    {
      provider: "abuseipdb",
      signals: ["abuse_ipdb_reports"],
      status: config.abuseIpDbApiKey ? "ok" : "not_configured",
      detail: config.abuseIpDbApiKey ? null : "ABUSEIPDB_API_KEY is not configured."
    },
    {
      provider: "google_safe_browsing",
      signals: ["google_safe_browsing"],
      status: config.googleSafeBrowsingApiKey ? "ok" : "not_configured",
      detail: config.googleSafeBrowsingApiKey ? null : "GOOGLE_SAFE_BROWSING_API_KEY is not configured."
    },
    {
      provider: "bedrock",
      signals: ["analyst_explanation", "reporting_contact_notes", "weak_confidence_brand_inference"],
      status: config.bedrockModelId ? "ok" : "not_configured",
      detail: config.bedrockModelId ? null : "BEDROCK_MODEL_ID is not configured. Deterministic analysis still works."
    }
  ];
}
