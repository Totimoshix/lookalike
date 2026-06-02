import { useEffect, useState } from "react";
import type { AnalysisResult, BrandMatch, EvidenceSummary } from "@capstone/shared";

const SYNC_KEYS = {
  expertMode: "expertMode",
  realtimeProtection: "realtimeProtection",
  trustedDomains: "trustedDomains",
  apiBaseUrl: "apiBaseUrl"
} as const;

const LOCAL_KEYS = {
  analysisCache: "analysisCache",
  pendingWarningPrefix: "pendingWarning:"
} as const;

const SESSION_KEYS = {
  sessionBypass: "sessionBypass"
} as const;

const CACHE_MAX_ENTRIES = 1000;
const TTL_DEFAULT_MS = 60 * 60 * 1000;
const TTL_MEDIUM_MS = 10 * 60 * 1000;

export type CachedAnalysis = {
  verdict: AnalysisResult["verdict"];
  threat_score: number;
  brand_match: BrandMatch;
  evidence_summary: EvidenceSummary;
  reasoning: string;
  normalized_url: string;
  cached_at: number;
  ttl_ms: number;
};

type CacheMap = Record<string, CachedAnalysis>;

const hasChromeStorage = typeof chrome !== "undefined" && Boolean(chrome.storage);

const memoryStore: Record<"sync" | "local" | "session", Record<string, unknown>> = {
  sync: {},
  local: {},
  session: {}
};

type ChangeListener = (
  changes: Record<string, { oldValue?: unknown; newValue?: unknown }>,
  area: "sync" | "local" | "session" | "managed"
) => void;
const memoryListeners = new Set<ChangeListener>();

async function readArea(area: "sync" | "local" | "session", keys: string[]): Promise<Record<string, unknown>> {
  if (!hasChromeStorage) {
    const out: Record<string, unknown> = {};
    for (const key of keys) {
      if (key in memoryStore[area]) out[key] = memoryStore[area][key];
    }
    return out;
  }
  return chrome.storage[area].get(keys);
}

async function writeArea(area: "sync" | "local" | "session", items: Record<string, unknown>): Promise<void> {
  if (!hasChromeStorage) {
    const changes: Record<string, { oldValue?: unknown; newValue?: unknown }> = {};
    for (const [key, value] of Object.entries(items)) {
      changes[key] = { oldValue: memoryStore[area][key], newValue: value };
      memoryStore[area][key] = value;
    }
    for (const cb of memoryListeners) cb(changes, area);
    return;
  }
  await chrome.storage[area].set(items);
}

function addChangeListener(cb: ChangeListener): () => void {
  if (!hasChromeStorage) {
    memoryListeners.add(cb);
    return () => memoryListeners.delete(cb);
  }
  chrome.storage.onChanged.addListener(cb);
  return () => chrome.storage.onChanged.removeListener(cb);
}

// ---------- Sync settings ----------

export async function getExpertMode(): Promise<boolean> {
  const result = await readArea("sync", [SYNC_KEYS.expertMode]);
  return Boolean(result[SYNC_KEYS.expertMode]);
}

export async function setExpertMode(value: boolean): Promise<void> {
  await writeArea("sync", { [SYNC_KEYS.expertMode]: value });
}

export async function getRealtimeProtection(): Promise<boolean> {
  const result = await readArea("sync", [SYNC_KEYS.realtimeProtection]);
  // Default ON: the value is only `false` if the user explicitly turned it off.
  const value = result[SYNC_KEYS.realtimeProtection];
  return value === undefined ? true : Boolean(value);
}

export async function setRealtimeProtection(value: boolean): Promise<void> {
  await writeArea("sync", { [SYNC_KEYS.realtimeProtection]: value });
}

export async function getTrustedDomains(): Promise<Set<string>> {
  const result = await readArea("sync", [SYNC_KEYS.trustedDomains]);
  const list = result[SYNC_KEYS.trustedDomains];
  return new Set(Array.isArray(list) ? (list as string[]) : []);
}

export async function setTrustedDomains(value: Set<string>): Promise<void> {
  await writeArea("sync", { [SYNC_KEYS.trustedDomains]: Array.from(value) });
}

export async function addTrustedDomain(domain: string): Promise<void> {
  const current = await getTrustedDomains();
  current.add(domain.toLowerCase());
  await setTrustedDomains(current);
}

export async function removeTrustedDomain(domain: string): Promise<void> {
  const current = await getTrustedDomains();
  current.delete(domain.toLowerCase());
  await setTrustedDomains(current);
}

export async function getApiBaseUrl(): Promise<string | null> {
  const result = await readArea("sync", [SYNC_KEYS.apiBaseUrl]);
  const value = result[SYNC_KEYS.apiBaseUrl];
  return typeof value === "string" && value.length > 0 ? value : null;
}

export async function setApiBaseUrl(value: string | null): Promise<void> {
  await writeArea("sync", { [SYNC_KEYS.apiBaseUrl]: value ?? "" });
}

// ---------- Session bypass ----------

export async function getSessionBypass(): Promise<Set<string>> {
  const result = await readArea("session", [SESSION_KEYS.sessionBypass]);
  const list = result[SESSION_KEYS.sessionBypass];
  return new Set(Array.isArray(list) ? (list as string[]) : []);
}

export async function addSessionBypass(domain: string): Promise<void> {
  const current = await getSessionBypass();
  current.add(domain.toLowerCase());
  await writeArea("session", { [SESSION_KEYS.sessionBypass]: Array.from(current) });
}

// ---------- Analysis cache ----------

function ttlFor(verdict: AnalysisResult["verdict"]): number {
  if (verdict === "Medium") return TTL_MEDIUM_MS;
  return TTL_DEFAULT_MS;
}

export async function getCachedAnalysis(domain: string): Promise<CachedAnalysis | null> {
  const result = await readArea("local", [LOCAL_KEYS.analysisCache]);
  const cache = (result[LOCAL_KEYS.analysisCache] as CacheMap | undefined) ?? {};
  const entry = cache[domain.toLowerCase()];
  if (!entry) return null;
  if (Date.now() - entry.cached_at > entry.ttl_ms) {
    return null;
  }
  return entry;
}

export async function setCachedAnalysis(domain: string, result: AnalysisResult): Promise<void> {
  const current = await readArea("local", [LOCAL_KEYS.analysisCache]);
  const cache = ((current[LOCAL_KEYS.analysisCache] as CacheMap | undefined) ?? {}) as CacheMap;
  cache[domain.toLowerCase()] = {
    verdict: result.verdict,
    threat_score: result.threat_score,
    brand_match: result.brand_match,
    evidence_summary: result.evidence_summary,
    reasoning: result.reasoning,
    normalized_url: result.normalized_url,
    cached_at: Date.now(),
    ttl_ms: ttlFor(result.verdict)
  };

  const entries = Object.entries(cache);
  if (entries.length > CACHE_MAX_ENTRIES) {
    entries.sort((a, b) => a[1].cached_at - b[1].cached_at);
    const pruned = entries.slice(entries.length - CACHE_MAX_ENTRIES);
    const next: CacheMap = {};
    for (const [k, v] of pruned) next[k] = v;
    await writeArea("local", { [LOCAL_KEYS.analysisCache]: next });
    return;
  }

  await writeArea("local", { [LOCAL_KEYS.analysisCache]: cache });
}

// ---------- Pending warning handoff ----------

export async function putPendingWarning(id: string, result: AnalysisResult): Promise<void> {
  await writeArea("local", { [`${LOCAL_KEYS.pendingWarningPrefix}${id}`]: result });
}

export async function takePendingWarning(id: string): Promise<AnalysisResult | null> {
  const key = `${LOCAL_KEYS.pendingWarningPrefix}${id}`;
  const stored = await readArea("local", [key]);
  const value = (stored[key] as AnalysisResult | undefined) ?? null;
  if (hasChromeStorage && value) {
    await chrome.storage.local.remove(key);
  } else if (value) {
    delete memoryStore.local[key];
  }
  return value;
}

// ---------- React hooks ----------

export function useExpertMode(): [boolean, (next: boolean) => void] {
  const [value, setValue] = useState(false);

  useEffect(() => {
    let cancelled = false;
    getExpertMode().then((v) => {
      if (!cancelled) setValue(v);
    });
    const off = addChangeListener((changes, area) => {
      if (area === "sync" && SYNC_KEYS.expertMode in changes) {
        setValue(Boolean(changes[SYNC_KEYS.expertMode].newValue));
      }
    });
    return () => {
      cancelled = true;
      off();
    };
  }, []);

  return [value, (next) => void setExpertMode(next)];
}

export function useRealtimeProtection(): [boolean, (next: boolean) => void] {
  // Initialize ON to match the storage default and avoid a flash of "off".
  const [value, setValue] = useState(true);

  useEffect(() => {
    let cancelled = false;
    getRealtimeProtection().then((v) => {
      if (!cancelled) setValue(v);
    });
    const off = addChangeListener((changes, area) => {
      if (area === "sync" && SYNC_KEYS.realtimeProtection in changes) {
        setValue(Boolean(changes[SYNC_KEYS.realtimeProtection].newValue));
      }
    });
    return () => {
      cancelled = true;
      off();
    };
  }, []);

  return [value, (next) => void setRealtimeProtection(next)];
}

export function useTrustedDomains(): [Set<string>, (next: Set<string>) => void] {
  const [value, setValue] = useState<Set<string>>(new Set());

  useEffect(() => {
    let cancelled = false;
    getTrustedDomains().then((v) => {
      if (!cancelled) setValue(v);
    });
    const off = addChangeListener((changes, area) => {
      if (area === "sync" && SYNC_KEYS.trustedDomains in changes) {
        const list = changes[SYNC_KEYS.trustedDomains].newValue;
        setValue(new Set(Array.isArray(list) ? (list as string[]) : []));
      }
    });
    return () => {
      cancelled = true;
      off();
    };
  }, []);

  return [value, (next) => void setTrustedDomains(next)];
}
