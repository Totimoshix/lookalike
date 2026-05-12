type CacheRecord<T> = {
  expiresAt: number;
  value: T;
};

const cache = new Map<string, CacheRecord<unknown>>();

export async function withTtlCache<T>(cacheKey: string, ttlMs: number, loader: () => Promise<T>): Promise<T> {
  const now = Date.now();
  const cached = cache.get(cacheKey);

  if (cached && cached.expiresAt > now) {
    return cached.value as T;
  }

  const value = await loader();
  cache.set(cacheKey, {
    expiresAt: now + ttlMs,
    value
  });
  return value;
}
