export interface RateLimiter { consume(key: string, now: number): boolean; }

export function createFixedWindowRateLimiter(limit: number): RateLimiter {
  const entries = new Map<string, { window: number; count: number }>();
  return {
    consume(key, now) {
      const window = Math.floor(now / 60_000);
      const entry = entries.get(key);
      if (!entry || entry.window !== window) { entries.set(key, { window, count: 1 }); return true; }
      if (entry.count >= limit) return false;
      entry.count += 1;
      if (entries.size > 10_000) {
        for (const [candidate, value] of entries) if (value.window < window) entries.delete(candidate);
      }
      return true;
    }
  };
}
