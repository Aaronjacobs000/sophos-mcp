/**
 * Retry-After on a 429 (RFC 9110 section 10.2.3) is either a number of
 * seconds or an HTTP date. parseInt on a date gives NaN, which setTimeout
 * treats as 0, so the retry went out at once. Both clients parse it here.
 */

/** The longest one 429 wait lasts, whatever Retry-After asks for. */
export const MAX_RETRY_AFTER_MS = 60_000;

// IMF-fixdate, RFC 850 and asctime dates all start with the day name. Date.parse
// alone would read "1.5" or "60" as a date in the past.
const HTTP_DATE_START = /^(Mon|Tue|Wed|Thu|Fri|Sat|Sun)[a-z]*,?\s/i;

/**
 * Milliseconds to wait before retrying a 429: seconds or an HTTP date, capped
 * at MAX_RETRY_AFTER_MS. A date in the past means retry now. A missing or
 * unreadable header gives fallbackMs.
 */
export function retryAfterMs(header: string | null | undefined, fallbackMs: number, now = Date.now()): number {
  const value = header?.trim();
  if (!value) return fallbackMs;
  let ms: number;
  if (/^\d+$/.test(value)) {
    ms = Number(value) * 1000;
  } else if (HTTP_DATE_START.test(value)) {
    // An asctime date carries no zone and is UTC; Date.parse would read it as local time
    const at = Date.parse(/\b(GMT|UTC)\b/i.test(value) ? value : `${value} GMT`);
    if (Number.isNaN(at)) return fallbackMs;
    ms = Math.max(0, at - now);
  } else {
    return fallbackMs;
  }
  return Math.min(ms, MAX_RETRY_AFTER_MS);
}
