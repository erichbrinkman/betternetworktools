const HOUR_MS = 60 * 60 * 1_000;
const DAY_MS = 24 * HOUR_MS;
const RETENTION_GRACE_MS = 5 * 60 * 1_000;
const HOURLY_MAXIMUM = 5;
const DAILY_MAXIMUM = 20;

type RateLimitWindow = {
  expiresAt: number;
  key: string;
  resetsAt: number;
};

export type FeedbackRateLimitKeys = {
  daily: RateLimitWindow;
  hourly: RateLimitWindow;
};

function hex(bytes: Uint8Array) {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

async function hmacFeedbackKey(
  clientIp: string,
  secret: string,
  windowName: "hour" | "day",
  bucket: number,
) {
  const encoder = new TextEncoder();
  const secretBytes = encoder.encode(secret);

  if (secretBytes.byteLength < 32) {
    throw new Error("Feedback rate-limit secret must be at least 32 bytes.");
  }

  const key = await crypto.subtle.importKey(
    "raw",
    secretBytes,
    { hash: "SHA-256", name: "HMAC" },
    false,
    ["sign"],
  );
  const signature = await crypto.subtle.sign(
    "HMAC",
    key,
    encoder.encode(`feedback:v1:${windowName}:${bucket}:${clientIp}`),
  );

  return hex(new Uint8Array(signature));
}

export async function createFeedbackRateLimitKeys(
  clientIp: string,
  secret: string,
  now = Date.now(),
): Promise<FeedbackRateLimitKeys> {
  const hourBucket = Math.floor(now / HOUR_MS);
  const dayBucket = Math.floor(now / DAY_MS);
  const hourResetsAt = (hourBucket + 1) * HOUR_MS;
  const dayResetsAt = (dayBucket + 1) * DAY_MS;
  const [hourlyKey, dailyKey] = await Promise.all([
    hmacFeedbackKey(clientIp, secret, "hour", hourBucket),
    hmacFeedbackKey(clientIp, secret, "day", dayBucket),
  ]);

  return {
    hourly: {
      expiresAt: hourResetsAt + RETENTION_GRACE_MS,
      key: hourlyKey,
      resetsAt: hourResetsAt,
    },
    daily: {
      expiresAt: dayResetsAt + RETENTION_GRACE_MS,
      key: dailyKey,
      resetsAt: dayResetsAt,
    },
  };
}

function rateLimitStatement(
  database: D1Database,
  window: RateLimitWindow,
  maximum: number,
) {
  return database
    .prepare(
      `INSERT INTO feedback_rate_limits (
        limiter_key,
        request_count,
        expires_at
      ) VALUES (?1, 1, ?2)
      ON CONFLICT(limiter_key) DO UPDATE SET
        request_count = feedback_rate_limits.request_count + 1,
        expires_at = excluded.expires_at
      WHERE feedback_rate_limits.request_count < ?3`,
    )
    .bind(window.key, window.expiresAt, maximum);
}

function statementChanged(result: D1Result<unknown> | undefined) {
  if (!result || result.success === false) {
    throw new Error("Feedback rate-limit database operation failed.");
  }

  return Number(result.meta?.changes ?? 0) > 0;
}

export async function consumeFeedbackRateLimit(
  database: D1Database,
  keys: FeedbackRateLimitKeys,
  now = Date.now(),
) {
  const results = await database.batch([
    database
      .prepare("DELETE FROM feedback_rate_limits WHERE expires_at <= ?1")
      .bind(now),
    rateLimitStatement(database, keys.hourly, HOURLY_MAXIMUM),
    rateLimitStatement(database, keys.daily, DAILY_MAXIMUM),
  ]);
  const hourlyAllowed = statementChanged(results[1]);
  const dailyAllowed = statementChanged(results[2]);
  const blockedUntil = Math.max(
    hourlyAllowed ? now : keys.hourly.resetsAt,
    dailyAllowed ? now : keys.daily.resetsAt,
  );

  return {
    allowed: hourlyAllowed && dailyAllowed,
    retryAfterSeconds:
      hourlyAllowed && dailyAllowed
        ? 0
        : Math.max(1, Math.ceil((blockedUntil - now) / 1_000)),
  };
}
