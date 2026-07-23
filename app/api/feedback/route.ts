import {
  isAllowedFeedbackOrigin,
  validateFeedbackPayload,
} from "../../../lib/feedback";
import {
  consumeFeedbackRateLimit,
  createFeedbackRateLimitKeys,
} from "../../../lib/feedbackRateLimit";
import { createPrivateGitHubFeedbackIssue } from "../../../lib/githubFeedbackApp";

const MAX_BODY_BYTES = 8_192;

type FeedbackRuntimeEnvironment = {
  BNT_FEEDBACK_GITHUB_APP_PRIVATE_KEY?: string;
  BNT_FEEDBACK_RATE_LIMIT_SECRET?: string;
  DB?: D1Database;
};

async function getFeedbackRuntimeEnvironment() {
  const { env } = await import("cloudflare:workers");
  const runtime = env as unknown as FeedbackRuntimeEnvironment;

  if (!runtime.DB) {
    throw new Error("Feedback database binding is unavailable.");
  }

  if (!runtime.BNT_FEEDBACK_GITHUB_APP_PRIVATE_KEY) {
    throw new Error("GitHub App private key is unavailable.");
  }

  if (!runtime.BNT_FEEDBACK_RATE_LIMIT_SECRET) {
    throw new Error("Feedback rate-limit secret is unavailable.");
  }

  return {
    database: runtime.DB,
    privateKey: runtime.BNT_FEEDBACK_GITHUB_APP_PRIVATE_KEY,
    rateLimitSecret: runtime.BNT_FEEDBACK_RATE_LIMIT_SECRET,
  };
}

function corsHeaders(origin: string) {
  return {
    "access-control-allow-headers": "content-type",
    "access-control-allow-methods": "POST, OPTIONS",
    "access-control-allow-origin": origin,
    "access-control-max-age": "600",
    vary: "Origin",
  };
}

function jsonResponse(
  body: object,
  status: number,
  origin: string,
  extraHeaders: HeadersInit = {},
) {
  return Response.json(body, {
    headers: {
      ...corsHeaders(origin),
      "cache-control": "no-store",
      "x-content-type-options": "nosniff",
      ...extraHeaders,
    },
    status,
  });
}

function feedbackClientIp(request: Request) {
  const cloudflareIp = request.headers.get("cf-connecting-ip")?.trim();

  if (cloudflareIp) {
    if (cloudflareIp.length > 64) {
      throw new Error("Cloudflare client address is invalid.");
    }

    return cloudflareIp;
  }

  const hostname = new URL(request.url).hostname;

  if (["localhost", "127.0.0.1", "::1", "[::1]"].includes(hostname)) {
    return "local-dev";
  }

  throw new Error("Cloudflare client address is unavailable.");
}

export async function OPTIONS(request: Request) {
  const origin = request.headers.get("origin");

  if (!origin || !isAllowedFeedbackOrigin(request.url, origin)) {
    return new Response(null, { status: 403 });
  }

  return new Response(null, { headers: corsHeaders(origin), status: 204 });
}

export async function POST(request: Request) {
  const origin = request.headers.get("origin");

  if (!origin || !isAllowedFeedbackOrigin(request.url, origin)) {
    return new Response(null, { status: 403 });
  }

  if (
    !request.headers
      .get("content-type")
      ?.toLowerCase()
      .startsWith("application/json")
  ) {
    return jsonResponse({ error: "Send feedback as JSON." }, 415, origin);
  }

  const contentLength = Number(request.headers.get("content-length") ?? 0);

  if (Number.isFinite(contentLength) && contentLength > MAX_BODY_BYTES) {
    return jsonResponse({ error: "Feedback is too large." }, 413, origin);
  }

  const rawBody = await request.text();

  if (new TextEncoder().encode(rawBody).byteLength > MAX_BODY_BYTES) {
    return jsonResponse({ error: "Feedback is too large." }, 413, origin);
  }

  let payload: unknown;

  try {
    payload = JSON.parse(rawBody);
  } catch {
    return jsonResponse({ error: "Invalid feedback submission." }, 400, origin);
  }

  const validation = validateFeedbackPayload(payload);

  if (!validation.ok) {
    return jsonResponse({ error: validation.error }, 400, origin);
  }

  try {
    const runtime = await getFeedbackRuntimeEnvironment();
    const rateLimitKeys = await createFeedbackRateLimitKeys(
      feedbackClientIp(request),
      runtime.rateLimitSecret,
    );
    const rateLimit = await consumeFeedbackRateLimit(
      runtime.database,
      rateLimitKeys,
    );

    if (!rateLimit.allowed) {
      return jsonResponse(
        { error: "Too many feedback submissions. Please try again later." },
        429,
        origin,
        { "retry-after": String(rateLimit.retryAfterSeconds) },
      );
    }

    await createPrivateGitHubFeedbackIssue({
      feedback: validation.value,
      privateKeyPem: runtime.privateKey,
    });

    return jsonResponse({ sent: true }, 201, origin);
  } catch (error) {
    console.error("Private feedback relay failed", {
      error: error instanceof Error ? error.message : "Unexpected error",
      rayId: request.headers.get("cf-ray") ?? "unavailable",
    });
    return jsonResponse(
      { error: "Feedback is temporarily unavailable. Please try again." },
      503,
      origin,
    );
  }
}
