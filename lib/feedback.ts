export const FEEDBACK_COMMENTS_LIMIT = 2_000;
export const FEEDBACK_EMAIL_LIMIT = 254;

const EMAIL_PATTERN = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const DISALLOWED_CONTROL_CHARACTERS =
  /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f\u202a-\u202e\u2066-\u2069]/g;
const ALLOWED_FEEDBACK_ORIGINS = new Set([
  "https://better-network-tools-suite.erichbrinkman.chatgpt.site",
  "http://127.0.0.1:3000",
  "http://localhost:3000",
]);

export type Feedback = {
  comments: string;
  email: string;
};

type FeedbackValidation =
  | { ok: true; value: Feedback }
  | { ok: false; error: string };

function cleanFeedbackText(value: string) {
  return value
    .replace(/\r\n?/g, "\n")
    .replace(DISALLOWED_CONTROL_CHARACTERS, "")
    .trim();
}

function asIndentedMarkdown(value: string) {
  return value
    .split("\n")
    .map((line) => `    ${line}`)
    .join("\n");
}

export function validateFeedbackPayload(payload: unknown): FeedbackValidation {
  if (!payload || typeof payload !== "object" || Array.isArray(payload)) {
    return { ok: false, error: "Invalid feedback submission." };
  }

  const candidate = payload as Record<string, unknown>;
  const comments =
    typeof candidate.comments === "string"
      ? cleanFeedbackText(candidate.comments)
      : "";
  const email =
    typeof candidate.email === "string" ? cleanFeedbackText(candidate.email) : "";

  if (!comments) {
    return { ok: false, error: "Suggestions/Comments is required." };
  }

  if (comments.length > FEEDBACK_COMMENTS_LIMIT) {
    return {
      ok: false,
      error: `Suggestions/Comments must be ${FEEDBACK_COMMENTS_LIMIT.toLocaleString()} characters or fewer.`,
    };
  }

  if (
    email.length > FEEDBACK_EMAIL_LIMIT ||
    (email.length > 0 && !EMAIL_PATTERN.test(email))
  ) {
    return {
      ok: false,
      error: "Enter a valid email address or leave it blank.",
    };
  }

  return { ok: true, value: { comments, email } };
}

export function buildPrivateFeedbackIssue(
  feedback: Feedback,
  submittedAt = new Date().toISOString(),
) {
  const body = [
    "## Suggestions / Comments",
    "",
    asIndentedMarkdown(feedback.comments),
    ...(feedback.email
      ? [
          "",
          "## Optional contact email",
          "",
          asIndentedMarkdown(feedback.email),
        ]
      : []),
    "",
    "---",
    "Submitted privately from Better Network Tools.",
    `Received: ${submittedAt}`,
  ].join("\n");

  return { title: "Website feedback", body };
}

export function isAllowedFeedbackOrigin(
  _requestUrl: string,
  origin: string | null,
) {
  return origin !== null && ALLOWED_FEEDBACK_ORIGINS.has(origin);
}
