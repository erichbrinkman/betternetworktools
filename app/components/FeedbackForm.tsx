"use client";

import { type FormEvent, useState } from "react";

type FeedbackStatus = {
  message: string;
  tone: "idle" | "success" | "error";
};

const HOSTED_FEEDBACK_ORIGIN =
  "https://better-network-tools-suite.erichbrinkman.chatgpt.site";
const HOSTED_FEEDBACK_ENDPOINT = `${HOSTED_FEEDBACK_ORIGIN}/api/feedback`;
const SEND_TIMEOUT_MS = 15_000;
const initialStatus: FeedbackStatus = { message: "", tone: "idle" };

function feedbackEndpoint() {
  return window.location.origin === HOSTED_FEEDBACK_ORIGIN
    ? "/api/feedback"
    : HOSTED_FEEDBACK_ENDPOINT;
}

export function FeedbackForm() {
  const [isSending, setIsSending] = useState(false);
  const [status, setStatus] = useState<FeedbackStatus>(initialStatus);

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();

    if (isSending) {
      return;
    }

    const form = event.currentTarget;
    const formData = new FormData(form);
    const email = String(formData.get("email") ?? "").trim();
    const comments = String(formData.get("comments") ?? "").trim();

    if (!comments) {
      setStatus({
        message: "Please enter a suggestion or comment before sending.",
        tone: "error",
      });
      return;
    }

    const controller = new AbortController();
    const timeout = window.setTimeout(() => controller.abort(), SEND_TIMEOUT_MS);
    setIsSending(true);
    setStatus(initialStatus);

    try {
      const response = await fetch(feedbackEndpoint(), {
        body: JSON.stringify({ comments, email }),
        credentials: "omit",
        headers: { "content-type": "application/json" },
        method: "POST",
        referrerPolicy: "no-referrer",
        signal: controller.signal,
      });
      const result = (await response.json().catch(() => null)) as {
        error?: unknown;
      } | null;

      if (!response.ok) {
        throw new Error(
          typeof result?.error === "string"
            ? result.error
            : "Feedback is temporarily unavailable. Please try again.",
        );
      }

      form.reset();
      setStatus({
        message: "Thank you — your feedback was sent privately.",
        tone: "success",
      });
    } catch (error) {
      setStatus({
        message:
          error instanceof DOMException && error.name === "AbortError"
            ? "Sending timed out. Your message was not cleared; please try again."
            : error instanceof Error
              ? error.message
              : "Feedback is temporarily unavailable. Please try again.",
        tone: "error",
      });
    } finally {
      window.clearTimeout(timeout);
      setIsSending(false);
    }
  }

  return (
    <form
      aria-busy={isSending}
      className="feedback-form"
      onSubmit={handleSubmit}
    >
      <div className="feedback-field">
        <label htmlFor="feedback-email">Email (optional)</label>
        <input
          aria-describedby="feedback-email-hint"
          autoComplete="email"
          id="feedback-email"
          maxLength={254}
          name="email"
          placeholder="you@example.com"
          type="email"
        />
        <span className="feedback-hint" id="feedback-email-hint">
          It stays private and is used only if a reply is needed.
        </span>
      </div>

      <div className="feedback-field">
        <label htmlFor="feedback-comments">Suggestions/Comments:</label>
        <textarea
          aria-describedby="feedback-count-hint"
          id="feedback-comments"
          maxLength={2000}
          name="comments"
          placeholder="What would make Better Network Tools more useful?"
          required
          rows={6}
        />
        <span className="feedback-hint" id="feedback-count-hint">
          Up to 2,000 characters.
        </span>
      </div>

      <div className="feedback-actions">
        <p
          aria-live="polite"
          className="feedback-status"
          data-tone={status.tone}
          role="status"
        >
          {status.message}
        </p>
        <button className="feedback-send" disabled={isSending} type="submit">
          {isSending ? "Sending…" : "Send"}
        </button>
      </div>
    </form>
  );
}
