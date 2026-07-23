import assert from "node:assert/strict";
import { createVerify, generateKeyPairSync } from "node:crypto";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { operationMatchesPending } from "../app/components/updateRecovery.ts";
import {
  buildPrivateFeedbackIssue,
  FEEDBACK_COMMENTS_LIMIT,
  FEEDBACK_EMAIL_LIMIT,
  isAllowedFeedbackOrigin,
  validateFeedbackPayload,
} from "../lib/feedback.ts";
import {
  createGitHubAppJwt,
  createPrivateGitHubFeedbackIssue,
  FEEDBACK_GITHUB_APP_ID,
  FEEDBACK_GITHUB_APP_SLUG,
  FEEDBACK_GITHUB_INSTALLATION_ID,
  FEEDBACK_GITHUB_OWNER,
  FEEDBACK_GITHUB_REPOSITORY,
} from "../lib/githubFeedbackApp.ts";
import {
  consumeFeedbackRateLimit,
  createFeedbackRateLimitKeys,
} from "../lib/feedbackRateLimit.ts";
import "./netspeed-provider-sort.test.mjs";

const developmentPreviewMeta =
  /<meta(?=[^>]*\bname=["']codex-preview["'])(?=[^>]*\bcontent=["']development["'])[^>]*>/i;

async function dispatch(request, environment = {}) {
  const workerUrl = new URL("../dist/server/index.js", import.meta.url);
  workerUrl.searchParams.set(
    "test",
    `${process.pid}-${Date.now()}-${new URL(request.url).pathname}`,
  );
  const { default: worker } = await import(workerUrl.href);

  return worker.fetch(request, {
    ...environment,
    ASSETS: environment.ASSETS ?? {
      fetch: async () => new Response("Not found", { status: 404 }),
    },
  }, {
      waitUntil() {},
      passThroughOnException() {},
  });
}

async function render(pathname = "/") {
  return dispatch(
    new Request(`http://localhost${pathname}`, {
      headers: { accept: "text/html" },
    }),
  );
}

test("server-renders the Better Network Tools apps homepage", async () => {
  const response = await render();
  assert.equal(response.status, 200);
  assert.match(response.headers.get("content-type") ?? "", /^text\/html\b/i);

  const html = await response.text();
  assert.match(html, /<title>Better Network Tools<\/title>/i);
  assert.match(html, /<h1>Better Network Tools<\/h1>/i);
  assert.match(
    html,
    /<button[^>]*type=["']button["'][^>]*aria-label=["']Check for Updates["']/i,
  );
  assert.match(html, /id=["']update-status["'][^>]*role=["']status["']/i);
  assert.match(html, />Apps<\/h2>/i);
  assert.match(html, /NetScanner/);
  assert.match(html, /NetPorts/);
  assert.match(html, /NetPinger/);
  assert.match(html, /NetSpeed/);
  assert.match(html, /NetTransfer/);
  assert.match(html, /NetTrace/);
  assert.match(html, /QuickSSH/);
  assert.match(html, /SSH or Telnet sessions/i);
  assert.match(html, /MAC OUI Lookup/);
  assert.match(html, /Subnet Calculator/);
  assert.match(html, /href=["']\/netscanner["']/);
  assert.match(html, /href=["']\/netports["']/);
  assert.doesNotMatch(html, /href=["']\/netport["']/);
  assert.match(html, /href=["']\/netpinger["']/);
  assert.match(html, /href=["']\/netspeed["']/);
  assert.match(html, /href=["']\/nettransfer["']/);
  assert.match(html, /href=["']\/nettrace["']/);
  assert.match(html, /href=["']\/quickssh["']/);
  assert.match(html, /href=["']\/oui["']/);
  assert.match(html, /href=["']\/subnet["']/);
  assert.match(html, /favicon\.svg/);
  assert.doesNotMatch(html, /og(?:-[^"'<>]+)?\.png/i);
  assert.match(html, /Developed and managed by Erich Brinkman/);
  assert.match(html, /href=["']https:\/\/github\.com\/erichbrinkman\/["']/);
  assert.match(
    html,
    /href=["']https:\/\/www\.linkedin\.com\/in\/erichbrinkman\/["']/,
  );
  assert.match(html, /Help improve the toolkit/);
  assert.match(html, /delivered privately to the developer/i);
  assert.match(html, /<label[^>]*for=["']feedback-email["'][^>]*>Email \(optional\)<\/label>/i);
  const emailInput = html.match(/<input[^>]*id=["']feedback-email["'][^>]*>/i)?.[0];
  assert.ok(emailInput, "expected the optional feedback email input");
  assert.match(emailInput, /type=["']email["']/i);
  assert.match(emailInput, /aria-describedby=["']feedback-email-hint["']/i);
  assert.doesNotMatch(emailInput, /\brequired\b/i);
  assert.match(html, /<label[^>]*for=["']feedback-comments["'][^>]*>Suggestions\/Comments:<\/label>/i);
  assert.match(html, /<textarea[^>]*id=["']feedback-comments["'][^>]*required/i);
  assert.match(html, /<button[^>]*class=["']feedback-send["'][^>]*type=["']submit["'][^>]*>Send<\/button>/i);
  assert.match(
    html,
    /href=["']https:\/\/github\.com\/erichbrinkman\/["']/,
  );
  assert.match(html, />https:\/\/github\.com\/erichbrinkman\/<\/a>/);
  assert.doesNotMatch(html, /Your network,|PathProbe|DNS Lens|Choose an instrument/);
  assert.doesNotMatch(html, developmentPreviewMeta);
  assert.doesNotMatch(html, /Your site is taking shape|SkeletonPreview|react-loading-skeleton/);
});

test("update control keeps GitHub installation behind the local pinned API", async () => {
  const source = await readFile(
    new URL("../app/components/UpdateButton.tsx", import.meta.url),
    "utf8",
  );

  assert.match(source, /\/api\/updates\/check/);
  assert.match(source, /\/api\/updates\/apply/);
  assert.match(source, /\/api\/updates\/status/);
  assert.match(source, /method: "GET" \| "POST"/);
  assert.match(source, /credentials: "omit"/);
  assert.match(source, /confirm: true/);
  assert.match(source, /expected_current_commit/);
  assert.match(source, /expected_candidate_commit/);
  assert.match(source, /expected_release_tag/);
  assert.match(source, /CHECK_TIMEOUT_MS = 330_000/);
  assert.match(source, /INSTALL_TIMEOUT_MS = 900_000/);
  assert.match(source, /sessionStorage/);
  assert.match(source, /isLoopbackPage/);
  assert.match(source, /View Releases/);
  assert.match(source, /aria-live=/);
  assert.doesNotMatch(source, /api\.github\.com|github\.com\/[^`"']+\.git/);
});

test("feedback validation trims accepted input and enforces the public form limits", () => {
  assert.deepEqual(
    validateFeedbackPayload({
      comments: "  Add a packet capture helper  ",
      email: "  person+tools@example.com  ",
    }),
    {
      ok: true,
      value: {
        comments: "Add a packet capture helper",
        email: "person+tools@example.com",
      },
    },
  );
  assert.deepEqual(
    validateFeedbackPayload({ comments: "Useful note", email: "   " }),
    { ok: true, value: { comments: "Useful note", email: "" } },
  );
  assert.deepEqual(
    validateFeedbackPayload({
      comments: "  First line\r\nsecond\u202eline\u0000  ",
      email: "person@example.com\u2066",
    }),
    {
      ok: true,
      value: {
        comments: "First line\nsecondline",
        email: "person@example.com",
      },
    },
  );

  for (const payload of [null, [], {}, { comments: "   " }, { comments: 42 }]) {
    assert.equal(validateFeedbackPayload(payload).ok, false);
  }
  assert.deepEqual(
    validateFeedbackPayload({ comments: "x".repeat(FEEDBACK_COMMENTS_LIMIT + 1) }),
    {
      ok: false,
      error: `Suggestions/Comments must be ${FEEDBACK_COMMENTS_LIMIT.toLocaleString()} characters or fewer.`,
    },
  );
  assert.deepEqual(
    validateFeedbackPayload({ comments: "Hello", email: "not-an-email" }),
    {
      ok: false,
      error: "Enter a valid email address or leave it blank.",
    },
  );
  assert.equal(
    validateFeedbackPayload({
      comments: "Hello",
      email: `${"a".repeat(FEEDBACK_EMAIL_LIMIT)}@example.com`,
    }).ok,
    false,
  );
});

test("feedback relay accepts only its own site and HTTP loopback callers", () => {
  const endpoint =
    "https://better-network-tools-suite.erichbrinkman.chatgpt.site/api/feedback";

  for (const origin of [
    "https://better-network-tools-suite.erichbrinkman.chatgpt.site",
    "http://localhost:3000",
    "http://127.0.0.1:3000",
  ]) {
    assert.equal(isAllowedFeedbackOrigin(endpoint, origin), true, origin);
  }

  for (const origin of [
    null,
    "null",
    "not a URL",
    "http://better-network-tools-suite.erichbrinkman.chatgpt.site",
    "http://localhost",
    "http://localhost:3001",
    "https://localhost:3000",
    "http://127.0.0.1:3210",
    "http://127.0.0.2:3000",
    "http://[::1]:3000",
    "http://192.168.1.20:3000",
    "http://localhost.example.com:3000",
    "https://example.com",
  ]) {
    assert.equal(isAllowedFeedbackOrigin(endpoint, origin), false, String(origin));
  }
});

test("built feedback route enforces CORS and validates requests before secrets", async () => {
  const endpoint = "http://localhost/api/feedback";
  const allowedOrigin = "http://localhost:3000";
  const preflight = await dispatch(
    new Request(endpoint, {
      headers: { origin: allowedOrigin },
      method: "OPTIONS",
    }),
  );

  assert.equal(preflight.status, 204);
  assert.equal(
    preflight.headers.get("access-control-allow-origin"),
    allowedOrigin,
  );
  assert.equal(
    preflight.headers.get("access-control-allow-methods"),
    "POST, OPTIONS",
  );
  assert.equal(preflight.headers.get("access-control-max-age"), "600");
  assert.ok(
    (preflight.headers.get("vary") ?? "")
      .split(",")
      .map((value) => value.trim().toLowerCase())
      .includes("origin"),
  );

  const invalidOrigin = await dispatch(
    new Request(endpoint, {
      body: JSON.stringify({ comments: "Hello", email: "" }),
      headers: {
        "content-type": "application/json",
        origin: "https://example.com",
      },
      method: "POST",
    }),
  );
  assert.equal(invalidOrigin.status, 403);
  assert.equal(invalidOrigin.headers.get("access-control-allow-origin"), null);

  const invalidJson = await dispatch(
    new Request(endpoint, {
      body: "not JSON",
      headers: {
        "content-type": "application/json",
        origin: allowedOrigin,
      },
      method: "POST",
    }),
  );
  assert.equal(invalidJson.status, 400);
  assert.deepEqual(await invalidJson.json(), {
    error: "Invalid feedback submission.",
  });
  assert.equal(invalidJson.headers.get("cache-control"), "no-store");
});

test("feedback rate limits use rotating keyed hashes and atomic D1 writes", async () => {
  const now = Date.parse("2026-07-17T16:30:00.000Z");
  const secret = "a-private-rate-limit-secret-that-is-long-enough";
  const clientIp = "203.0.113.42";
  const keys = await createFeedbackRateLimitKeys(clientIp, secret, now);
  const repeatedKeys = await createFeedbackRateLimitKeys(clientIp, secret, now);
  const nextHourKeys = await createFeedbackRateLimitKeys(
    clientIp,
    secret,
    now + 60 * 60 * 1_000,
  );

  assert.deepEqual(keys, repeatedKeys);
  assert.match(keys.hourly.key, /^[a-f0-9]{64}$/);
  assert.match(keys.daily.key, /^[a-f0-9]{64}$/);
  assert.notEqual(keys.hourly.key, keys.daily.key);
  assert.notEqual(keys.hourly.key, nextHourKeys.hourly.key);
  assert.doesNotMatch(JSON.stringify(keys), new RegExp(clientIp));
  await assert.rejects(
    createFeedbackRateLimitKeys(clientIp, "too-short", now),
    /at least 32 bytes/,
  );

  const batches = [];
  const changes = [1, 1, 1];
  const database = {
    prepare(sql) {
      return {
        bind(...values) {
          return { sql, values };
        },
      };
    },
    async batch(statements) {
      batches.push(statements);
      return changes.map((change) => ({
        meta: { changes: change },
        success: true,
      }));
    },
  };

  assert.deepEqual(await consumeFeedbackRateLimit(database, keys, now), {
    allowed: true,
    retryAfterSeconds: 0,
  });
  assert.equal(batches[0].length, 3);
  assert.match(batches[0][0].sql, /^DELETE FROM feedback_rate_limits/);
  assert.match(batches[0][1].sql, /ON CONFLICT\(limiter_key\) DO UPDATE/);
  assert.match(batches[0][1].sql, /request_count < \?3/);
  assert.deepEqual(batches[0][1].values, [
    keys.hourly.key,
    keys.hourly.expiresAt,
    5,
  ]);
  assert.deepEqual(batches[0][2].values, [
    keys.daily.key,
    keys.daily.expiresAt,
    20,
  ]);
  assert.doesNotMatch(JSON.stringify(batches), new RegExp(clientIp));

  changes.splice(0, changes.length, 1, 0, 1);
  const blocked = await consumeFeedbackRateLimit(database, keys, now);
  assert.equal(blocked.allowed, false);
  assert.equal(
    blocked.retryAfterSeconds,
    Math.ceil((keys.hourly.resetsAt - now) / 1_000),
  );
});

test("private feedback issue content includes contact details only when supplied", () => {
  const submittedAt = "2026-07-17T16:30:00.000Z";
  const withEmail = buildPrivateFeedbackIssue(
    {
      comments: "Add DNS lookup & export support #1 🚀\nThis would help a lot.",
      email: "person+tools@example.com",
    },
    submittedAt,
  );
  const withoutEmail = buildPrivateFeedbackIssue(
    { comments: "Add a packet capture helper", email: "" },
    submittedAt,
  );

  assert.deepEqual(withEmail, {
    title: "Website feedback",
    body: [
      "## Suggestions / Comments",
      "",
      "    Add DNS lookup & export support #1 🚀",
      "    This would help a lot.",
      "",
      "## Optional contact email",
      "",
      "    person+tools@example.com",
      "",
      "---",
      "Submitted privately from Better Network Tools.",
      `Received: ${submittedAt}`,
    ].join("\n"),
  });
  assert.deepEqual(withoutEmail, {
    title: "Website feedback",
    body: [
      "## Suggestions / Comments",
      "",
      "    Add a packet capture helper",
      "",
      "---",
      "Submitted privately from Better Network Tools.",
      `Received: ${submittedAt}`,
    ].join("\n"),
  });
  assert.doesNotMatch(withoutEmail.body, /contact email/i);
});

test("GitHub App relay signs a PKCS#1 JWT and targets only the private feedback repo", async () => {
  const { privateKey, publicKey } = generateKeyPairSync("rsa", {
    modulusLength: 2048,
  });
  const privateKeyPem = privateKey
    .export({ format: "pem", type: "pkcs1" })
    .toString();
  const now = Date.parse("2026-07-17T16:30:00.000Z");
  const jwt = await createGitHubAppJwt(privateKeyPem, now);
  const [encodedHeader, encodedPayload, encodedSignature] = jwt.split(".");
  const header = JSON.parse(Buffer.from(encodedHeader, "base64url").toString());
  const payload = JSON.parse(Buffer.from(encodedPayload, "base64url").toString());
  const verifier = createVerify("RSA-SHA256");

  assert.match(privateKeyPem, /BEGIN RSA PRIVATE KEY/);
  assert.deepEqual(header, { alg: "RS256", typ: "JWT" });
  assert.equal(payload.iss, String(FEEDBACK_GITHUB_APP_ID));
  assert.equal(payload.iat, Math.floor(now / 1_000) - 60);
  assert.equal(payload.exp, Math.floor(now / 1_000) + 9 * 60);
  assert.equal(payload.exp - payload.iat, 10 * 60);
  verifier.update(`${encodedHeader}.${encodedPayload}`);
  verifier.end();
  assert.equal(
    verifier.verify(publicKey, Buffer.from(encodedSignature, "base64url")),
    true,
  );

  const calls = [];
  const fetchImplementation = async (input, init) => {
    calls.push({ input: String(input), init });
    return calls.length === 1
      ? Response.json(
          {
            expires_at: new Date(now + 60 * 60 * 1_000).toISOString(),
            token: "installation-token-secret",
          },
          { status: 201 },
        )
      : Response.json(
          { number: 381, html_url: "private-url-must-not-leak" },
          { status: 201 },
        );
  };
  const result = await createPrivateGitHubFeedbackIssue({
    feedback: {
      comments: "Add DNS lookup & export support #1 🚀",
      email: "person+tools@example.com",
    },
    fetchImplementation,
    now,
    privateKeyPem,
  });

  assert.equal(FEEDBACK_GITHUB_APP_ID, 4_324_889);
  assert.equal(FEEDBACK_GITHUB_INSTALLATION_ID, 147_232_318);
  assert.equal(FEEDBACK_GITHUB_APP_SLUG, "betternetworktools-feedback-erich");
  assert.equal(FEEDBACK_GITHUB_OWNER, "erichbrinkman");
  assert.equal(FEEDBACK_GITHUB_REPOSITORY, "betternetworktools-feedback");
  assert.equal(calls.length, 2);

  assert.equal(
    calls[0].input,
    `https://api.github.com/app/installations/${FEEDBACK_GITHUB_INSTALLATION_ID}/access_tokens`,
  );
  assert.equal(calls[0].init.method, "POST");
  assert.deepEqual(JSON.parse(calls[0].init.body), {
    repositories: [FEEDBACK_GITHUB_REPOSITORY],
    permissions: { issues: "write" },
  });
  const tokenHeaders = new Headers(calls[0].init.headers);
  assert.equal(tokenHeaders.get("authorization"), `Bearer ${jwt}`);
  assert.equal(tokenHeaders.get("user-agent"), FEEDBACK_GITHUB_APP_SLUG);
  assert.equal(tokenHeaders.get("x-github-api-version"), "2026-03-10");

  assert.equal(
    calls[1].input,
    `https://api.github.com/repos/${FEEDBACK_GITHUB_OWNER}/${FEEDBACK_GITHUB_REPOSITORY}/issues`,
  );
  assert.equal(calls[1].init.method, "POST");
  assert.equal(
    new Headers(calls[1].init.headers).get("authorization"),
    "Bearer installation-token-secret",
  );
  assert.deepEqual(
    JSON.parse(calls[1].init.body),
    buildPrivateFeedbackIssue(
      {
        comments: "Add DNS lookup & export support #1 🚀",
        email: "person+tools@example.com",
      },
      new Date(now).toISOString(),
    ),
  );
  assert.deepEqual(result, { issueNumber: 381 });
  assert.doesNotMatch(JSON.stringify(result), /private-url|installation-token/);
});

test("feedback browser code posts privately without containing GitHub credentials", async () => {
  const source = await readFile(
    new URL("../app/components/FeedbackForm.tsx", import.meta.url),
    "utf8",
  );

  assert.match(source, /\/api\/feedback/);
  assert.match(source, /fetch\(feedbackEndpoint\(\)/);
  assert.match(source, /credentials: "omit"/);
  assert.match(source, /referrerPolicy: "no-referrer"/);
  assert.match(source, /JSON\.stringify\(\{ comments, email \}\)/);
  assert.match(source, /sent privately/i);
  assert.doesNotMatch(
    source,
    /buildFeedbackIssueUrl|issues\/new|window\.open|mailto:|BEGIN (?:RSA )?PRIVATE KEY|BNT_FEEDBACK_GITHUB_APP_PRIVATE_KEY|147232318|4324889|installation-token-secret/,
  );
});

test("update recovery rejects stale operation status for a newer pending release", () => {
  const pending = {
    candidateCommit: "2".repeat(40),
    releaseTag: "v0.2.0",
  };
  assert.equal(
    operationMatchesPending(
      {
        state: "updated",
        release_tag: "v0.1.0",
        applied_commit: "1".repeat(40),
      },
      pending,
    ),
    false,
  );
  assert.equal(
    operationMatchesPending(
      {
        state: "updated",
        release_tag: "v0.2.0",
        applied_commit: "2".repeat(40),
      },
      pending,
    ),
    true,
  );
});

test("server-renders the QuickSSH connection workspace without opening a socket", async () => {
  const response = await render("/quickssh");
  assert.equal(response.status, 200);

  const html = await response.text();
  assert.match(html, /<title>QuickSSH · Better Network Tools<\/title>/i);
  assert.doesNotMatch(html, /og-quickssh-telnet\.png/);
  assert.match(html, /<h1>QuickSSH<\/h1>/i);
  assert.match(html, /local Python service/i);
  assert.match(html, />Protocol<\/legend>/i);
  assert.match(html, /name=["']remote-protocol["'][^>]*value=["']ssh["']/i);
  assert.match(html, /name=["']remote-protocol["'][^>]*value=["']telnet["']/i);
  assert.match(html, />Host<\/span>/i);
  assert.match(html, />Port<\/span>/i);
  assert.match(html, />Username<\/span>/i);
  assert.match(html, />Authentication<\/legend>/i);
  assert.match(html, />Password<\/span>/i);
  assert.match(html, /Agent \/ keys/i);
  assert.match(html, /Recent connections/i);
  assert.match(html, /Trusted hosts/i);
  assert.match(html, /No saved host keys/i);
  assert.match(html, /<h2[^>]*>Terminal<\/h2>/i);
  assert.match(html, />Disconnect<\/button>/i);
  assert.match(html, /aria-label=["']Disconnect SSH session["']/i);
  assert.match(html, /Preparing terminal/i);
  assert.doesNotMatch(html, developmentPreviewMeta);
});

test("QuickSSH keeps its host verification and bounded local-storage contracts", async () => {
  const source = await readFile(
    new URL("../app/quickssh/QuickSSHClient.tsx", import.meta.url),
    "utf8",
  );

  assert.match(source, /STORAGE_VERSION = 2/);
  assert.match(source, /LEGACY_STORAGE_VERSION = 1/);
  assert.match(source, /MAX_RECENT_CONNECTIONS = 20/);
  assert.match(source, /TRUSTED_HOST_STORAGE_VERSION = 1/);
  assert.match(source, /MAX_TRUSTED_HOSTS = 100/);
  assert.match(source, /function writeTrustedHosts/);
  assert.match(source, /rememberTrustedHost\(/);
  assert.match(
    source,
    /!existing && trustedHosts\.length >= MAX_TRUSTED_HOSTS/,
  );
  assert.match(source, /This session can continue, but this host will not be remembered/);
  assert.match(source, /slice\(0, remainingCapacity\)/);
  assert.match(source, /function forgetTrustedHost/);
  assert.match(source, /delete withoutHostKey\.hostKey/);
  assert.match(source, /Forget trusted host key for/);
  assert.match(source, /type: "trust_host_key"/);
  assert.match(source, /known_host_key:/);
  assert.match(source, /role="alertdialog"/);
  assert.match(source, /cancelButtonRef\.current\?\.focus\(\)/);
  assert.match(source, /Trust changed key & connect/);
  assert.match(source, /Trust & connect/);
  assert.match(source, /SHA256 fingerprint/);
  assert.match(source, /Number\.isSafeInteger\(value\)/);
  assert.match(source, /MAX_DATE_TIMESTAMP/);
  assert.match(source, /screenReaderMode: true/);
  assert.match(source, /\.xterm-helper-textarea/);
  assert.match(source, /aria-labelledby", "terminal-title/);
  assert.match(source, /aria-describedby", "terminal-help/);
  assert.match(source, /type Protocol = "ssh" \| "telnet"/);
  assert.match(source, /const protocol = forceLegacySsh/);
  assert.match(source, /value\.protocol === undefined/);
  assert.match(source, /parsed\.version === LEGACY_STORAGE_VERSION/);
  assert.match(source, /writeRecents\(connections\)/);
  assert.match(source, /url\.pathname = `\/api\/\$\{protocol\}`/);
  assert.match(
    source,
    /bytes\[end - 1\] === 13 && bytes\[end\] === 10/,
  );
  assert.match(source, /validated\.protocol === "telnet"/);
  assert.match(source, /Telnet has no encryption or host verification/);
  assert.match(source, /Anything you[\s\S]{0,150}output travels as plaintext/);
  assert.match(source, /observed or modified/);
  assert.match(source, /trusted, isolated network/);
  assert.match(source, /I understand and want to use Telnet for this connection/);
  assert.match(source, /aria-describedby="telnet-warning-copy"/);
  assert.match(source, /Telnet is unencrypted; traffic can be observed or modified/);
  assert.match(source, /Sign in interactively in the terminal/);
  assert.match(source, /protocol === "ssh" \? "22" : "23"/);
  assert.match(source, /protocol === "ssh" \? \(/);

  const terminalSizeStart = source.indexOf("const terminalSize");
  const telnetConnectStart = source.indexOf(
    'if (validated.protocol === "telnet")',
    terminalSizeStart,
  );
  const sshConnectStart = source.indexOf("} else {", telnetConnectStart);
  assert.ok(
    terminalSizeStart >= 0 &&
      telnetConnectStart > terminalSizeStart &&
      sshConnectStart > telnetConnectStart,
  );
  const telnetConnectSource = source.slice(
    telnetConnectStart,
    sshConnectStart,
  );
  assert.match(telnetConnectSource, /type: "connect"/);
  assert.match(telnetConnectSource, /host: validated\.host/);
  assert.match(telnetConnectSource, /port: validated\.port/);
  assert.match(telnetConnectSource, /\.\.\.terminalSize/);
  assert.doesNotMatch(telnetConnectSource, /username|auth:|known_host_key/);

  const writeRecentsStart = source.indexOf("function writeRecents");
  const parseTrustedHostStart = source.indexOf(
    "function parseTrustedHost",
    writeRecentsStart,
  );
  assert.ok(
    writeRecentsStart >= 0 && parseTrustedHostStart > writeRecentsStart,
  );
  assert.doesNotMatch(
    source.slice(writeRecentsStart, parseTrustedHostStart),
    /hostKey|publicKey|fingerprint/,
  );

  const deleteRecentStart = source.indexOf("function deleteRecent");
  const forgetTrustedHostStart = source.indexOf("function forgetTrustedHost");
  assert.ok(deleteRecentStart >= 0 && forgetTrustedHostStart > deleteRecentStart);
  const deleteRecentSource = source.slice(
    deleteRecentStart,
    forgetTrustedHostStart,
  );
  assert.doesNotMatch(deleteRecentSource, /setTrustedHosts|writeTrustedHosts/);
});

test("QuickSSH normalizes endpoint identity without folding SSH usernames", async () => {
  const source = await readFile(
    new URL("../app/quickssh/QuickSSHClient.tsx", import.meta.url),
    "utf8",
  );

  assert.ok(source.includes('.trim().replace(/\\.+$/, "")'));
  assert.match(source, /value\.length > 253/);
  assert.match(source, /value\.startsWith\("-"\)/);
  assert.match(source, /containsForbiddenCharacter/);
  assert.match(source, /isValidIpv4Literal/);
  assert.match(source, /isValidIpv6Literal/);
  assert.match(source, /isValidSshUsername/);
  assert.doesNotMatch(
    source,
    /username\.normalize\("NFKC"\)\.trim\(\)\.toLocaleLowerCase/,
  );
});

test("server-renders the MAC OUI lookup form without contacting the API", async () => {
  const response = await render("/oui");
  assert.equal(response.status, 200);

  const html = await response.text();
  assert.match(html, /<title>MAC OUI Lookup · Better Network Tools<\/title>/i);
  assert.match(html, /<h1>MAC OUI Lookup<\/h1>/i);
  assert.match(html, /MAC address or OUI/i);
  assert.match(html, /Lookup/);
  assert.doesNotMatch(html, developmentPreviewMeta);
});

test("server-renders NetPinger without starting a live job", async () => {
  const response = await render("/netpinger");
  assert.equal(response.status, 200);

  const html = await response.text();
  assert.match(html, /<title>NetPinger · Better Network Tools<\/title>/i);
  assert.match(html, /<h1>NetPinger<\/h1>/i);
  assert.match(html, /Hostnames or IP addresses/i);
  assert.match(html, /success and failure streaks/i);
  assert.match(html, /Start continuous ping/i);
  assert.match(html, />Stop<\/button>/i);
  assert.doesNotMatch(html, /Ping count/i);
  assert.match(html, /No ping results yet/i);
  assert.doesNotMatch(html, developmentPreviewMeta);
});

test("server-renders NetTransfer controls without starting a file server", async () => {
  const response = await render("/nettransfer");
  assert.equal(response.status, 200);

  const html = await response.text();
  assert.match(html, /<title>NetTransfer · Better Network Tools<\/title>/i);
  assert.match(html, /<h1>NetTransfer<\/h1>/i);
  assert.match(html, /TFTP · SFTP · FTP/i);
  assert.match(html, /<h2[^>]*>Transfer server<\/h2>/i);
  assert.match(html, />Protocol<\/legend>/i);
  assert.match(
    html,
    /<input(?=[^>]*name=["']transfer-protocol["'])(?=[^>]*value=["']tftp["'])(?=[^>]*checked)[^>]*>/i,
  );
  assert.match(
    html,
    /name=["']transfer-protocol["'][^>]*value=["']sftp["']/i,
  );
  assert.match(
    html,
    /name=["']transfer-protocol["'][^>]*value=["']ftp["']/i,
  );
  assert.match(html, /No authentication or encryption/i);
  assert.match(html, /Network exposure/i);
  assert.match(html, /This machine/i);
  assert.match(html, /Local network/i);
  assert.match(html, />Port<\/span>/i);
  assert.match(html, /Bind address/i);
  assert.match(html, /Transfer permissions/i);
  assert.match(html, /Allow downloads/i);
  assert.match(html, /Allow uploads/i);
  assert.match(html, /Allow overwrite/i);
  assert.match(html, /Root directory/i);
  assert.match(html, /Start TFTP server/i);
  assert.match(html, /Listener idle/i);
  assert.doesNotMatch(html, />Stop server<\/button>/i);
  assert.match(html, /Shared files/i);
  assert.match(html, /Recent transfers/i);
  assert.match(html, /All protocols · live polling/i);
  assert.doesNotMatch(html, /og-nettransfer\.png/i);
  assert.doesNotMatch(html, developmentPreviewMeta);
});

test("legacy NetTFTP route permanently redirects to NetTransfer", async () => {
  const response = await render("/nettftp");
  assert.equal(response.status, 308);
  assert.match(response.headers.get("location") ?? "", /\/nettransfer$/);
});

test("NetTransfer keeps server credentials memory-only", async () => {
  const source = await readFile(
    new URL("../app/nettransfer/NetTransferClient.tsx", import.meta.url),
    "utf8",
  );

  assert.match(source, /\/api\/transfer-server/);
  assert.match(source, /protocol,/);
  assert.match(source, /username: draft\.username/);
  assert.match(source, /password: draft\.password/);
  assert.match(source, /acknowledge_plaintext_ftp:/);
  assert.match(source, /credentials: "omit"/);
  assert.match(source, /updateDraft\(protocol, \{ password: "" \}\)/);
  assert.match(source, /sftp_host_key_fingerprint/);
  assert.match(source, /ftp_passive_port_start/);
  assert.doesNotMatch(source, /localStorage|sessionStorage/);
});

test("server-renders NetSpeed as a Python-backed suite tool", async () => {
  const response = await render("/netspeed");
  assert.equal(response.status, 200);

  const html = await response.text();
  assert.match(html, /<title>NetSpeed · Better Network Tools<\/title>/i);
  assert.match(html, /<h1>NetSpeed<\/h1>/i);
  assert.match(html, /Local Python engine/i);
  assert.match(html, /Choose a server/i);
  assert.match(html, /Sort servers/i);
  assert.match(html, /id=["']netspeed-server-sort["']/i);
  assert.match(html, /value=["']nearest["'][^>]*>Nearest measured</i);
  assert.match(html, /value=["']provider["'][^>]*>Provider A–Z</i);
  assert.match(html, /Nearest measured first/i);
  assert.match(html, /Start test/i);
  assert.match(html, />Stop<\/button>/i);
  assert.match(html, /Ping/i);
  assert.match(html, /Jitter/i);
  assert.match(html, /Download/i);
  assert.match(html, /Upload/i);
  assert.match(html, /Download size/i);
  assert.match(html, /Upload size/i);
  assert.match(html, /Standard · 250 MB/i);
  assert.match(html, /Standard · 100 MB/i);
  assert.match(html, /Larger samples give fast connections/i);
  assert.match(html, /Live throughput/i);
  assert.match(html, /Test elapsed \(s\)/i);
  assert.match(html, /Latest/i);
  assert.match(html, /Peak/i);
  assert.match(html, /Speed samples appear during download and upload/i);
  assert.match(html, /role=["']img["']/i);
  assert.match(html, /Download and upload throughput over the current speed test/i);
  assert.match(html, /No speed-test results yet/i);
  assert.match(html, /Public test traffic/i);
  assert.match(html, /rank them nearest-first/i);
  assert.doesNotMatch(html, /og-netspeed\.png/i);
  assert.doesNotMatch(html, developmentPreviewMeta);
});

test("NetSpeed delegates public traffic to the local Python API", async () => {
  const source = await readFile(
    new URL("../app/netspeed/NetSpeedClient.tsx", import.meta.url),
    "utf8",
  );

  assert.match(source, /\/api\/speed-servers/);
  assert.match(source, /\/api\/speed-jobs/);
  assert.match(source, /server_id: selectedServerId/);
  assert.match(source, /download_bytes: downloadBytes/);
  assert.match(source, /upload_bytes: uploadBytes/);
  assert.match(source, /method: "DELETE"/);
  assert.match(source, /ACTIVE_JOB_STORAGE_KEY/);
  assert.match(source, /SIZE_OPTIONS_STORAGE_KEY/);
  assert.match(source, /HISTORY_LIMIT = 6/);
  assert.match(source, /current_mbps/);
  assert.match(source, /elapsed_seconds/);
  assert.match(source, /latency_ms/);
  assert.match(source, /type ServerSort = "nearest" \| "provider"/);
  assert.match(source, /useState<ServerSort>\("nearest"\)/);
  assert.match(source, /sortServersByProvider\(filteredServers\)/);
  assert.match(source, /nearest measured first/i);
  assert.match(source, /viewBox="0 0 100 56"/);
  assert.match(source, /<title id="netspeed-throughput-title">/);
  assert.match(source, /<desc id="netspeed-throughput-description">/);
  assert.match(source, /Use automatic server/);
  assert.match(source, /Use nearest public server/);
  assert.match(source, /useNearestPublicServer/);
  assert.match(source, /refreshDirectoryAfterFailure/);
  assert.match(source, /role="radiogroup"/);
  assert.match(source, /aria-live="polite"/);
  assert.doesNotMatch(source, /librespeed\.org|speed\.cloudflare\.com|dlURL|ulURL/);
});

test("server-renders NetPorts as an authorized local TCP scan workspace", async () => {
  const response = await render("/netports");
  assert.equal(response.status, 200);

  const html = await response.text();
  assert.match(html, /<title>NetPorts · Better Network Tools<\/title>/i);
  assert.match(html, /<h1>NetPorts<\/h1>/i);
  assert.match(html, /Local Python engine/i);
  assert.match(html, /Hostname or IP address/i);
  assert.match(html, /Common 100/i);
  assert.match(html, /All TCP/i);
  assert.match(html, /Connection timeout/i);
  assert.match(html, /Concurrency/i);
  assert.match(html, /Collect safe service banners/i);
  assert.match(html, /Start TCP scan/i);
  assert.match(html, /Open TCP services/i);
  assert.match(html, /Authorized targets only/i);
  assert.doesNotMatch(html, /og-netports\.png/i);
  assert.doesNotMatch(html, /\bNetPort\b/);
  assert.doesNotMatch(html, developmentPreviewMeta);
});

test("legacy NetPort route permanently redirects to NetPorts", async () => {
  const response = await render("/netport");
  assert.equal(response.status, 308);
  assert.match(response.headers.get("location") ?? "", /\/netports$/);
});

test("NetPorts keeps scanning, cancellation, reattachment, and exports in the local API", async () => {
  const source = await readFile(
    new URL("../app/netports/NetPortsClient.tsx", import.meta.url),
    "utf8",
  );

  assert.match(source, /ACTIVE_JOB_STORAGE_KEY/);
  assert.match(source, /LEGACY_ACTIVE_JOB_STORAGE_KEY/);
  assert.match(source, /better-network-tools\.netports\.active-job-id/);
  assert.match(source, /better-network-tools\.netport\.active-job-id/);
  assert.match(source, /\/api\/port-jobs/);
  assert.match(source, /method: "DELETE"/);
  assert.match(source, /ports: portSpec\.trim\(\)/);
  assert.match(source, /collect_banners: collectBanners/);
  assert.match(source, /results_truncated/);
  assert.match(source, /Export CSV/);
  assert.match(source, /Export JSON/);
  assert.match(source, /`netports-\$\{filenameTarget\(job\.target\)\}\.csv`/);
  assert.match(source, /`netports-\$\{filenameTarget\(job\.target\)\}\.json`/);
  assert.match(source, /aria-live="polite"/);
  assert.match(source, /aria-sort=/);
  assert.ok(source.includes('/^[\\t\\r ]*[=+\\-@]/'));
  assert.doesNotMatch(source, /WebSocket|new\s+Worker|navigator\.connection/);
});

test("server-renders NetTrace with explicit private-by-default AS enrichment", async () => {
  const response = await render("/nettrace");
  assert.equal(response.status, 200);

  const html = await response.text();
  assert.match(html, /<title>NetTrace · Better Network Tools<\/title>/i);
  assert.match(html, /<h1>NetTrace<\/h1>/i);
  assert.match(html, /Hostname or IP address/i);
  assert.match(html, /Max hops/i);
  assert.match(html, /Resolve responder hostnames/i);
  assert.match(html, /Look up autonomous-system details/i);
  assert.match(html, /Team Cymru/i);
  assert.match(html, /Off by default/i);
  assert.match(html, /Trace route/i);
  assert.match(html, />Stop<\/button>/i);
  assert.match(html, /Recent target traces/i);
  assert.match(html, /Device-local history/i);
  assert.match(html, /only the target and start time/i);
  assert.match(html, /No recent traces yet/i);
  assert.match(html, /No route traced yet/i);
  assert.doesNotMatch(html, developmentPreviewMeta);
});

test("NetTrace keeps polling, cancellation, and route-boundary details accessible", async () => {
  const source = await readFile(
    new URL("../app/nettrace/NetTraceClient.tsx", import.meta.url),
    "utf8",
  );
  const recentSource = await readFile(
    new URL("../app/nettrace/recentTraces.ts", import.meta.url),
    "utf8",
  );

  assert.match(source, /useState\(false\)/);
  assert.match(source, /lookup_asn: lookupAsn/);
  assert.match(source, /ACTIVE_TRACE_STORAGE_KEY/);
  assert.match(recentSource, /RECENT_TRACES_STORAGE_KEY/);
  assert.match(recentSource, /MAX_RECENT_TRACES = 6/);
  assert.match(source, /rememberRecentTarget/);
  assert.match(source, /Clear all/);
  assert.match(source, /Remove \$\{recent\.target\} from recent traces/);
  assert.match(source, /rememberActiveTrace/);
  assert.match(source, /restoreActiveTrace/);
  assert.match(source, /\/api\/trace-jobs/);
  assert.match(source, /method: "DELETE"/);
  assert.match(source, /aria-expanded=\{expanded\}/);
  assert.match(source, /aria-controls=\{detailId\}/);
  assert.match(source, /boundary_confidence: "exact" \| "gap" \| "ecmp"/);
  assert.match(source, /Multiple AS paths observed/);
  assert.match(source, /Boundary location is uncertain/);
  assert.match(source, /no boundary is inferred/);
  assert.match(source, /Earlier or alternate hops prevent an exact entry boundary/);
  assert.match(source, /Team Cymru WHOIS/);

  const recentModel = recentSource.slice(
    recentSource.indexOf("export type RecentTrace"),
    recentSource.indexOf("type RecentTraceStorage"),
  );
  assert.doesNotMatch(recentModel, /hops|as_path|lookup_asn|resolved_address/);
});

test("NetTrace recent targets are sanitized, deduplicated, and bounded", async () => {
  const recent = await import(
    new URL("../app/nettrace/recentTraces.ts", import.meta.url).href
  );
  const values = new Map();
  const storage = {
    getItem(key) {
      return values.get(key) ?? null;
    },
    setItem(key, value) {
      values.set(key, value);
    },
    removeItem(key) {
      values.delete(key);
    },
  };
  const tracedAt = "2026-07-11T12:00:00.000Z";
  storage.setItem(
    recent.RECENT_TRACES_STORAGE_KEY,
    JSON.stringify({
      version: recent.RECENT_TRACES_VERSION,
      entries: [
        { target: "Example.com", traced_at: tracedAt, hops: ["private"] },
        { target: " Example.com ", traced_at: tracedAt, warnings: ["extra"] },
        { target: "example.COM", traced_at: tracedAt, as_path: [64500] },
        ...Array.from({ length: 7 }, (_, index) => ({
          target: `host${index}.example`,
          traced_at: tracedAt,
          resolved_address: "192.0.2.1",
        })),
        { target: "https://invalid.example", traced_at: tracedAt },
      ],
    }),
  );

  const loaded = recent.readRecentTraces(storage);
  assert.equal(loaded.length, recent.MAX_RECENT_TRACES);
  assert.equal(loaded[0].target, "Example.com");
  assert.equal(
    loaded.filter((entry) => entry.target.toLowerCase() === "example.com").length,
    1,
  );
  assert.ok(
    loaded.every(
      (entry) => Object.keys(entry).sort().join(",") === "target,traced_at",
    ),
  );

  const persisted = JSON.parse(
    storage.getItem(recent.RECENT_TRACES_STORAGE_KEY),
  );
  assert.ok(
    persisted.entries.every(
      (entry) => Object.keys(entry).sort().join(",") === "target,traced_at",
    ),
  );

  const refreshed = recent.upsertRecentTrace(loaded, {
    target: "EXAMPLE.COM",
    traced_at: "2026-07-11T13:00:00.000Z",
  });
  assert.equal(refreshed.length, recent.MAX_RECENT_TRACES);
  assert.equal(refreshed[0].target, "EXAMPLE.COM");
  assert.equal(recent.removeRecentTrace(refreshed, "EXAMPLE.COM").length, 5);

  storage.setItem(
    recent.RECENT_TRACES_STORAGE_KEY,
    JSON.stringify({ version: 99, entries: loaded }),
  );
  assert.deepEqual(recent.readRecentTraces(storage), []);
  assert.equal(storage.getItem(recent.RECENT_TRACES_STORAGE_KEY), null);
});

test("NetPinger keeps the expanded latency chart contract accessible", async () => {
  const source = await readFile(
    new URL("../app/netpinger/NetPingerClient.tsx", import.meta.url),
    "utf8",
  );
  const styles = await readFile(
    new URL("../app/netpinger/netpinger.module.css", import.meta.url),
    "utf8",
  );

  assert.match(source, /REPLY_HISTORY_LIMIT = 60/);
  assert.match(
    source,
    /useState<Set<string>>\(\s*\(\) => new Set\(\),?\s*\)/,
  );
  assert.match(source, /expandedTargetKeys\.has\(targetKey\)/);
  assert.match(source, /const next = new Set\(current\)/);
  assert.match(source, /next\.delete\(targetKey\)/);
  assert.match(source, /next\.add\(targetKey\)/);
  assert.match(source, /setExpandedTargetKeys\(new Set\(\)\)/);
  assert.doesNotMatch(source, /\[expandedTargetKey, setExpandedTargetKey\]/);
  assert.doesNotMatch(source, /current === targetKey \? null : targetKey/);
  assert.match(source, /Select one or more hosts to expand their reply-time graphs/);
  assert.match(source, /<Fragment key=\{targetKey\}>/);
  assert.match(source, /reply-detail-\$\{job\.id\}-\$\{targetIndex\}/);
  assert.match(source, /aria-expanded=\{expanded\}/);
  assert.match(source, /aria-controls=\{detailId\}/);
  assert.match(source, /colSpan=\{RESULT_COLUMN_COUNT\}/);
  assert.match(source, /Reply time \(ms\)/);
  assert.match(source, /Gap = no timed reply/);
  assert.match(source, /No timed replies to graph yet/);
  assert.match(source, /function buildReplyLineSeries/);
  assert.match(source, /data-chart-kind="line"/);
  assert.match(source, /<path/);
  assert.match(source, /vectorEffect="non-scaling-stroke"/);
  assert.match(source, /styles\.chartSampleGap/);
  assert.match(source, /replySparklineStyle/);
  assert.match(
    source,
    /if \(sample === null\) \{[\s\S]*?finishSegment\(\);/,
  );
  assert.match(
    source,
    /visualSlot \/ \(REPLY_HISTORY_LIMIT - 1\)/,
  );
  assert.doesNotMatch(source, /--sample-height/);
  assert.doesNotMatch(styles, /--sample-height/);
  assert.match(styles, /clip-path:\s*var\(--reply-sparkline\)/);
});

test("NetPinger presents optional reverse-DNS identity states accessibly", async () => {
  const source = await readFile(
    new URL("../app/netpinger/NetPingerClient.tsx", import.meta.url),
    "utf8",
  );

  assert.match(source, /reverse_dns_status\?: ReverseDnsStatus/);
  assert.match(source, /Reverse DNS hostname:/);
  assert.match(source, /PTR lookup pending/);
  assert.match(source, /No PTR record/);
  assert.match(source, /PTR unavailable/);
  assert.match(source, /"not_requested"/);
  assert.match(source, /"unavailable"/);
});

test("server-renders the subnet calculator with an initial calculation", async () => {
  const response = await render("/subnet");
  assert.equal(response.status, 200);

  const html = await response.text();
  assert.match(html, /<title>Subnet Calculator · Better Network Tools<\/title>/i);
  assert.match(html, /<h1>Subnet Calculator<\/h1>/i);
  assert.match(html, /IPv4 address or CIDR/i);
  assert.match(html, /192\.168\.1\.0\/24/);
  assert.match(html, /255\.255\.255\.0/);
  assert.doesNotMatch(html, developmentPreviewMeta);
});

test("server-renders the NetScanner workspace without contacting the API", async () => {
  const response = await render("/netscanner");
  assert.equal(response.status, 200);

  const html = await response.text();
  assert.match(html, /<title>NetScanner · Better Network Tools<\/title>/i);
  assert.match(html, /Discovery &amp; fingerprinting/i);
  assert.match(html, /IPv4 subnet/i);
  assert.match(html, /Start discovery/i);
  assert.match(html, /Recent scans/i);
  assert.match(html, /Loading recent scans/i);
  assert.match(html, /Discovery results/i);
  assert.doesNotMatch(html, developmentPreviewMeta);
});

test("NetScanner keeps recent scans refreshable without orphaning an active job", async () => {
  const source = await readFile(
    new URL("../app/netscanner/NetScannerClient.tsx", import.meta.url),
    "utf8",
  );

  assert.match(source, /\/api\/scans\?limit=8/);
  assert.match(source, /window\.setTimeout\(refreshRecentScans, 1500\)/);
  assert.match(source, /startInFlight\.current \|\| restoreInFlight\.current/);
  assert.match(source, /restoreInFlight\.current \|\| startInFlight\.current \|\| isActive/);
  assert.match(source, /disabled=\{historyDisabled\}/);
});

test("NetScanner builds safe new-tab links only for detected web services", async () => {
  const { webServiceUrl } = await import(
    new URL("../app/netscanner/webServiceUrl.mjs", import.meta.url)
  );
  const source = await readFile(
    new URL("../app/netscanner/NetScannerClient.tsx", import.meta.url),
    "utf8",
  );
  const styles = await readFile(
    new URL("../app/globals.css", import.meta.url),
    "utf8",
  );

  const service = (port, name, httpStatus = null, httpServer = null) => ({
    port,
    service: name,
    http_status: httpStatus,
    http_server: httpServer,
  });

  assert.equal(webServiceUrl("192.0.2.10", service(80, "http")), "http://192.0.2.10/");
  assert.equal(webServiceUrl("192.0.2.10", service(443, "https")), "https://192.0.2.10/");
  assert.equal(
    webServiceUrl("192.0.2.10", service(8080, "http-alt")),
    "http://192.0.2.10:8080/",
  );
  assert.equal(
    webServiceUrl("192.0.2.10", service(8443, "https-alt")),
    "https://192.0.2.10:8443/",
  );
  assert.equal(
    webServiceUrl("192.0.2.10", service(9200, "elasticsearch", 200)),
    "http://192.0.2.10:9200/",
  );
  assert.equal(webServiceUrl("192.0.2.10", service(22, "ssh")), null);
  assert.match(source, /target="_blank"/);
  assert.match(source, /rel="noopener noreferrer"/);
  assert.match(source, /referrerPolicy="no-referrer"/);
  assert.match(source, /serviceDetail \? ` · \$\{serviceDetail\}`/);
  assert.match(styles, /\.port-list > a \{[\s\S]*?background: rgba\(127, 161, 138, 0\.16\)/);
});
