import { buildPrivateFeedbackIssue, type Feedback } from "./feedback.ts";

export const FEEDBACK_GITHUB_APP_ID = 4_324_889;
export const FEEDBACK_GITHUB_INSTALLATION_ID = 147_232_318;
export const FEEDBACK_GITHUB_APP_SLUG = "betternetworktools-feedback-erich";
export const FEEDBACK_GITHUB_OWNER = "erichbrinkman";
export const FEEDBACK_GITHUB_REPOSITORY = "betternetworktools-feedback";

const GITHUB_API_VERSION = "2026-03-10";

type FetchImplementation = (
  input: string | URL | Request,
  init?: RequestInit,
) => Promise<Response>;

function concatBytes(...parts: Uint8Array[]) {
  const length = parts.reduce((total, part) => total + part.length, 0);
  const result = new Uint8Array(length);
  let offset = 0;

  for (const part of parts) {
    result.set(part, offset);
    offset += part.length;
  }

  return result;
}

function encodeDerLength(length: number) {
  if (length < 0x80) {
    return Uint8Array.of(length);
  }

  const bytes: number[] = [];
  let remaining = length;

  while (remaining > 0) {
    bytes.unshift(remaining & 0xff);
    remaining >>>= 8;
  }

  return Uint8Array.of(0x80 | bytes.length, ...bytes);
}

function encodeDer(tag: number, content: Uint8Array) {
  return concatBytes(Uint8Array.of(tag), encodeDerLength(content.length), content);
}

function wrapPkcs1AsPkcs8(pkcs1: Uint8Array) {
  const version = Uint8Array.of(0x02, 0x01, 0x00);
  const rsaAlgorithmIdentifier = Uint8Array.of(
    0x30,
    0x0d,
    0x06,
    0x09,
    0x2a,
    0x86,
    0x48,
    0x86,
    0xf7,
    0x0d,
    0x01,
    0x01,
    0x01,
    0x05,
    0x00,
  );
  const privateKey = encodeDer(0x04, pkcs1);

  return encodeDer(
    0x30,
    concatBytes(version, rsaAlgorithmIdentifier, privateKey),
  );
}

function decodePemBlock(privateKeyPem: string) {
  const normalized = privateKeyPem.replace(/\\n/g, "\n").trim();
  const pkcs8 = normalized.match(
    /-----BEGIN PRIVATE KEY-----([\s\S]+?)-----END PRIVATE KEY-----/,
  );
  const pkcs1 = normalized.match(
    /-----BEGIN RSA PRIVATE KEY-----([\s\S]+?)-----END RSA PRIVATE KEY-----/,
  );
  const match = pkcs8 ?? pkcs1;

  if (!match) {
    throw new Error("GitHub App private key is not valid PEM.");
  }

  const binary = atob(match[1].replace(/\s+/g, ""));
  const decoded = Uint8Array.from(binary, (character) => character.charCodeAt(0));

  return pkcs8 ? decoded : wrapPkcs1AsPkcs8(decoded);
}

function base64Url(input: Uint8Array | string) {
  const bytes =
    typeof input === "string" ? new TextEncoder().encode(input) : input;
  let binary = "";

  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }

  return btoa(binary)
    .replace(/=/g, "")
    .replace(/\+/g, "-")
    .replace(/\//g, "_");
}

export async function createGitHubAppJwt(
  privateKeyPem: string,
  now = Date.now(),
) {
  const key = await crypto.subtle.importKey(
    "pkcs8",
    decodePemBlock(privateKeyPem),
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const nowInSeconds = Math.floor(now / 1_000);
  const issuedAt = nowInSeconds - 60;
  const header = base64Url(JSON.stringify({ alg: "RS256", typ: "JWT" }));
  const payload = base64Url(
    JSON.stringify({
      iat: issuedAt,
      exp: nowInSeconds + 9 * 60,
      iss: String(FEEDBACK_GITHUB_APP_ID),
    }),
  );
  const unsignedToken = `${header}.${payload}`;
  const signature = await crypto.subtle.sign(
    "RSASSA-PKCS1-v1_5",
    key,
    new TextEncoder().encode(unsignedToken),
  );

  return `${unsignedToken}.${base64Url(new Uint8Array(signature))}`;
}

function githubHeaders(token: string) {
  return {
    accept: "application/vnd.github+json",
    authorization: `Bearer ${token}`,
    "content-type": "application/json",
    "user-agent": FEEDBACK_GITHUB_APP_SLUG,
    "x-github-api-version": GITHUB_API_VERSION,
  };
}

type InstallationToken = {
  expiresAt: number;
  token: string;
};

let cachedInstallationToken: InstallationToken | null = null;

async function requestInstallationToken(
  privateKeyPem: string,
  fetchImplementation: FetchImplementation,
  now: number,
) {
  const appJwt = await createGitHubAppJwt(privateKeyPem, now);
  const tokenResponse = await fetchImplementation(
    `https://api.github.com/app/installations/${FEEDBACK_GITHUB_INSTALLATION_ID}/access_tokens`,
    {
      body: JSON.stringify({
        repositories: [FEEDBACK_GITHUB_REPOSITORY],
        permissions: { issues: "write" },
      }),
      headers: githubHeaders(appJwt),
      method: "POST",
    },
  );

  if (tokenResponse.status !== 201) {
    throw new Error(
      `GitHub installation token request failed with status ${tokenResponse.status}.`,
    );
  }

  const tokenPayload = (await tokenResponse.json()) as {
    expires_at?: unknown;
    token?: unknown;
  };
  const expiresAt =
    typeof tokenPayload.expires_at === "string"
      ? Date.parse(tokenPayload.expires_at)
      : Number.NaN;

  if (
    typeof tokenPayload.token !== "string" ||
    !tokenPayload.token ||
    !Number.isFinite(expiresAt) ||
    expiresAt <= now
  ) {
    throw new Error("GitHub installation token response was invalid.");
  }

  return { expiresAt, token: tokenPayload.token };
}

async function getInstallationToken(
  privateKeyPem: string,
  fetchImplementation: FetchImplementation,
  now: number,
  forceRefresh = false,
) {
  const shouldCache = fetchImplementation === fetch;

  if (
    shouldCache &&
    !forceRefresh &&
    cachedInstallationToken &&
    cachedInstallationToken.expiresAt - 5 * 60 * 1_000 > now
  ) {
    return cachedInstallationToken.token;
  }

  const installationToken = await requestInstallationToken(
    privateKeyPem,
    fetchImplementation,
    now,
  );

  if (shouldCache) {
    cachedInstallationToken = installationToken;
  }

  return installationToken.token;
}

function createIssueRequest(
  issue: ReturnType<typeof buildPrivateFeedbackIssue>,
  installationToken: string,
  fetchImplementation: FetchImplementation,
) {
  return fetchImplementation(
    `https://api.github.com/repos/${FEEDBACK_GITHUB_OWNER}/${FEEDBACK_GITHUB_REPOSITORY}/issues`,
    {
      body: JSON.stringify(issue),
      headers: githubHeaders(installationToken),
      method: "POST",
    },
  );
}

export async function createPrivateGitHubFeedbackIssue({
  feedback,
  privateKeyPem,
  fetchImplementation = fetch,
  now = Date.now(),
}: {
  feedback: Feedback;
  privateKeyPem: string;
  fetchImplementation?: FetchImplementation;
  now?: number;
}) {
  const issue = buildPrivateFeedbackIssue(feedback, new Date(now).toISOString());
  let installationToken = await getInstallationToken(
    privateKeyPem,
    fetchImplementation,
    now,
  );
  let issueResponse = await createIssueRequest(
    issue,
    installationToken,
    fetchImplementation,
  );

  if (issueResponse.status === 401) {
    if (fetchImplementation === fetch) {
      cachedInstallationToken = null;
    }

    installationToken = await getInstallationToken(
      privateKeyPem,
      fetchImplementation,
      now,
      true,
    );
    issueResponse = await createIssueRequest(
      issue,
      installationToken,
      fetchImplementation,
    );
  }

  if (issueResponse.status !== 201) {
    throw new Error(
      `GitHub issue creation failed with status ${issueResponse.status}.`,
    );
  }

  const issuePayload = (await issueResponse.json()) as { number?: unknown };

  if (typeof issuePayload.number !== "number") {
    throw new Error("GitHub issue response was invalid.");
  }

  return { issueNumber: issuePayload.number };
}
