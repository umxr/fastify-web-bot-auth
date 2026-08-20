/**
 * Demo client: signs requests with the RFC 9421 Appendix B.1.4 Ed25519 test
 * key and sends them to the demo server (demo/server.mjs). The plugin on the
 * server verifies each signature against Cloudflare's live hosted key
 * directory — real end-to-end verification over the network.
 * Run `node demo/server.mjs` first, then `node demo/client.mjs`.
 */
import { signatureHeaders } from 'web-bot-auth';
import { Ed25519Signer } from 'web-bot-auth/crypto';

/**
 * RFC 9421 Appendix B.1.4 Ed25519 test key (`test-key-ed25519`). This is
 * public test material from the RFC, not a secret — Cloudflare publishes the
 * matching public key in its live signature directory.
 */
const TEST_PRIVATE_JWK = {
  kty: 'OKP',
  crv: 'Ed25519',
  x: 'JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs',
  d: 'n4Ni-HpISpVObnQMW0wOhCKROaIKqKtW_2ZYb2p9KcU',
};

const LIVE_ORIGIN = 'https://http-message-signatures-example.research.cloudflare.com';

/** Validate PORT: an integer in 1-65535. Exits 1 on an invalid value. */
function resolvePort() {
  const raw = process.env.PORT ?? '3000';
  const port = /^\d+$/.test(raw) ? Number(raw) : Number.NaN;
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    console.error(
      `fastify-web-bot-auth demo: invalid PORT ${JSON.stringify(raw)} — expected an integer in 1-65535.`,
    );
    process.exit(1);
  }
  return port;
}

const PORT = resolvePort();
const HOST = `localhost:${PORT}`;
const BASE_URL = `http://${HOST}`;

/** Sign a GET request for `path`; returns the headers to send with fetch. */
async function signedHeaders(path) {
  const created = new Date();
  const expires = new Date(created.getTime() + 120_000);
  const signer = await Ed25519Signer.fromJWK(TEST_PRIVATE_JWK);
  // sf-string (quoted) form; the agent stays the Cloudflare origin — only
  // the signed `host` header is local, so `@authority` matches the server.
  const signatureAgent = `"${LIVE_ORIGIN}"`;
  const signed = await signatureHeaders(
    {
      method: 'GET',
      url: path,
      protocol: 'http',
      headers: { host: HOST, 'signature-agent': signatureAgent },
    },
    signer,
    { created, expires },
  );
  return {
    'signature-agent': signatureAgent,
    signature: signed.Signature,
    'signature-input': signed['Signature-Input'],
  };
}

async function getJson(path, headers = {}) {
  const response = await fetch(`${BASE_URL}${path}`, { headers });
  const text = await response.text();
  try {
    return { status: response.status, body: JSON.parse(text) };
  } catch {
    throw new Error(`HTTP ${response.status} with a non-JSON body: ${text.slice(0, 100)}`);
  }
}

function expectEqual(actual, expected, label) {
  if (actual !== expected) {
    throw new Error(
      `${label}: expected ${JSON.stringify(expected)}, got ${JSON.stringify(actual)}`,
    );
  }
}

const REASON_HINTS = {
  'directory-unreachable': `the plugin could not reach the live Cloudflare key directory — this demo needs network access to ${LIVE_ORIGIN}`,
  'unknown-key':
    'the live directory no longer contains the RFC test key — Cloudflare may have rotated it',
  expired: "the signature window was rejected — check this machine's clock",
  'bad-signature':
    'crypto verification failed — the signed host may not match the server authority',
  malformed: 'the server saw malformed signature headers',
  unsigned: 'the server saw no signature headers — a proxy may have stripped them',
};

/**
 * Turn an unexpected verdict `reason` into a clear error instead of a raw
 * expected/got mismatch. Pass `expectedReason` when a reason is expected.
 */
function failOnUnexpectedReason(reason, expectedReason) {
  if (reason === undefined || reason === expectedReason) return;
  const hint = REASON_HINTS[reason] ?? 'see the verdict reference in the root README';
  throw new Error(`unexpected verdict reason ${JSON.stringify(reason)} — ${hint}`);
}

const scenarios = [
  {
    name: 'unsigned GET /          (observe) -> 200, reason unsigned',
    async run() {
      const { status, body } = await getJson('/');
      failOnUnexpectedReason(body.reason, 'unsigned');
      expectEqual(status, 200, 'status');
      expectEqual(body.verified, false, 'verified');
      expectEqual(body.reason, 'unsigned', 'reason');
    },
  },
  {
    name: 'signed   GET /          (observe) -> 200, verified, live agent',
    async run() {
      const { status, body } = await getJson('/', await signedHeaders('/'));
      failOnUnexpectedReason(body.reason);
      expectEqual(status, 200, 'status');
      expectEqual(body.verified, true, 'verified');
      expectEqual(body.agent, LIVE_ORIGIN, 'agent');
    },
  },
  {
    name: 'signed   GET /agent-api (enforce) -> 200, handler runs',
    async run() {
      const { status, body } = await getJson('/agent-api', await signedHeaders('/agent-api'));
      failOnUnexpectedReason(body.reason);
      expectEqual(status, 200, 'status');
      expectEqual(body.private, 'verified agents only', 'body.private');
    },
  },
  {
    name: 'unsigned GET /agent-api (enforce) -> 401 Unauthorized',
    async run() {
      const { status, body } = await getJson('/agent-api');
      failOnUnexpectedReason(body.reason, 'unsigned');
      expectEqual(status, 401, 'status');
      expectEqual(body.statusCode, 401, 'body.statusCode');
      expectEqual(body.error, 'Unauthorized', 'body.error');
      expectEqual(body.reason, 'unsigned', 'body.reason');
    },
  },
];

console.log(`fastify-web-bot-auth demo client -> ${BASE_URL}`);
console.log(`verifying against live directory: ${LIVE_ORIGIN}\n`);

let failures = 0;
for (const scenario of scenarios) {
  try {
    await scenario.run();
    console.log(`PASS  ${scenario.name}`);
  } catch (err) {
    failures += 1;
    const message = err instanceof Error ? err.message : String(err);
    if (/fetch failed|ECONNREFUSED/.test(message)) {
      console.log(`FAIL  ${scenario.name}`);
      console.log(`      could not reach ${BASE_URL} — start it with \`node demo/server.mjs\``);
    } else {
      console.log(`FAIL  ${scenario.name}`);
      console.log(`      ${message}`);
    }
  }
}

console.log(
  failures === 0
    ? `\nAll ${scenarios.length} scenarios passed.`
    : `\n${failures} of ${scenarios.length} scenarios failed.`,
);
process.exitCode = failures === 0 ? 0 : 1;
