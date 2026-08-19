# fastify-web-bot-auth

[![CI](https://github.com/umxr/fastify-web-bot-auth/actions/workflows/ci.yml/badge.svg)](https://github.com/umxr/fastify-web-bot-auth/actions/workflows/ci.yml)

Fastify v5 plugin that verifies **Web Bot Auth** signatures (RFC 9421 HTTP
Message Signatures + the IETF web-bot-auth drafts) on inbound requests. It
gives your origin server cryptographic proof of which AI agent is calling —
without a verifying CDN in front.

- Verifies Ed25519 signatures in an `onRequest` hook via Cloudflare's
  [`web-bot-auth`](https://github.com/cloudflare/web-bot-auth) library.
- Decorates `request.webBotAuth` with a verdict for your route logic.
- **Observe mode by default** (labels, never blocks); **enforce mode** opt-in
  globally or per route.
- Owns JWKS directory fetching, caching, rotation, and negative caching —
  the documented failure modes of hand-rolled integrations.
- Accepts both `Signature-Agent` wire forms: RFC 8941 sf-string (quoted) and
  the legacy bare string.

Requires Node >= 20 and Fastify ^5. ESM-first with a CJS compatibility build.

## Quickstart

```bash
npm install fastify-web-bot-auth
```

```ts
import Fastify from 'fastify';
import webBotAuth from 'fastify-web-bot-auth';

const app = Fastify({ logger: true });

// Observe mode (default): every request gets a verdict, nothing is blocked.
await app.register(webBotAuth);

app.get('/', async (request) => {
  const { verified, agent, reason } = request.webBotAuth ?? {};
  return verified
    ? { hello: 'verified agent', agent }
    : { hello: 'anonymous caller', reason };
});

// Enforce on selected routes only:
app.get(
  '/agent-api',
  { config: { webBotAuth: { mode: 'enforce' } } },
  async () => ({ private: 'verified agents only' }),
);

await app.listen({ port: 3000 });
```

## The verdict: `request.webBotAuth`

```ts
interface WebBotAuthResult {
  verified: boolean;   // signature cryptographically verified against the agent's directory
  agent?: string;      // https origin from Signature-Agent, e.g. "https://chatgpt.com"
  keyid?: string;      // base64url JWK SHA-256 thumbprint (RFC 7638 / RFC 8037 A.3)
  trusted?: boolean;   // result of your trust policy; only set when verified
  reason?:             // only set when not verified
    | 'unsigned'              // no Signature / Signature-Input headers
    | 'expired'               // outside the created/expires window
    | 'bad-signature'         // crypto verification failed
    | 'unknown-key'           // keyid not in the agent's directory (after one forced refresh)
    | 'directory-unreachable' // key directory could not be fetched
    | 'malformed';            // bad header syntax, non-https agent, invalid JWKS, bad nonce
  elapsedMs: number;   // wall-clock time spent verifying
}
```

Verification never throws into the request lifecycle: every failure becomes a
`reason` on the verdict.

## Options

| Option | Type | Default | Description |
| --- | --- | --- | --- |
| `mode` | `'observe' \| 'enforce'` | `'observe'` | Global mode. Observe never blocks; enforce rejects failing requests. |
| `trust` | `string[]` or `(result, request) => boolean \| Promise<boolean>` | trust all verified | Trust policy for verified agents. Array form is an allowlist of https origins — entries are normalized to origins at registration (`https://Example.com:443/x` matches `https://example.com`); invalid or non-https entries throw. Callback form: only a strict `true` return counts as trusted; a throwing callback counts as untrusted. |
| `clockSkew` | `number` (seconds) | `60` | Allowed skew for the plugin's `created`/`expires` window checks. **Cannot widen the strict window enforced by the underlying `web-bot-auth` library** — see the threat-model notes. |
| `directoryTimeoutMs` | `number` | `5000` | Deadline for one directory fetch, covering headers *and* body read. |
| `directoryMaxBytes` | `number` | `65536` | Response size cap for directory fetches. |
| `directoryNegativeTtlMs` | `number` | `30000` | How long a failing directory origin is negative-cached. |
| `fetch` | `typeof fetch` | global `fetch` | Injectable fetch (tests, proxies, custom agents). |
| `onVerified` | `(result, request) => void \| Promise<void>` | — | Called after a successful verification. **Awaited on the request path** before the route handler runs — a slow hook adds latency to every verified request, so keep it fast and offload heavy work (queues, `setImmediate`, fire-and-forget). Errors are logged at debug and swallowed. |
| `onFailed` | `(result, request) => void \| Promise<void>` | — | Called after a failed verification, also before enforce-mode 401 replies. Same latency caveat as `onVerified`. Errors are logged at debug and swallowed. |

Options are validated at registration: an unknown `mode`, a negative
`clockSkew`, or non-positive directory limits throw immediately. So does an
invalid per-route `config.webBotAuth` (e.g. the typo `mode: 'enforced'`) and
registering the plugin twice on one Fastify instance.

A plain-JSON `optionsSchema` is exported for tooling.

Per route, `config: { webBotAuth: { mode } }` overrides the global mode in
either direction.

### Enforce-mode responses

Machine-readable JSON bodies:

- Not verified → `401` with `{ statusCode: 401, error: 'Unauthorized', reason, agent? }`
- Verified but denied by `trust` → `403` with `{ statusCode: 403, error: 'Forbidden', reason: 'untrusted', agent }`

## Observe → enforce rollout guide

1. **Register in observe mode** (the default). Nothing changes for callers.
2. **Watch the verdicts.** Log `request.webBotAuth` (or use `onVerified` /
   `onFailed`) and build a picture of which agents call you, with which
   reasons requests fail.
3. **Add a trust policy** once the picture is clear, e.g.
   `trust: ['https://chatgpt.com']`, still in observe mode. Check
   `trusted: false` rates.
4. **Enforce on low-risk routes first** with
   `config: { webBotAuth: { mode: 'enforce' } }` on the routes that should
   only serve verified agents.
5. **Enforce globally** (`mode: 'enforce'`) when you are confident, and keep
   `config: { webBotAuth: { mode: 'observe' } }` escape hatches on routes
   that must stay open.

Remember: unsigned human browser traffic is `reason: 'unsigned'`. Only
enforce on routes that are meant exclusively for verified agents, or gate the
enforcement decision in your own handler using the verdict.

## Known signers

| Signer | `Signature-Agent` origin | Notes |
| --- | --- | --- |
| OpenAI (ChatGPT Agent / Operator) | `https://chatgpt.com` | Bare-string `Signature-Agent` form |
| Google (Google-Agent) | `https://agent.bot.goog` | Structured (sf-string) form |
| Cloudflare test bot | `https://http-message-signatures-example.research.cloudflare.com` | Publishes the RFC 9421 B.1.4 Ed25519 test key; used by this repo's live test |

Any origin that publishes an Ed25519 JWKS at
`/.well-known/http-message-signatures-directory` works — the plugin resolves
keys by JWK thumbprint from the `Signature-Agent` origin.

## Directory fetching & caching

- Per-origin in-memory cache. TTL comes from `Cache-Control: max-age`,
  clamped to [60 s, 24 h], default 1 h.
- Stale entries are served while a background refresh runs
  (stale-while-revalidate); concurrent refreshes are single-flighted.
- Stale serving is capped: keys older than **24 hours past fetch** are never
  served, even if every refresh attempt keeps failing — past the cap the
  directory must be refetched, and requests fail `directory-unreachable`
  until it succeeds.
- A signature with an unknown `keyid` triggers **one** forced refresh
  (key rotation support) before the request is flagged `unknown-key`.
  Forced refreshes are throttled to one per origin per 30 s, so fabricated
  keyids cannot turn every request into a directory fetch.
- Failing origins are negative-cached (default 30 s) so a dead directory
  cannot slow every request down.
- The number of tracked origins is capped (1000, oldest evicted first) so an
  origin-spray attack cannot grow memory without bound.

## Threat-model notes

- **SSRF:** directory URLs are derived only from a validated https origin;
  `localhost` names and IP literals in loopback, private, link-local, and
  unspecified ranges (IPv4 and IPv6, including IPv4-mapped forms) are
  rejected as `malformed`; redirects are followed same-origin only (max 3
  hops); responses are capped at 64 KB and the timeout bounds the whole
  fetch, body included. Non-443 https ports stay allowed by design. These
  checks cover literals only — an attacker-controlled *hostname* can still
  resolve to an internal address (DNS rebinding), so defense in depth needs
  network-level egress controls (an egress proxy via the injectable `fetch`,
  firewall rules, or DNS policy).
- **Spoofed `Signature-Agent`:** an attacker can claim any origin, but the
  signature must verify against a key published *by that origin*, so a claim
  without the matching private key yields `bad-signature`/`unknown-key`.
- **Nonce replay:** nonces are length/format-checked, but v1 keeps **no
  replay store** — a captured signature can be replayed until `expires`
  (bounded by `clockSkew`). Keep signature windows short and treat Web Bot
  Auth as identity, not as a transaction-level anti-replay mechanism.
- **Directory outages:** a signer whose directory is down yields
  `directory-unreachable`. In enforce mode those requests are rejected (401);
  cached keys keep working, and stale keys are served while revalidation
  fails — but only up to 24 hours past the last successful fetch. Past that
  cap the origin fails `directory-unreachable` until a refetch succeeds.
- **Unknown-key refreshes:** unknown `keyid`s from an otherwise valid origin
  trigger at most one forced directory refresh per origin per 30 s; the
  negative cache and single-flight dedupe bound the amplification further.
- **Clock skew:** the underlying `web-bot-auth` library enforces a strict
  `created <= now <= expires` window *before* the plugin's `clockSkew` checks
  run. Plainly: **`clockSkew` cannot widen the accepted window** — a
  signature even one second past `expires` is rejected as `'expired'`
  regardless of the `clockSkew` value. The option only guards the plugin's
  own additional checks.
- **Key material** is never logged; debug logging goes through the Fastify
  logger only.

## Behind a reverse proxy / TLS terminator

The signature covers `@authority` (and sometimes `@scheme`), computed from
the request Fastify sees. If a TLS-terminating proxy (nginx, an ALB, a CDN)
sits in front, Fastify sees `http` and possibly a rewritten `Host` header —
the signature base no longer matches what the agent signed, and **every
signature fails with `bad-signature`**.

Fix it by making Fastify reconstruct the original request:

```ts
const app = Fastify({
  // Trust X-Forwarded-* from your proxy (scope this to your proxy's IPs).
  trustProxy: true,
});
```

and make sure the proxy forwards the original values:

```
proxy_set_header Host              $host;
proxy_set_header X-Forwarded-Proto $scheme;
proxy_set_header X-Forwarded-Host  $host;
```

With `trustProxy` set, `request.protocol` and `request.host` reflect the
client-facing values and the signature base lines up. If verified requests
still fail with `bad-signature`, compare the `Host` header and protocol your
handler sees against the public URL the agent called.

## Out of scope (v1)

Outbound signing, rate limiting, llms.txt, bot-detection heuristics, nonce
replay storage, and debug/echo endpoints. This plugin verifies identity —
policy stays in your app.

## Verification / development

```bash
npm run build          # dual ESM/CJS output in dist/
npm test               # vitest + v8 coverage (>= 90% lines, >= 85% branches, >= 95% functions)
npm run test:dist      # builds, then smoke-tests dist/ from both ESM and CJS consumers
npm run lint           # biome
npx tsc --noEmit       # typecheck
LIVE_TESTS=1 npm test  # network-gated live test against Cloudflare's example endpoint
```

CI runs the lint, typecheck, test (Node 20/22/24), and dist-smoke jobs on
every PR and push to `main`. The live network test runs only in a weekly
scheduled workflow (`live.yml`), never on the PR path.

Note: GitHub silently disables scheduled workflows after ~60 days without
repository activity, and a failing weekly live run only notifies via the
Actions email — check the Actions tab occasionally.

## Releasing

Releases are automated with
[release-please](https://github.com/googleapis/release-please) and
conventional commits:

1. **Write conventional commits** on `main` (`feat:`, `fix:`, `feat!:` /
   `BREAKING CHANGE:`). release-please opens or updates a release PR that
   bumps the version and changelog.
2. **A human merges the release PR.** Auto-merge is not used. The merge
   creates the GitHub release and tag.
3. **The publish job runs automatically** on the new release: `npm publish`
   via npm **trusted publishing** (OIDC) — no `NPM_TOKEN` secret, and npm
   provenance is attached automatically.

One-time npm setup: on npmjs.com, register a **trusted publisher** for this
package pointing at this repository (`umxr/fastify-web-bot-auth`) and the
workflow file `release.yml`. Note that the first-ever publish of a brand-new
package may need a manual token-based `npm publish` before trusted publishing
can take over.

Version note: the release-please manifest records `0.1.0` as already
released, so the **first** release PR proposes the *next* version (e.g.
`0.1.1` or `0.2.0`) — `0.1.0` itself is never published to npm. This is
intended behavior, not a bug.

Known limitation: release PRs created with the default `GITHUB_TOKEN` do not
trigger CI on the release PR itself. The workaround is to configure a PAT or
GitHub App token for release-please — that requires adding a repository
secret, so it is intentionally not wired up here.

## License

MIT
