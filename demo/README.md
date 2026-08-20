# Demo: verify live signed agent traffic

A runnable end-to-end demo of `fastify-web-bot-auth`. A local Fastify server
registers the built plugin; a client signs requests exactly the way a real
Web Bot Auth agent does, and the plugin verifies them against **Cloudflare's
live hosted key directory** at
`https://http-message-signatures-example.research.cloudflare.com`.

## What "real signed traffic" means here

- The client signs each request with the **RFC 9421 Appendix B.1.4 Ed25519
  test key** — public test material from the RFC, not a secret.
- The `Signature-Agent` header names the Cloudflare origin above, which
  publishes the matching public key at
  `/.well-known/http-message-signatures-directory`.
- The plugin on the server fetches that live directory over the network,
  resolves the key by JWK thumbprint, and cryptographically verifies the
  signature — the same path a production signer (ChatGPT Agent,
  Google-Agent, …) takes.

Only the `host` header (and so `@authority`) is local; the key directory and
the verification flow are the real, live ones.

## Run it

```bash
npm install
npm run build          # the demo imports the built plugin from dist/
node demo/server.mjs   # terminal 1 — listens on PORT or 3000
node demo/client.mjs   # terminal 2 — sends the four scenarios
```

The client exits `0` when all scenarios pass and `1` on any mismatch.

The client reads the same `PORT` variable as the server. For a custom port,
set it in both terminals: `PORT=8080 node demo/server.mjs` and
`PORT=8080 node demo/client.mjs`.

> **Network note:** the demo needs internet access — verification fetches
> Cloudflare's live key directory. Without network access, signed scenarios
> fail with `reason: 'directory-unreachable'` and the client exits `1`.
> If the server fails to start with an import error, run `npm run build`
> first.

## Scenarios

| Request | Route (mode) | Expected |
| --- | --- | --- |
| Unsigned | `/` (observe) | 200, `verified: false`, `reason: 'unsigned'` |
| Signed | `/` (observe) | 200, `verified: true`, `agent` = Cloudflare origin |
| Signed | `/agent-api` (enforce) | 200, route handler runs |
| Unsigned | `/agent-api` (enforce) | 401 `{ statusCode, error: 'Unauthorized', reason: 'unsigned' }` |

## Sample output

```
fastify-web-bot-auth demo client -> http://localhost:3000
verifying against live directory: https://http-message-signatures-example.research.cloudflare.com

PASS  unsigned GET /          (observe) -> 200, reason unsigned
PASS  signed   GET /          (observe) -> 200, verified, live agent
PASS  signed   GET /agent-api (enforce) -> 200, handler runs
PASS  unsigned GET /agent-api (enforce) -> 401 Unauthorized

All 4 scenarios passed.
```
