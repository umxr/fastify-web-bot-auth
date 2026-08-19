# Project Brief: `fastify-web-bot-auth`

> Input document for BMAD v6 planning workflow (Analyst → PM → Architect). Contains the research-backed context, scoped requirements, constraints, and success criteria needed to produce a PRD, architecture, and epics/stories.

---

## 1. Executive Summary

**Product:** An open-source Fastify plugin that verifies Web Bot Auth signatures (IETF draft, built on RFC 9421 HTTP Message Signatures) on inbound requests, giving origin servers cryptographic proof of which AI agent is calling them.

**One-liner:** Drop-in Fastify plugin that tells you, cryptographically, whether a request came from a verified AI agent (ChatGPT Agent, Google-Agent, Bedrock AgentCore, etc.) — and lets you act on it.

**Strategic context:** Bots overtook human web traffic in mid-2026 (~57% of HTML requests per Cloudflare Radar); AI-agent traffic grew thousands of percent YoY. OpenAI, Google, and Amazon already cryptographically sign agent requests in production; Cloudflare, Vercel, Akamai, DataDome, and HUMAN verify at the edge. **No Fastify-native verification plugin exists.** Developers not behind a verifying CDN must hand-roll a hook around Cloudflare's low-level `web-bot-auth` library. This plugin fills that gap and follows the proven `@fastify/*` auth-plugin pattern, with a credible path to the official Fastify ecosystem list.

**Staged strategy (from research, Aug 2026):**
- **Stage 1 (this project):** Narrow, well-tested Web Bot Auth *verification* plugin.
- **Stage 2 (out of scope, design for it):** Agent-class rate limiting (on top of `@fastify/rate-limit`) + agent-friendly structured errors.
- **Stage 3 (out of scope):** Optional llms.txt-from-schema + `.well-known` discovery modules; `fastify-agent-ready` as a meta-package composing the focused plugins.

---

## 2. Problem Statement

1. A growing majority of API/web traffic is automated; a fast-growing slice is legitimate AI agents acting on behalf of users.
2. User-agent strings and IP allowlists are spoofable and unmaintainable. The industry answer is cryptographic identity: Web Bot Auth (Ed25519 signatures per RFC 9421, keys published at `/.well-known/http-message-signatures-directory`).
3. Verification today lives at the CDN edge (Cloudflare/Vercel/Akamai). Origin-side Node.js developers — especially those *not* behind a verifying CDN — have no drop-in option. Cloudflare's `web-bot-auth` npm library is framework-agnostic and low-level; getting signature-base serialization and JWKS caching/rotation right is a documented failure mode.
4. Fastify has no plugin for this. Express has a community verifier (OpenBotAuth); Fastify has nothing.

## 3. Goals & Non-Goals

### Goals
- G1: Verify inbound Web Bot Auth signatures (RFC 9421, Ed25519) in a Fastify `onRequest`/`preHandler` hook.
- G2: Decorate the request with a verdict object (e.g. `request.webBotAuth = { verified, agent, keyid, directory }`) for downstream route logic.
- G3: Support **observe-only mode** (default: label, never block) and **enforce mode** (reject unverified/invalid signatures on selected routes).
- G4: Handle JWKS directory fetching, caching (honor `Cache-Control`), and key rotation robustly.
- G5: Interoperate with **both** `Signature-Agent` header forms: legacy bare-string (OpenAI, Cloudflare) and structured dictionary (Google, newer draft revisions).
- G6: Ship with first-class TypeScript types, 100% of RFC 9421 Appendix B.1.4 test vectors passing, and validation against Cloudflare Research's live test endpoint.
- G7: Be small, dependency-light, and structured for eventual adoption as `@fastify/web-bot-auth`.

### Non-Goals (v1)
- NG1: Signing outbound requests (verification only).
- NG2: Rate limiting, error-shaping, llms.txt, agents.json, MCP — Stages 2/3.
- NG3: Reimplementing RFC 9421 crypto — wrap `web-bot-auth` (Cloudflare, Apache-2.0) rather than reimplementing.
- NG4: Bot *detection* heuristics (fingerprinting, behavior analysis). This is identity verification, not bot management.
- NG5: A registry/trust policy deciding which agents are "good" — expose identity; let the app decide policy (but allow a user-supplied allowlist/trust callback).

## 4. Target Users & Use Cases

- **Primary:** Node.js/Fastify API owners not behind a verifying CDN who want to identify, allow, throttle, or block AI-agent traffic per policy.
- **Secondary:** Teams behind Cloudflare/Vercel who want defense-in-depth, host portability, or local/dev parity.
- **Tertiary:** Agent developers testing that their signed requests verify correctly against an origin.

Representative use cases:
1. E-commerce API allows verified ChatGPT Agent traffic to product endpoints but blocks unsigned scrapers on checkout.
2. Content API logs verified agent identity for analytics/licensing decisions before any enforcement (observe-only rollout).
3. SaaS API applies stricter rate limits to unverified automation while trusting verified agents (Stage 2 hook point).

## 5. Functional Requirements

- FR1: Register as a standard Fastify plugin (`fastify-plugin`), Fastify v5 support required (v4 nice-to-have).
- FR2: Detect presence of `Signature`, `Signature-Input`, and `Signature-Agent` headers; requests without them pass through untouched with `verified: false, reason: 'unsigned'`.
- FR3: Parse `Signature-Agent` in both bare-string and RFC 8941 structured-dictionary forms.
- FR4: Fetch signer key directory from `https://<signature-agent>/.well-known/http-message-signatures-directory`; validate content type and JWKS shape; select key by `keyid` (JWK thumbprint).
- FR5: Verify Ed25519 signature over the signature base per RFC 9421, including required components (`@authority`, `signature-agent`), `created`/`expires` window, `nonce`, and `tag="web-bot-auth"`.
- FR6: Cache directories per origin with TTL from `Cache-Control` (bounded min/max); support stale-while-revalidate behavior and graceful handling of rotation (on keyid miss, one forced refresh before failing).
- FR7: Decorate `request.webBotAuth` with: `verified: boolean`, `agent` (origin string), `keyid`, `reason` (enum for failures: `unsigned | expired | bad-signature | unknown-key | directory-unreachable | malformed`), timing metadata.
- FR8: Plugin options: `mode: 'observe' | 'enforce'` (default `observe`), per-route override via route config, `trust` callback or allowlist of agent origins, `fetch` injection (custom dispatcher/proxy), cache options, clock-skew tolerance, `onVerified`/`onFailed` hooks for logging/metrics.
- FR9: In enforce mode, reply 401/403 with a structured, machine-readable error body (design this shape carefully — it seeds Stage 2 agent-friendly errors).
- FR10: Emit debug-level logs via the Fastify logger; never log key material.
- FR11: Expose TypeBox/JSON schema for the options object; full TypeScript declarations including the `FastifyRequest` augmentation.

## 6. Non-Functional Requirements

- NFR1: Verification overhead target: <1ms excluding first (uncached) directory fetch; directory fetch never blocks unrelated requests.
- NFR2: Zero runtime dependencies beyond `web-bot-auth`, `fastify-plugin`, and (if needed) a structured-field parser; no native modules.
- NFR3: Node.js ≥20 (built-in WebCrypto Ed25519, built-in fetch).
- NFR4: Security: SSRF-safe directory fetching (only derive URL from validated `Signature-Agent` origin, https only, no redirects across origins, response size cap); constant-time comparisons via WebCrypto; no crypto rolled by hand.
- NFR5: Test coverage ≥90%; include RFC 9421 Appendix B.1.4 test key vectors and an integration test against `http-message-signatures-example.research.cloudflare.com` (network-gated/optional in CI).
- NFR6: ESM-first with CJS compatibility per current Fastify ecosystem conventions.
- NFR7: Docs: README with quickstart, threat-model notes, observe→enforce rollout guide, and a table of known signers (OpenAI `https://chatgpt.com`, Google `https://agent.bot.goog`, Amazon Bedrock AgentCore, Goose, Browserbase, Anchor Browser).

## 7. Technical Context & Constraints

- **Standards base:** RFC 9421 (stable, Feb 2024) + IETF Web Bot Auth drafts (`draft-meunier-web-bot-auth-architecture-05`, Mar 2026; WG chartered Oct 2025, zero adopted docs as of Aug 2026 — expect churn in directory/registry details and header forms).
- **Key insulation decision:** depend on Cloudflare's `web-bot-auth` npm library for crypto/spec-tracking; the plugin owns Fastify integration, caching, policy hooks, and DX.
- **Known interop hazard:** OpenAI/Cloudflare send bare-string `Signature-Agent`; Google sends dictionary form (with `g=` label); newer draft mandates dictionary. Must accept both; make this a headline feature and test matrix dimension.
- **JWKS rotation** is the production pitfall "nobody hits in testing" — treat cache/rotation logic as a first-class module with its own unit tests.
- Repo conventions: TypeScript, Vitest (or node:test per Fastify conventions — Architect to decide), Biome/ESLint, semantic-release or release-please, MIT or Apache-2.0 (note: upstream lib is Apache-2.0).

## 8. Success Metrics

- M1: Published to npm as `fastify-web-bot-auth` with passing test matrix (both header forms, rotation, expiry, tamper cases).
- M2: Verifies real signed traffic from at least one production signer (OpenAI ChatGPT Agent or Cloudflare's test bot) in a demo app.
- M3: Listed on the official Fastify ecosystem page; stretch: adoption conversation with the Fastify org (`@fastify/web-bot-auth`).
- M4: ≥500 weekly npm downloads OR ecosystem-list inclusion → triggers Stage 2 planning.
- M5: Zero reported security issues in SSRF/verification paths in first 90 days.

## 9. Risks & Mitigations

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| IETF drafts change header/directory details | High | Medium | Depend on `web-bot-auth` lib for spec tracking; version plugin conservatively; feature-flag draft-specific behavior |
| Fastify org or Platformatic ships first-party equivalent | Low-Med | High | Ship fast; engage Fastify maintainers early; be the contributor, not the competitor |
| Low near-term downloads (early market) | High | Low | Treat as category-defining OSS + content asset; measure via M2/M3 not raw downloads |
| SSRF / security bug in directory fetching | Medium | High | NFR4 controls; security-focused review; fuzz malformed headers |
| Signers' directories unreliable/slow | Medium | Medium | Bounded timeouts, negative caching, `directory-unreachable` verdict rather than hard failure in observe mode |

## 10. Open Questions (for PM/Architect phases)

- OQ1: Should enforce-mode rejection integrate with `@fastify/auth` composition patterns (so Web Bot Auth can be one strategy among several)?
- OQ2: Nonce replay protection — in scope for v1 (requires a store) or documented as out-of-scope?
- OQ3: Ship a tiny `/.well-known` *debug* endpoint (echo verification verdict) for agent developers, or keep the plugin verification-only?
- OQ4: Directory cache: in-memory only for v1, or pluggable store interface (Redis) from day one?
- OQ5: Package scope/name fallback if `fastify-web-bot-auth` is contested; reserve `fastify-agent-ready` name now for the future meta-package?
- OQ6: Vitest vs node:test to align with potential `@fastify/*` adoption requirements.

## 11. Deliverables Checklist (Stage 1)

- [ ] Plugin source (TS), typed request decoration, options schema
- [ ] Directory fetch/cache/rotation module with unit tests
- [ ] Verification module wrapping `web-bot-auth`, both `Signature-Agent` forms
- [ ] Observe/enforce modes + per-route config + trust callback
- [ ] Test suite: RFC 9421 vectors, tamper/expiry/rotation/malformed cases, integration test vs Cloudflare research endpoint
- [ ] Demo app + README (quickstart, rollout guide, signer table)
- [ ] CI (lint, typecheck, test matrix Node 20/22, Fastify v5), release automation
- [ ] Launch content: announcement post + Fastify ecosystem PR
