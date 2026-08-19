import type { FastifyBaseLogger, FastifyRequest } from 'fastify';

/**
 * Machine-readable reason a request failed Web Bot Auth verification.
 */
export type WebBotAuthReason =
  | 'unsigned'
  | 'expired'
  | 'bad-signature'
  | 'unknown-key'
  | 'directory-unreachable'
  | 'malformed';

/**
 * Verification verdict decorated onto `request.webBotAuth`.
 */
export interface WebBotAuthResult {
  /** True when the signature cryptographically verified against a directory key. */
  verified: boolean;
  /** The https origin of the signing agent (from `Signature-Agent`), when known. */
  agent?: string;
  /** The JWK thumbprint keyid the signature was made with, when known. */
  keyid?: string;
  /** Result of the `trust` policy. Only set when `verified` is true. */
  trusted?: boolean;
  /** Why verification failed. Only set when `verified` is false. */
  reason?: WebBotAuthReason;
  /** Wall-clock milliseconds spent verifying this request. */
  elapsedMs: number;
}

export type WebBotAuthMode = 'observe' | 'enforce';

/**
 * Per-route override, set via `config.webBotAuth` on a route.
 */
export interface WebBotAuthRouteConfig {
  mode?: WebBotAuthMode;
}

/**
 * Trust policy: either a static allowlist of https agent origins (entries are
 * normalized to origins at registration; invalid or non-https entries throw),
 * or a callback receiving the verdict and the request. Only a strict `true`
 * return counts as trusted; a throwing callback counts as untrusted.
 */
export type WebBotAuthTrust =
  | string[]
  | ((result: WebBotAuthResult, request: FastifyRequest) => boolean | Promise<boolean>);

export interface WebBotAuthOptions {
  /** Global mode. Default `'observe'` (never blocks). */
  mode?: WebBotAuthMode;
  /** Trust policy applied to verified requests. Default: trust every verified agent. */
  trust?: WebBotAuthTrust;
  /** Allowed clock skew, in seconds, for `created`/`expires` checks. Default 60. */
  clockSkew?: number;
  /** Timeout for a single directory fetch, in milliseconds. Default 5000. */
  directoryTimeoutMs?: number;
  /** Maximum accepted directory response size in bytes. Default 65536 (64 KB). */
  directoryMaxBytes?: number;
  /** How long a failing directory origin is negative-cached, in milliseconds. Default 30000. */
  directoryNegativeTtlMs?: number;
  /** Injectable fetch implementation (testing / custom agents). Default: global fetch. */
  fetch?: typeof globalThis.fetch;
  /**
   * Called after a request verifies successfully. Awaited on the request
   * path before the route handler runs — a slow hook adds latency to every
   * verified request, so keep it fast and offload heavy work.
   */
  onVerified?: (result: WebBotAuthResult, request: FastifyRequest) => void | Promise<void>;
  /**
   * Called after a request fails verification. Awaited on the request path
   * (also before enforce-mode 401 replies) — keep it fast and offload heavy
   * work.
   */
  onFailed?: (result: WebBotAuthResult, request: FastifyRequest) => void | Promise<void>;
}

/**
 * Plain-JSON schema for {@link WebBotAuthOptions}. Function-valued options
 * (`trust` callback, `fetch`, `onVerified`, `onFailed`) cannot be expressed in
 * JSON schema and are intentionally left loose.
 */
export const optionsSchema = {
  $id: 'fastify-web-bot-auth-options',
  type: 'object',
  additionalProperties: false,
  properties: {
    mode: { type: 'string', enum: ['observe', 'enforce'] },
    trust: {},
    clockSkew: { type: 'number', minimum: 0 },
    directoryTimeoutMs: { type: 'number', minimum: 1 },
    directoryMaxBytes: { type: 'number', minimum: 1 },
    directoryNegativeTtlMs: { type: 'number', minimum: 0 },
    fetch: {},
    onVerified: {},
    onFailed: {},
  },
} as const;

/** Internal: options with defaults applied. */
export interface ResolvedWebBotAuthOptions {
  mode: WebBotAuthMode;
  trust: WebBotAuthTrust | undefined;
  clockSkew: number;
  directoryTimeoutMs: number;
  directoryMaxBytes: number;
  directoryNegativeTtlMs: number;
  fetch: typeof globalThis.fetch;
  onVerified: WebBotAuthOptions['onVerified'];
  onFailed: WebBotAuthOptions['onFailed'];
  logger: FastifyBaseLogger | undefined;
}

declare module 'fastify' {
  interface FastifyRequest {
    webBotAuth: WebBotAuthResult | null;
  }
  interface FastifyContextConfig {
    webBotAuth?: WebBotAuthRouteConfig;
  }
}
