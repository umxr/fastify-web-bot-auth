import { SIGNATURE_AGENT_HEADER, validateNonce, verify } from 'web-bot-auth';
import { verifierFromJWK } from 'web-bot-auth/crypto';
import { type DirectoryCache, DirectoryError } from './directory.js';
import { parseSignatureAgent } from './signature-agent.js';
import type { WebBotAuthReason, WebBotAuthResult } from './types.js';

/** Structural subset of a Fastify request needed for verification. */
export interface VerifiableRequest {
  method: string;
  url: string;
  protocol: string;
  headers: Record<string, string | string[] | undefined>;
}

export interface VerifyRequestOptions {
  /**
   * Allowed clock skew in seconds for the created/expires window.
   *
   * Note: the underlying `web-bot-auth` library enforces a strict
   * `created <= now <= expires` window before this plugin's skew-tolerant
   * checks run, so `clockSkew` cannot widen the window beyond the library's
   * strict check — a signature even one second past `expires` is `'expired'`.
   */
  clockSkew: number;
  /** Logger for debug traces and warn-level internal faults. Never receives key material. */
  logger?: { debug: (msg: string) => void; warn?: (obj: unknown, msg?: string) => void };
  /** Clock override for tests. */
  now?: () => number;
}

class ReasonError extends Error {
  readonly reason: WebBotAuthReason;

  constructor(reason: WebBotAuthReason, message: string) {
    super(message);
    this.name = 'ReasonError';
    this.reason = reason;
  }
}

/**
 * Verify a request's Web Bot Auth signature against the signer's key
 * directory. Never throws: every failure maps to a `reason` on the verdict.
 */
export async function verifyRequest(
  request: VerifiableRequest,
  cache: DirectoryCache,
  options: VerifyRequestOptions,
): Promise<WebBotAuthResult> {
  const startedAt = performance.now();
  const finish = (partial: Omit<WebBotAuthResult, 'elapsedMs'>): WebBotAuthResult => ({
    ...partial,
    elapsedMs: Math.max(0, Math.round(performance.now() - startedAt)),
  });

  const headers = request.headers;
  if (!headerValue(headers, 'signature') || !headerValue(headers, 'signature-input')) {
    return finish({ verified: false, reason: 'unsigned' });
  }

  const agentHeader = headerValue(headers, SIGNATURE_AGENT_HEADER);
  const agent = parseSignatureAgent(agentHeader);
  if (agent === null) {
    options.logger?.debug(
      agentHeader === undefined
        ? 'web-bot-auth: signed request without a Signature-Agent header'
        : 'web-bot-auth: Signature-Agent is not a valid public https origin',
    );
    return finish({ verified: false, reason: 'malformed' });
  }

  const now = options.now ?? Date.now;
  const skewMs = options.clockSkew * 1000;
  let keyid: string | undefined;

  try {
    await verify(
      {
        method: request.method,
        url: request.url,
        protocol: request.protocol,
        headers: request.headers as Record<string, string | string[]>,
      },
      async (data, signature, params) => {
        keyid = params.keyid;
        if (!(params.created instanceof Date) || !(params.expires instanceof Date)) {
          throw new ReasonError('malformed', 'signature is missing created/expires parameters');
        }
        const nowMs = now();
        if (params.created.getTime() > nowMs + skewMs) {
          throw new ReasonError('expired', 'created is in the future beyond clock skew');
        }
        if (params.expires.getTime() < nowMs - skewMs) {
          throw new ReasonError('expired', 'signature expired beyond clock skew');
        }
        if (params.nonce !== undefined && !validateNonce(params.nonce)) {
          throw new ReasonError('malformed', 'nonce has an invalid length or format');
        }

        const jwk = await cache.getKey(agent, params.keyid);
        if (jwk === null) {
          throw new ReasonError(
            'unknown-key',
            `keyid ${params.keyid} not found in directory for ${agent}`,
          );
        }
        const verifyWithKey = await verifierFromJWK(jwk);
        try {
          await verifyWithKey(data, signature, params);
        } catch (err) {
          throw new ReasonError('bad-signature', (err as Error).message);
        }
      },
    );
  } catch (err) {
    const { reason, expected } = mapFailure(err);
    if (expected) {
      options.logger?.debug(
        `web-bot-auth: verification failed (${reason}): ${(err as Error).message}`,
      );
    } else {
      // An error that is neither a typed verdict nor a known library parse
      // failure points at a server-side fault (cache bug, unexpected
      // upstream change). Surface it for operators; the verdict stays a
      // reason, never a throw. The error object carries no key material.
      options.logger?.warn?.(
        { err },
        `web-bot-auth: unexpected internal error during verification (mapped to '${reason}')`,
      );
    }
    return finish({ verified: false, agent, keyid, reason });
  }

  return finish({ verified: true, agent, keyid });
}

function headerValue(
  headers: Record<string, string | string[] | undefined>,
  name: string,
): string | string[] | undefined {
  const direct = headers[name];
  if (direct !== undefined) return direct;
  const lower = name.toLowerCase();
  for (const key of Object.keys(headers)) {
    if (key.toLowerCase() === lower) return headers[key];
  }
  return undefined;
}

/**
 * Known failure messages thrown by `web-bot-auth` / `http-message-sig` while
 * parsing or validating a message. These are expected client-input failures
 * and map to `'malformed'` without operator noise.
 */
const KNOWN_LIBRARY_FAILURES = [
  /invalid .* header/i,
  /multiple signatures is not supported/i,
  /missing components/i,
  /failed to parse/i,
  /key mismatch/i,
  /tag must be/i,
  /keyid must be defined/i,
  /nonce is not a valid/i,
  /only valid for (requests|responses)/i,
  /unknown specialty component/i,
  /not implemented yet/i,
  /component parameter can only be used/i,
  // `web-bot-auth` dereferences created/expires before this plugin can guard
  // them; a Signature-Input without those params surfaces as this TypeError.
  /cannot read properties of undefined \(reading 'gettime'\)/i,
];

function mapFailure(err: unknown): { reason: WebBotAuthReason; expected: boolean } {
  if (err instanceof ReasonError) return { reason: err.reason, expected: true };
  if (err instanceof DirectoryError) return { reason: err.reason, expected: true };
  const message = err instanceof Error ? err.message : String(err);
  if (/does not contain signature/i.test(message)) return { reason: 'unsigned', expected: true };
  if (/expired|created in the future/i.test(message)) return { reason: 'expired', expected: true };
  if (KNOWN_LIBRARY_FAILURES.some((pattern) => pattern.test(message))) {
    return { reason: 'malformed', expected: true };
  }
  // Crypto verification failures surface as ReasonError('bad-signature') from
  // the callback; anything else is an unexpected internal fault, still
  // reported as 'malformed' to keep the public reason enum stable.
  return { reason: 'malformed', expected: false };
}
