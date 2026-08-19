import type { webcrypto } from 'node:crypto';
import { jwkThumbprint } from 'jsonwebkey-thumbprint';
import { HTTP_MESSAGE_SIGNATURES_DIRECTORY, MediaType, helpers } from 'web-bot-auth';
import { isForbiddenHost } from './signature-agent.js';

type JsonWebKey = webcrypto.JsonWebKey;

const DEFAULT_TTL_MS = 3_600_000; // 1 h
const MIN_TTL_MS = 60_000; // 60 s
const MAX_TTL_MS = 86_400_000; // 24 h
const DEFAULT_TIMEOUT_MS = 5_000;
const DEFAULT_MAX_BYTES = 64 * 1024;
const DEFAULT_NEGATIVE_TTL_MS = 30_000;
const DEFAULT_MAX_ORIGINS = 1000;
const DEFAULT_MIN_FORCED_REFRESH_INTERVAL_MS = 30_000;
const DEFAULT_MAX_STALE_MS = 86_400_000; // 24 h past fetch, then treated as unreachable
const MAX_REDIRECTS = 3;
const REDIRECT_STATUSES = new Set([301, 302, 303, 307, 308]);

export type DirectoryFailure = 'directory-unreachable' | 'malformed';

/** Typed failure raised by {@link DirectoryCache} lookups. */
export class DirectoryError extends Error {
  readonly reason: DirectoryFailure;

  constructor(reason: DirectoryFailure, message: string) {
    super(message);
    this.name = 'DirectoryError';
    this.reason = reason;
  }
}

interface MinimalLogger {
  debug: (msg: string) => void;
}

export interface DirectoryCacheOptions {
  /** Injectable fetch implementation. Default: global fetch. */
  fetch?: typeof globalThis.fetch;
  /** Per-fetch timeout in milliseconds. Default 5000. */
  timeoutMs?: number;
  /** Maximum accepted response size in bytes. Default 65536. */
  maxBytes?: number;
  /** Negative-cache TTL in milliseconds. Default 30000. */
  negativeTtlMs?: number;
  /** Maximum number of origins tracked (oldest evicted first). Default 1000. */
  maxOrigins?: number;
  /**
   * Minimum interval between forced refreshes of one origin, in milliseconds.
   * Within the interval, further keyid misses resolve as unknown without a
   * fetch. Default 30000.
   */
  minForcedRefreshIntervalMs?: number;
  /**
   * Maximum age of a cached directory, in milliseconds, past which stale keys
   * are no longer served and a blocking refetch is required. Default 86400000
   * (24 h).
   */
  maxStaleMs?: number;
  /** Debug logger (e.g. the Fastify logger). Never receives key material. */
  logger?: MinimalLogger;
  /** Clock override for tests. */
  now?: () => number;
}

interface CacheEntry {
  /** keyid (RFC 7638/8037 base64url SHA-256 thumbprint) -> Ed25519 JWK */
  keys: Map<string, JsonWebKey>;
  fetchedAt: number;
  ttlMs: number;
  /** When the last forced (keyid-miss) refresh of this origin started. */
  forcedRefreshAt?: number;
}

interface NegativeEntry {
  reason: DirectoryFailure;
  until: number;
}

/**
 * Per-origin, in-memory cache of Web Bot Auth key directories
 * (`/.well-known/http-message-signatures-directory`).
 *
 * - TTL from `Cache-Control: max-age`, clamped to [60 s, 24 h], default 1 h.
 * - Stale-while-revalidate: stale hits are served while a background refresh runs.
 * - Single-flight: concurrent refreshes of one origin share one fetch.
 * - One forced (blocking) refresh when a keyid is not in the cached directory,
 *   throttled to one forced refresh per origin per interval (default 30 s).
 * - Stale keys are served at most `maxStaleMs` (default 24 h) past fetch; past
 *   that the directory must be refetched.
 * - Negative caching of failing origins; tracked origins are capped (default
 *   1000) with oldest-first eviction.
 * - SSRF-safe fetch: public https origins only (no localhost / private /
 *   link-local IP literals), same-origin redirects only, response size cap,
 *   bounded timeout covering headers and body.
 */
export class DirectoryCache {
  private readonly entries = new Map<string, CacheEntry>();
  private readonly negative = new Map<string, NegativeEntry>();
  private readonly inflight = new Map<string, Promise<CacheEntry>>();

  private readonly fetchImpl: typeof globalThis.fetch;
  private readonly timeoutMs: number;
  private readonly maxBytes: number;
  private readonly negativeTtlMs: number;
  private readonly maxOrigins: number;
  private readonly minForcedRefreshIntervalMs: number;
  private readonly maxStaleMs: number;
  private readonly logger: MinimalLogger | undefined;
  private readonly now: () => number;

  constructor(options: DirectoryCacheOptions = {}) {
    this.fetchImpl = options.fetch ?? globalThis.fetch;
    this.timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
    this.maxBytes = options.maxBytes ?? DEFAULT_MAX_BYTES;
    this.negativeTtlMs = options.negativeTtlMs ?? DEFAULT_NEGATIVE_TTL_MS;
    this.maxOrigins = options.maxOrigins ?? DEFAULT_MAX_ORIGINS;
    this.minForcedRefreshIntervalMs =
      options.minForcedRefreshIntervalMs ?? DEFAULT_MIN_FORCED_REFRESH_INTERVAL_MS;
    this.maxStaleMs = options.maxStaleMs ?? DEFAULT_MAX_STALE_MS;
    this.logger = options.logger;
    this.now = options.now ?? Date.now;
  }

  /**
   * Resolve `keyid` in the directory of `origin`.
   *
   * Returns the JWK, or `null` when the directory is reachable but does not
   * contain the key (after one forced refresh). Throws {@link DirectoryError}
   * when the directory cannot be fetched or is malformed.
   */
  async getKey(origin: string, keyid: string): Promise<JsonWebKey | null> {
    this.assertHttpsOrigin(origin);
    let entry = this.entries.get(origin);

    // Staleness cap: past maxStaleMs the cached directory is too old to serve
    // even as a stale fallback; drop it and require a blocking refetch.
    if (entry && this.now() - entry.fetchedAt > this.maxStaleMs) {
      this.entries.delete(origin);
      entry = undefined;
    }

    if (entry) {
      const key = entry.keys.get(keyid);
      if (key) {
        if (this.isStale(entry) && !this.isNegativeCached(origin)) {
          this.revalidateInBackground(origin);
        }
        return key;
      }
      // keyid miss: possible rotation. One forced refresh, unless the origin
      // recently failed (negative cache) or was force-refreshed within the
      // throttle interval — then treat as unknown against the directory we have.
      if (this.isNegativeCached(origin)) return null;
      if (
        entry.forcedRefreshAt !== undefined &&
        this.now() - entry.forcedRefreshAt < this.minForcedRefreshIntervalMs
      ) {
        return null;
      }
      const forcedRefreshAt = this.now();
      entry.forcedRefreshAt = forcedRefreshAt;
      const refreshed = await this.refresh(origin);
      refreshed.forcedRefreshAt = forcedRefreshAt;
      return refreshed.keys.get(keyid) ?? null;
    }

    const negative = this.negative.get(origin);
    if (negative && negative.until > this.now()) {
      throw new DirectoryError(negative.reason, `directory for ${origin} is negative-cached`);
    }
    const fresh = await this.refresh(origin);
    return fresh.keys.get(keyid) ?? null;
  }

  /** Drop all cached state (tests / manual invalidation). */
  clear(): void {
    this.entries.clear();
    this.negative.clear();
    this.inflight.clear();
  }

  private assertHttpsOrigin(origin: string): void {
    let url: URL;
    try {
      url = new URL(origin);
    } catch {
      throw new DirectoryError('malformed', `invalid origin: ${origin}`);
    }
    if (url.protocol !== 'https:' || url.origin !== origin) {
      throw new DirectoryError('malformed', `origin must be a bare https origin: ${origin}`);
    }
    if (isForbiddenHost(url.hostname)) {
      throw new DirectoryError(
        'malformed',
        `origin host is not allowed for directory fetches: ${url.hostname}`,
      );
    }
  }

  private isStale(entry: CacheEntry): boolean {
    return this.now() - entry.fetchedAt >= entry.ttlMs;
  }

  /** Insert into a per-origin map, evicting the oldest entry at capacity. */
  private boundedSet<T>(map: Map<string, T>, origin: string, value: T): void {
    if (!map.has(origin) && map.size >= this.maxOrigins) {
      const oldest = map.keys().next().value;
      if (oldest !== undefined) map.delete(oldest);
    }
    map.set(origin, value);
  }

  private isNegativeCached(origin: string): boolean {
    const negative = this.negative.get(origin);
    return negative !== undefined && negative.until > this.now();
  }

  private revalidateInBackground(origin: string): void {
    this.refresh(origin).catch(() => {
      // Failure is already negative-cached by refresh(); stale keys keep serving.
    });
  }

  /** Single-flight refresh of an origin's directory. */
  private refresh(origin: string): Promise<CacheEntry> {
    const pending = this.inflight.get(origin);
    if (pending) return pending;

    const task = (async () => {
      try {
        const entry = await this.fetchDirectory(origin);
        this.boundedSet(this.entries, origin, entry);
        this.negative.delete(origin);
        return entry;
      } catch (err) {
        const reason: DirectoryFailure =
          err instanceof DirectoryError ? err.reason : 'directory-unreachable';
        this.boundedSet(this.negative, origin, {
          reason,
          until: this.now() + this.negativeTtlMs,
        });
        this.logger?.debug(
          `web-bot-auth: directory fetch for ${origin} failed (${reason}): ${(err as Error).message}`,
        );
        if (err instanceof DirectoryError) throw err;
        throw new DirectoryError('directory-unreachable', (err as Error).message);
      } finally {
        this.inflight.delete(origin);
      }
    })();

    this.inflight.set(origin, task);
    return task;
  }

  private async fetchDirectory(origin: string): Promise<CacheEntry> {
    // One deadline covers the whole operation: connection, headers, redirect
    // hops, and the body read — a trickling body cannot hang the hook.
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);
    if (typeof timer === 'object' && 'unref' in timer) timer.unref();

    try {
      const response = await this.fetchWithPolicy(origin, controller.signal);
      if (!response.ok) {
        throw new DirectoryError(
          'directory-unreachable',
          `directory fetch for ${origin} returned HTTP ${response.status}`,
        );
      }

      const contentType = response.headers.get('content-type') ?? '';
      if (!contentType.includes(MediaType.HTTP_MESSAGE_SIGNATURES_DIRECTORY)) {
        this.logger?.debug(
          `web-bot-auth: directory for ${origin} served unexpected content-type "${contentType}"; attempting to parse anyway`,
        );
      }

      const body = await this.readBodyCapped(response, origin, controller.signal);
      const keys = await this.parseDirectory(body, origin);
      return {
        keys,
        fetchedAt: this.now(),
        ttlMs: this.parseTtl(response.headers.get('cache-control')),
      };
    } finally {
      clearTimeout(timer);
    }
  }

  /** Fetch with same-origin-only redirect following under the given signal. */
  private async fetchWithPolicy(origin: string, signal: AbortSignal): Promise<Response> {
    let url = new URL(HTTP_MESSAGE_SIGNATURES_DIRECTORY, origin);

    try {
      for (let hop = 0; hop <= MAX_REDIRECTS; hop++) {
        const response = await this.fetchImpl(url.toString(), {
          redirect: 'manual',
          signal,
          headers: { accept: MediaType.HTTP_MESSAGE_SIGNATURES_DIRECTORY },
        });
        if (!REDIRECT_STATUSES.has(response.status)) return response;

        // The redirect response's body is never used; release the connection.
        await response.body?.cancel().catch(() => {});

        const location = response.headers.get('location');
        if (!location) {
          throw new DirectoryError(
            'directory-unreachable',
            `redirect without Location from ${origin}`,
          );
        }
        const next = new URL(location, url);
        if (next.origin !== origin) {
          throw new DirectoryError(
            'directory-unreachable',
            `cross-origin redirect refused: ${origin} -> ${next.origin}`,
          );
        }
        url = next;
      }
      throw new DirectoryError('directory-unreachable', `too many redirects from ${origin}`);
    } catch (err) {
      if (err instanceof DirectoryError) throw err;
      const aborted = (err as Error).name === 'AbortError' || signal.aborted;
      throw new DirectoryError(
        'directory-unreachable',
        aborted
          ? `directory fetch for ${origin} timed out after ${this.timeoutMs}ms`
          : `directory fetch for ${origin} failed: ${(err as Error).message}`,
      );
    }
  }

  private async readBodyCapped(
    response: Response,
    origin: string,
    signal: AbortSignal,
  ): Promise<string> {
    const declared = Number(response.headers.get('content-length'));
    if (Number.isFinite(declared) && declared > this.maxBytes) {
      throw new DirectoryError(
        'malformed',
        `directory for ${origin} exceeds size cap (${declared} > ${this.maxBytes} bytes)`,
      );
    }

    const timedOut = () =>
      new DirectoryError(
        'directory-unreachable',
        `directory body read for ${origin} timed out after ${this.timeoutMs}ms`,
      );

    if (response.body && typeof response.body.getReader === 'function') {
      const reader = response.body.getReader();
      // A pending reader.read() does not observe the fetch signal by itself;
      // cancel the reader on abort so the read settles and the hook cannot hang.
      const onAbort = () => {
        reader.cancel().catch(() => {});
      };
      if (signal.aborted) onAbort();
      signal.addEventListener('abort', onAbort, { once: true });
      try {
        const chunks: Uint8Array[] = [];
        let total = 0;
        for (;;) {
          const { done, value } = await reader.read();
          if (signal.aborted) throw timedOut();
          if (done) break;
          total += value.byteLength;
          if (total > this.maxBytes) {
            await reader.cancel().catch(() => {});
            throw new DirectoryError(
              'malformed',
              `directory for ${origin} exceeds size cap (${this.maxBytes} bytes)`,
            );
          }
          chunks.push(value);
        }
        return new TextDecoder().decode(concat(chunks, total));
      } finally {
        signal.removeEventListener('abort', onAbort);
      }
    }

    const text = await Promise.race([
      response.text(),
      new Promise<never>((_resolve, reject) => {
        if (signal.aborted) reject(timedOut());
        signal.addEventListener('abort', () => reject(timedOut()), { once: true });
      }),
    ]);
    if (new TextEncoder().encode(text).byteLength > this.maxBytes) {
      throw new DirectoryError(
        'malformed',
        `directory for ${origin} exceeds size cap (${this.maxBytes} bytes)`,
      );
    }
    return text;
  }

  private async parseDirectory(body: string, origin: string): Promise<Map<string, JsonWebKey>> {
    let parsed: unknown;
    try {
      parsed = JSON.parse(body);
    } catch {
      throw new DirectoryError('malformed', `directory for ${origin} is not valid JSON`);
    }
    if (
      parsed === null ||
      typeof parsed !== 'object' ||
      !Array.isArray((parsed as { keys?: unknown }).keys)
    ) {
      throw new DirectoryError('malformed', `directory for ${origin} is not a JWKS ("keys" array)`);
    }

    const keys = new Map<string, JsonWebKey>();
    for (const candidate of (parsed as { keys: unknown[] }).keys) {
      if (!isEd25519Jwk(candidate)) {
        this.logger?.debug(`web-bot-auth: skipping non-Ed25519 key in directory for ${origin}`);
        continue;
      }
      const jwk: JsonWebKey = { kty: 'OKP', crv: 'Ed25519', x: candidate.x };
      const keyid = await jwkThumbprint(jwk, helpers.WEBCRYPTO_SHA256, helpers.BASE64URL_DECODE);
      keys.set(keyid, jwk);
    }
    return keys;
  }

  /** `Cache-Control: max-age` clamped to [60 s, 24 h]; default 1 h. */
  private parseTtl(cacheControl: string | null): number {
    if (!cacheControl) return DEFAULT_TTL_MS;
    const match = /(?:^|[\s,])max-age\s*=\s*(\d+)/i.exec(cacheControl);
    if (!match?.[1]) return DEFAULT_TTL_MS;
    const ttlMs = Number(match[1]) * 1000;
    return Math.min(Math.max(ttlMs, MIN_TTL_MS), MAX_TTL_MS);
  }
}

function isEd25519Jwk(candidate: unknown): candidate is { kty: 'OKP'; crv: 'Ed25519'; x: string } {
  return (
    candidate !== null &&
    typeof candidate === 'object' &&
    (candidate as JsonWebKey).kty === 'OKP' &&
    (candidate as JsonWebKey).crv === 'Ed25519' &&
    typeof (candidate as JsonWebKey).x === 'string'
  );
}

function concat(chunks: Uint8Array[], total: number): Uint8Array {
  const out = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    out.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return out;
}
