import { beforeAll, describe, expect, it, vi } from 'vitest';
import { DirectoryCache, DirectoryError } from '../src/directory.js';
import {
  DIRECTORY_MEDIA_TYPE,
  TEST_PUBLIC_JWK,
  directoryBody,
  directoryResponse,
  generateEd25519Jwks,
  thumbprint,
} from './helpers.js';

const ORIGIN = 'https://signer.test';
const DIRECTORY_URL = `${ORIGIN}/.well-known/http-message-signatures-directory`;

let keyid: string;

beforeAll(async () => {
  keyid = await thumbprint(TEST_PUBLIC_JWK);
});

function makeCache(
  fetchImpl: typeof fetch,
  extra: ConstructorParameters<typeof DirectoryCache>[0] = {},
) {
  return new DirectoryCache({ fetch: fetchImpl, ...extra });
}

describe('DirectoryCache', () => {
  it('fetches the well-known directory and resolves a key by thumbprint', async () => {
    const fetchMock = vi.fn(async (..._args: Parameters<typeof fetch>) =>
      directoryResponse(directoryBody(TEST_PUBLIC_JWK)),
    );
    const cache = makeCache(fetchMock);

    const jwk = await cache.getKey(ORIGIN, keyid);
    expect(jwk).toEqual({ kty: 'OKP', crv: 'Ed25519', x: TEST_PUBLIC_JWK.x });
    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(fetchMock.mock.calls[0]?.[0]).toBe(DIRECTORY_URL);
    const init = fetchMock.mock.calls[0]?.[1];
    expect(init?.redirect).toBe('manual');
    expect((init?.headers as Record<string, string>).accept).toBe(DIRECTORY_MEDIA_TYPE);
  });

  it('serves from cache within the TTL without refetching', async () => {
    const fetchMock = vi.fn(async () => directoryResponse(directoryBody(TEST_PUBLIC_JWK)));
    let nowMs = 1_000_000;
    const cache = makeCache(fetchMock, { now: () => nowMs });

    await cache.getKey(ORIGIN, keyid);
    nowMs += 3_599_000; // just inside the default 1 h TTL
    await cache.getKey(ORIGIN, keyid);
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it('honors Cache-Control max-age and revalidates stale entries in the background', async () => {
    const fetchMock = vi.fn(async () =>
      directoryResponse(directoryBody(TEST_PUBLIC_JWK), { cacheControl: 'max-age=120' }),
    );
    let nowMs = 1_000_000;
    const cache = makeCache(fetchMock, { now: () => nowMs });

    await cache.getKey(ORIGIN, keyid);
    nowMs += 121_000; // past the 120 s TTL
    const jwk = await cache.getKey(ORIGIN, keyid); // stale-while-revalidate
    expect(jwk).not.toBeNull();
    await vi.waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(2));
  });

  it('clamps max-age below 60 s up to 60 s', async () => {
    const fetchMock = vi.fn(async () =>
      directoryResponse(directoryBody(TEST_PUBLIC_JWK), { cacheControl: 'max-age=1' }),
    );
    let nowMs = 1_000_000;
    const cache = makeCache(fetchMock, { now: () => nowMs });

    await cache.getKey(ORIGIN, keyid);
    nowMs += 59_000; // beyond max-age=1 but inside the 60 s clamp
    await cache.getKey(ORIGIN, keyid);
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it('clamps max-age above 24 h down to 24 h', async () => {
    const fetchMock = vi.fn(async () =>
      directoryResponse(directoryBody(TEST_PUBLIC_JWK), { cacheControl: 'public, max-age=172800' }),
    );
    let nowMs = 1_000_000;
    const cache = makeCache(fetchMock, { now: () => nowMs });

    await cache.getKey(ORIGIN, keyid);
    nowMs += 25 * 3_600_000; // past the 24 h clamp, inside the served 48 h
    await cache.getKey(ORIGIN, keyid);
    await vi.waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(2));
  });

  it('deduplicates concurrent fetches for one origin (single-flight)', async () => {
    let release: (r: Response) => void = () => {};
    const fetchMock = vi.fn(
      () =>
        new Promise<Response>((resolve) => {
          release = resolve;
        }),
    );
    const cache = makeCache(fetchMock as unknown as typeof fetch);

    const first = cache.getKey(ORIGIN, keyid);
    const second = cache.getKey(ORIGIN, keyid);
    release(directoryResponse(directoryBody(TEST_PUBLIC_JWK)));
    const [a, b] = await Promise.all([first, second]);
    expect(a).not.toBeNull();
    expect(b).not.toBeNull();
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it('forces exactly one refresh when a keyid is missing (rotation)', async () => {
    const { publicJwk: rotatedPublic } = await generateEd25519Jwks();
    const rotatedKeyid = await thumbprint(rotatedPublic);
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(directoryResponse(directoryBody(TEST_PUBLIC_JWK)))
      .mockResolvedValue(directoryResponse(directoryBody(TEST_PUBLIC_JWK, rotatedPublic)));
    const cache = makeCache(fetchMock as unknown as typeof fetch);

    await cache.getKey(ORIGIN, keyid); // populates cache with old directory
    const jwk = await cache.getKey(ORIGIN, rotatedKeyid);
    expect(jwk).toEqual({ kty: 'OKP', crv: 'Ed25519', x: rotatedPublic.x });
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it('returns null when a keyid is still missing after the forced refresh', async () => {
    const fetchMock = vi.fn(async () => directoryResponse(directoryBody(TEST_PUBLIC_JWK)));
    const cache = makeCache(fetchMock);

    await cache.getKey(ORIGIN, keyid);
    const jwk = await cache.getKey(ORIGIN, 'nope');
    expect(jwk).toBeNull();
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it('negative-caches unreachable origins for ~30 s', async () => {
    const fetchMock = vi.fn().mockRejectedValue(new TypeError('fetch failed'));
    let nowMs = 1_000_000;
    const cache = makeCache(fetchMock as unknown as typeof fetch, { now: () => nowMs });

    await expect(cache.getKey(ORIGIN, keyid)).rejects.toMatchObject({
      reason: 'directory-unreachable',
    });
    await expect(cache.getKey(ORIGIN, keyid)).rejects.toMatchObject({
      reason: 'directory-unreachable',
    });
    expect(fetchMock).toHaveBeenCalledTimes(1); // second failure came from the negative cache

    nowMs += 31_000;
    fetchMock.mockResolvedValue(directoryResponse(directoryBody(TEST_PUBLIC_JWK)));
    await expect(cache.getKey(ORIGIN, keyid)).resolves.not.toBeNull();
  });

  it('skips the forced refresh while the origin is negative-cached', async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(directoryResponse(directoryBody(TEST_PUBLIC_JWK)))
      .mockRejectedValue(new TypeError('fetch failed'));
    const cache = makeCache(fetchMock as unknown as typeof fetch);

    await cache.getKey(ORIGIN, keyid);
    await expect(cache.getKey(ORIGIN, 'missing-key')).rejects.toMatchObject({
      reason: 'directory-unreachable',
    });
    // Origin is now negative-cached; a further miss resolves against the cached
    // directory instead of refetching.
    await expect(cache.getKey(ORIGIN, 'missing-key')).resolves.toBeNull();
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it('maps HTTP error statuses to directory-unreachable', async () => {
    const fetchMock = vi.fn(async () => directoryResponse('nope', { status: 503 }));
    const cache = makeCache(fetchMock);
    await expect(cache.getKey(ORIGIN, keyid)).rejects.toMatchObject({
      reason: 'directory-unreachable',
    });
  });

  it('aborts slow fetches after the timeout', async () => {
    const fetchMock = vi.fn(
      (_url: string, init?: RequestInit) =>
        new Promise<Response>((_resolve, reject) => {
          init?.signal?.addEventListener('abort', () =>
            reject(new DOMException('The operation was aborted', 'AbortError')),
          );
        }),
    );
    const cache = makeCache(fetchMock as unknown as typeof fetch, { timeoutMs: 20 });
    await expect(cache.getKey(ORIGIN, keyid)).rejects.toMatchObject({
      reason: 'directory-unreachable',
    });
  });

  it('aborts a trickling body read after the timeout', async () => {
    // Headers arrive instantly, but the body never finishes.
    const trickle = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(new TextEncoder().encode('{"keys":['));
        // never closes
      },
    });
    const fetchMock = vi.fn(
      async () =>
        new Response(trickle, {
          status: 200,
          headers: { 'content-type': DIRECTORY_MEDIA_TYPE },
        }),
    );
    const cache = makeCache(fetchMock, { timeoutMs: 30 });
    await expect(cache.getKey(ORIGIN, keyid)).rejects.toMatchObject({
      reason: 'directory-unreachable',
    });
  });

  it('reads bodies from fetch implementations without a streaming body', async () => {
    const body = directoryBody(TEST_PUBLIC_JWK);
    const fetchMock = vi.fn(async () => {
      return {
        ok: true,
        status: 200,
        headers: new Headers({ 'content-type': DIRECTORY_MEDIA_TYPE }),
        body: null,
        text: async () => body,
      } as unknown as Response;
    });
    const cache = makeCache(fetchMock);
    await expect(cache.getKey(ORIGIN, keyid)).resolves.not.toBeNull();
  });

  it('follows same-origin redirects', async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(
        new Response(null, { status: 302, headers: { location: `${ORIGIN}/directory-v2` } }),
      )
      .mockResolvedValueOnce(directoryResponse(directoryBody(TEST_PUBLIC_JWK)));
    const cache = makeCache(fetchMock as unknown as typeof fetch);

    await expect(cache.getKey(ORIGIN, keyid)).resolves.not.toBeNull();
    expect(fetchMock.mock.calls[1]?.[0]).toBe(`${ORIGIN}/directory-v2`);
  });

  it('refuses cross-origin redirects', async () => {
    const fetchMock = vi.fn(
      async () =>
        new Response(null, { status: 302, headers: { location: 'https://evil.test/dir' } }),
    );
    const cache = makeCache(fetchMock as unknown as typeof fetch);
    await expect(cache.getKey(ORIGIN, keyid)).rejects.toMatchObject({
      reason: 'directory-unreachable',
    });
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it('gives up after too many redirects', async () => {
    const fetchMock = vi.fn(
      async () => new Response(null, { status: 302, headers: { location: `${ORIGIN}/loop` } }),
    );
    const cache = makeCache(fetchMock as unknown as typeof fetch);
    await expect(cache.getKey(ORIGIN, keyid)).rejects.toMatchObject({
      reason: 'directory-unreachable',
    });
  });

  it('rejects redirects without a Location header', async () => {
    const fetchMock = vi.fn(async () => new Response(null, { status: 302 }));
    const cache = makeCache(fetchMock as unknown as typeof fetch);
    await expect(cache.getKey(ORIGIN, keyid)).rejects.toMatchObject({
      reason: 'directory-unreachable',
    });
  });

  it('rejects oversized responses (declared via Content-Length)', async () => {
    const fetchMock = vi.fn(async () => {
      const response = directoryResponse(directoryBody(TEST_PUBLIC_JWK));
      response.headers.set('content-length', String(1024 * 1024));
      return response;
    });
    const cache = makeCache(fetchMock);
    await expect(cache.getKey(ORIGIN, keyid)).rejects.toMatchObject({ reason: 'malformed' });
  });

  it('rejects oversized streamed responses', async () => {
    const big = `{"keys":[${'1,'.repeat(40_000)}1]}`;
    const fetchMock = vi.fn(async () => directoryResponse(big));
    const cache = makeCache(fetchMock, { maxBytes: 1024 });
    await expect(cache.getKey(ORIGIN, keyid)).rejects.toMatchObject({ reason: 'malformed' });
  });

  it('rejects invalid JSON as malformed', async () => {
    const fetchMock = vi.fn(async () => directoryResponse('this is not json'));
    const cache = makeCache(fetchMock);
    await expect(cache.getKey(ORIGIN, keyid)).rejects.toMatchObject({ reason: 'malformed' });
  });

  it('rejects JSON without a keys array as malformed', async () => {
    const fetchMock = vi.fn(async () => directoryResponse('{"keys": "nope"}'));
    const cache = makeCache(fetchMock);
    await expect(cache.getKey(ORIGIN, keyid)).rejects.toMatchObject({ reason: 'malformed' });
  });

  it('tolerates an unexpected content-type when the body is a valid JWKS', async () => {
    const debug = vi.fn();
    const fetchMock = vi.fn(async () =>
      directoryResponse(directoryBody(TEST_PUBLIC_JWK), { contentType: 'application/json' }),
    );
    const cache = makeCache(fetchMock, { logger: { debug } });
    await expect(cache.getKey(ORIGIN, keyid)).resolves.not.toBeNull();
    expect(debug).toHaveBeenCalledWith(expect.stringContaining('unexpected content-type'));
  });

  it('skips non-Ed25519 keys', async () => {
    const body = JSON.stringify({
      keys: [
        { kty: 'RSA', n: 'xxx', e: 'AQAB' },
        { kty: 'OKP', crv: 'X25519', x: 'yyy' },
        'garbage',
        null,
        TEST_PUBLIC_JWK,
      ],
    });
    const fetchMock = vi.fn(async () => directoryResponse(body));
    const cache = makeCache(fetchMock);
    await expect(cache.getKey(ORIGIN, keyid)).resolves.not.toBeNull();
  });

  it('rejects non-https or non-origin inputs', async () => {
    const fetchMock = vi.fn();
    const cache = makeCache(fetchMock as unknown as typeof fetch);
    await expect(cache.getKey('http://signer.test', keyid)).rejects.toMatchObject({
      reason: 'malformed',
    });
    await expect(cache.getKey('https://signer.test/path', keyid)).rejects.toMatchObject({
      reason: 'malformed',
    });
    await expect(cache.getKey('not-a-url', keyid)).rejects.toMatchObject({ reason: 'malformed' });
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('serves stale keys while refreshes fail, then stops at the staleness cap', async () => {
    let nowMs = 1_000_000;
    let failing = false;
    const fetchMock = vi.fn(async () => {
      if (failing) throw new TypeError('fetch failed');
      return directoryResponse(directoryBody(TEST_PUBLIC_JWK), { cacheControl: 'max-age=60' });
    });
    const cache = makeCache(fetchMock, { now: () => nowMs });

    await cache.getKey(ORIGIN, keyid); // t0: populate (TTL 60 s)
    failing = true;

    nowMs += 120_000; // stale, refresh will fail in the background
    await expect(cache.getKey(ORIGIN, keyid)).resolves.not.toBeNull();
    await vi.waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(2));

    nowMs += 3_600_000; // still under the 24 h cap; negative cache expired
    await expect(cache.getKey(ORIGIN, keyid)).resolves.not.toBeNull();

    nowMs = 1_000_000 + 25 * 3_600_000; // past the 24 h staleness cap
    await expect(cache.getKey(ORIGIN, keyid)).rejects.toMatchObject({
      reason: 'directory-unreachable',
    });
  });

  it('honors a custom maxStaleMs', async () => {
    let nowMs = 1_000_000;
    let failing = false;
    const fetchMock = vi.fn(async () => {
      if (failing) throw new TypeError('fetch failed');
      return directoryResponse(directoryBody(TEST_PUBLIC_JWK), { cacheControl: 'max-age=60' });
    });
    const cache = makeCache(fetchMock, { now: () => nowMs, maxStaleMs: 120_000 });

    await cache.getKey(ORIGIN, keyid);
    failing = true;
    nowMs += 121_000; // just past the 120 s cap
    await expect(cache.getKey(ORIGIN, keyid)).rejects.toMatchObject({
      reason: 'directory-unreachable',
    });
  });

  it('throttles forced refreshes for fabricated keyids', async () => {
    let nowMs = 1_000_000;
    const fetchMock = vi.fn(async () => directoryResponse(directoryBody(TEST_PUBLIC_JWK)));
    const cache = makeCache(fetchMock, { now: () => nowMs });

    await cache.getKey(ORIGIN, keyid); // initial fetch
    await expect(cache.getKey(ORIGIN, 'bogus-1')).resolves.toBeNull(); // forced refresh
    expect(fetchMock).toHaveBeenCalledTimes(2);

    // Within the 30 s throttle window further misses do not fetch.
    nowMs += 1_000;
    await expect(cache.getKey(ORIGIN, 'bogus-2')).resolves.toBeNull();
    await expect(cache.getKey(ORIGIN, 'bogus-3')).resolves.toBeNull();
    expect(fetchMock).toHaveBeenCalledTimes(2);

    // A real key still resolves from cache during the window.
    await expect(cache.getKey(ORIGIN, keyid)).resolves.not.toBeNull();

    nowMs += 31_000; // past the throttle window
    await expect(cache.getKey(ORIGIN, 'bogus-4')).resolves.toBeNull();
    expect(fetchMock).toHaveBeenCalledTimes(3);
  });

  it('rotation still refreshes after the throttle window and finds the new key', async () => {
    let nowMs = 1_000_000;
    const { publicJwk } = await generateEd25519Jwks();
    const rotatedKeyid = await thumbprint(publicJwk);
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(directoryResponse(directoryBody(TEST_PUBLIC_JWK)))
      .mockResolvedValueOnce(directoryResponse(directoryBody(TEST_PUBLIC_JWK)))
      .mockResolvedValue(directoryResponse(directoryBody(TEST_PUBLIC_JWK, publicJwk)));
    const cache = makeCache(fetchMock as unknown as typeof fetch, {
      now: () => nowMs,
      minForcedRefreshIntervalMs: 10_000,
    });

    await cache.getKey(ORIGIN, keyid);
    await expect(cache.getKey(ORIGIN, 'bogus')).resolves.toBeNull(); // burns the forced refresh...
    nowMs += 5_000; // ...and rotation inside the window resolves as unknown
    await expect(cache.getKey(ORIGIN, rotatedKeyid)).resolves.toBeNull();
    nowMs += 6_000; // window over: rotation is picked up
    await expect(cache.getKey(ORIGIN, rotatedKeyid)).resolves.not.toBeNull();
  });

  it('caps tracked origins with oldest-first eviction', async () => {
    const fetchMock = vi.fn(async () => directoryResponse(directoryBody(TEST_PUBLIC_JWK)));
    const cache = makeCache(fetchMock, { maxOrigins: 2 });

    await cache.getKey('https://a.test', keyid);
    await cache.getKey('https://b.test', keyid);
    await cache.getKey('https://c.test', keyid); // evicts a.test
    expect(fetchMock).toHaveBeenCalledTimes(3);

    await cache.getKey('https://b.test', keyid); // still cached
    expect(fetchMock).toHaveBeenCalledTimes(3);

    await cache.getKey('https://a.test', keyid); // evicted: refetches
    expect(fetchMock).toHaveBeenCalledTimes(4);
  });

  it('rejects localhost and private-range IP origins without fetching', async () => {
    const fetchMock = vi.fn();
    const cache = makeCache(fetchMock as unknown as typeof fetch);
    for (const origin of [
      'https://localhost',
      'https://127.0.0.1',
      'https://10.0.0.1',
      'https://192.168.0.1',
      'https://169.254.169.254',
      'https://[::1]',
      'https://[fd00::1]',
    ]) {
      await expect(cache.getKey(origin, keyid)).rejects.toMatchObject({ reason: 'malformed' });
    }
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('clear() drops all cached state', async () => {
    const fetchMock = vi.fn(async () => directoryResponse(directoryBody(TEST_PUBLIC_JWK)));
    const cache = makeCache(fetchMock);
    await cache.getKey(ORIGIN, keyid);
    cache.clear();
    await cache.getKey(ORIGIN, keyid);
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });
});

describe('DirectoryError', () => {
  it('carries the failure reason', () => {
    const err = new DirectoryError('malformed', 'boom');
    expect(err.reason).toBe('malformed');
    expect(err.name).toBe('DirectoryError');
  });
});
