import { beforeAll, describe, expect, it, vi } from 'vitest';
import { DirectoryCache } from '../src/directory.js';
import { verifyRequest } from '../src/verify.js';
import {
  TEST_PUBLIC_JWK,
  directoryBody,
  directoryResponse,
  generateEd25519Jwks,
  signRequest,
  thumbprint,
} from './helpers.js';

const AGENT = 'https://signer.test';

let keyid: string;

beforeAll(async () => {
  keyid = await thumbprint(TEST_PUBLIC_JWK);
});

function makeCache(fetchImpl?: typeof fetch) {
  return new DirectoryCache({
    fetch:
      fetchImpl ??
      (vi.fn(async () =>
        directoryResponse(directoryBody(TEST_PUBLIC_JWK)),
      ) as unknown as typeof fetch),
  });
}

const OPTS = { clockSkew: 60 };

describe('verifyRequest', () => {
  it('returns unsigned for requests without signature headers', async () => {
    const result = await verifyRequest(
      { method: 'GET', url: '/', protocol: 'https', headers: { host: 'origin.test' } },
      makeCache(),
      OPTS,
    );
    expect(result).toMatchObject({ verified: false, reason: 'unsigned' });
    expect(result.elapsedMs).toBeGreaterThanOrEqual(0);
  });

  it('verifies a valid request with an sf-string Signature-Agent', async () => {
    const request = await signRequest({ signatureAgent: `"${AGENT}"` });
    const result = await verifyRequest(request, makeCache(), OPTS);
    expect(result).toEqual({
      verified: true,
      agent: AGENT,
      keyid,
      elapsedMs: expect.any(Number),
    });
  });

  it('verifies a valid request with a bare Signature-Agent', async () => {
    const request = await signRequest({ signatureAgent: AGENT });
    const result = await verifyRequest(request, makeCache(), OPTS);
    expect(result).toMatchObject({ verified: true, agent: AGENT, keyid });
  });

  it('flags signatures expired beyond the clock skew', async () => {
    const request = await signRequest({
      signatureAgent: `"${AGENT}"`,
      created: new Date(Date.now() - 600_000),
      expires: new Date(Date.now() - 300_000),
    });
    const result = await verifyRequest(request, makeCache(), OPTS);
    expect(result).toMatchObject({ verified: false, reason: 'expired' });
  });

  it('flags signatures created in the future', async () => {
    const request = await signRequest({
      signatureAgent: `"${AGENT}"`,
      created: new Date(Date.now() + 600_000),
      expires: new Date(Date.now() + 900_000),
    });
    const result = await verifyRequest(request, makeCache(), OPTS);
    expect(result).toMatchObject({ verified: false, reason: 'expired' });
  });

  it('flags tampered signatures as bad-signature', async () => {
    const request = await signRequest({ signatureAgent: `"${AGENT}"` });
    request.headers.signature = tamperSignature(request.headers.signature);
    const result = await verifyRequest(request, makeCache(), OPTS);
    expect(result).toMatchObject({ verified: false, reason: 'bad-signature', keyid });
  });

  it('flags tampered covered components as bad-signature', async () => {
    const request = await signRequest({ signatureAgent: `"${AGENT}"` });
    request.headers.host = 'attacker.test'; // @authority is covered by the signature
    const result = await verifyRequest(request, makeCache(), OPTS);
    expect(result).toMatchObject({ verified: false, reason: 'bad-signature' });
  });

  it('handles key rotation with exactly one forced refresh', async () => {
    const { privateJwk, publicJwk } = await generateEd25519Jwks();
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(directoryResponse(directoryBody(TEST_PUBLIC_JWK)))
      .mockResolvedValue(directoryResponse(directoryBody(TEST_PUBLIC_JWK, publicJwk)));
    const cache = makeCache(fetchMock as unknown as typeof fetch);

    const first = await signRequest({ signatureAgent: `"${AGENT}"` });
    expect((await verifyRequest(first, cache, OPTS)).verified).toBe(true);

    const rotated = await signRequest({ signatureAgent: `"${AGENT}"`, privateJwk });
    const result = await verifyRequest(rotated, cache, OPTS);
    expect(result).toMatchObject({ verified: true, keyid: await thumbprint(publicJwk) });
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it('flags unknown keys after the forced refresh', async () => {
    const { privateJwk } = await generateEd25519Jwks();
    const request = await signRequest({ signatureAgent: `"${AGENT}"`, privateJwk });
    const result = await verifyRequest(request, makeCache(), OPTS);
    expect(result).toMatchObject({ verified: false, reason: 'unknown-key' });
  });

  it('flags unreachable directories', async () => {
    const fetchMock = vi.fn().mockRejectedValue(new TypeError('fetch failed'));
    const request = await signRequest({ signatureAgent: `"${AGENT}"` });
    const result = await verifyRequest(
      request,
      makeCache(fetchMock as unknown as typeof fetch),
      OPTS,
    );
    expect(result).toMatchObject({ verified: false, reason: 'directory-unreachable' });
  });

  it('flags malformed directories', async () => {
    const fetchMock = vi.fn(async () => directoryResponse('not json'));
    const request = await signRequest({ signatureAgent: `"${AGENT}"` });
    const result = await verifyRequest(
      request,
      makeCache(fetchMock as unknown as typeof fetch),
      OPTS,
    );
    expect(result).toMatchObject({ verified: false, reason: 'malformed' });
  });

  it('flags signed requests without a Signature-Agent header as malformed', async () => {
    const request = await signRequest({});
    const result = await verifyRequest(request, makeCache(), OPTS);
    expect(result).toMatchObject({ verified: false, reason: 'malformed' });
  });

  it('flags non-https Signature-Agent values as malformed', async () => {
    const request = await signRequest({ signatureAgent: '"http://signer.test"' });
    const result = await verifyRequest(request, makeCache(), OPTS);
    expect(result).toMatchObject({ verified: false, reason: 'malformed' });
  });

  it('flags malformed Signature-Input syntax', async () => {
    const request = await signRequest({ signatureAgent: `"${AGENT}"` });
    request.headers['signature-input'] = 'complete garbage ;;;';
    const result = await verifyRequest(request, makeCache(), OPTS);
    expect(result).toMatchObject({ verified: false, reason: 'malformed' });
  });

  it('flags a wrong signature tag as malformed', async () => {
    const request = await signRequest({ signatureAgent: `"${AGENT}"` });
    request.headers['signature-input'] = request.headers['signature-input'].replace(
      'tag="web-bot-auth"',
      'tag="other-tag"',
    );
    const result = await verifyRequest(request, makeCache(), OPTS);
    expect(result).toMatchObject({ verified: false, reason: 'malformed' });
  });

  it('flags an invalid nonce as malformed before touching crypto', async () => {
    const request = await signRequest({ signatureAgent: `"${AGENT}"` });
    request.headers['signature-input'] = request.headers['signature-input'].replace(
      /nonce="[^"]+"/,
      'nonce="too-short"',
    );
    const result = await verifyRequest(request, makeCache(), OPTS);
    expect(result).toMatchObject({ verified: false, reason: 'malformed' });
  });

  it('pins the upstream strict window: clockSkew cannot widen it', async () => {
    // The signature expired 2 s ago; even a huge clockSkew cannot save it,
    // because web-bot-auth enforces created <= now <= expires strictly before
    // the plugin's skew-tolerant checks run. Documented behavior — this test
    // pins it so an upstream change is noticed.
    const request = await signRequest({
      signatureAgent: `"${AGENT}"`,
      created: new Date(Date.now() - 60_000),
      expires: new Date(Date.now() - 2_000),
    });
    const result = await verifyRequest(request, makeCache(), { clockSkew: 3600 });
    expect(result).toMatchObject({ verified: false, reason: 'expired' });
  });

  it('flags a Signature-Input without created/expires as malformed', async () => {
    const request = await signRequest({ signatureAgent: `"${AGENT}"` });
    request.headers['signature-input'] = request.headers['signature-input']
      .replace(/;created=\d+/, '')
      .replace(/;expires=\d+/, '');
    const warn = vi.fn();
    const result = await verifyRequest(request, makeCache(), { ...OPTS, logger: warnLogger(warn) });
    expect(result).toMatchObject({ verified: false, reason: 'malformed' });
    // Known upstream failure shape: no operator warning.
    expect(warn).not.toHaveBeenCalled();
  });

  it('never throws when the cache misbehaves, and warns operators', async () => {
    const cache = makeCache();
    const failure = new Error('internal blowup');
    vi.spyOn(cache, 'getKey').mockRejectedValue(failure);
    const request = await signRequest({ signatureAgent: `"${AGENT}"` });
    const warn = vi.fn();
    const result = await verifyRequest(request, cache, { ...OPTS, logger: warnLogger(warn) });
    expect(result).toMatchObject({ verified: false, reason: 'malformed' });
    expect(warn).toHaveBeenCalledWith(
      { err: failure },
      expect.stringContaining('unexpected internal error'),
    );
  });

  it('does not warn for expected failures (expired, bad signature, unknown key)', async () => {
    const warn = vi.fn();
    const logger = warnLogger(warn);
    const expired = await signRequest({
      signatureAgent: `"${AGENT}"`,
      created: new Date(Date.now() - 600_000),
      expires: new Date(Date.now() - 300_000),
    });
    await verifyRequest(expired, makeCache(), { ...OPTS, logger });

    const tampered = await signRequest({ signatureAgent: `"${AGENT}"` });
    tampered.headers.host = 'attacker.test';
    await verifyRequest(tampered, makeCache(), { ...OPTS, logger });
    expect(warn).not.toHaveBeenCalled();
  });
});

function warnLogger(warn: (obj: unknown, msg?: string) => void) {
  return { debug: () => {}, warn };
}

function tamperSignature(header: string): string {
  // header looks like sig1=:BASE64:; flip one character of the base64 payload.
  const match = /^(.*=:)([A-Za-z0-9+/=]+)(:)$/.exec(header);
  if (!match) throw new Error(`unexpected Signature header shape: ${header}`);
  const b64 = match[2] as string;
  const i = 10;
  const replacement = b64[i] === 'A' ? 'B' : 'A';
  return `${match[1]}${b64.slice(0, i)}${replacement}${b64.slice(i + 1)}${match[3]}`;
}
