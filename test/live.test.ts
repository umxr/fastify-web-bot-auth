import { describe, expect, it } from 'vitest';
import { DirectoryCache } from '../src/directory.js';
import { verifyRequest } from '../src/verify.js';
import { TEST_PUBLIC_JWK, signRequest, thumbprint } from './helpers.js';

const LIVE_ORIGIN = 'https://http-message-signatures-example.research.cloudflare.com';

/**
 * Network-gated integration test against Cloudflare Research's live Web Bot
 * Auth example, which publishes the RFC 9421 Appendix B.1.4 Ed25519 test key
 * in its signature directory. Run with `LIVE_TESTS=1 npm test`.
 */
describe.skipIf(process.env.LIVE_TESTS !== '1')('live: Cloudflare research endpoint', () => {
  it('fetches the live directory and finds the RFC 9421 test key', async () => {
    const cache = new DirectoryCache();
    const keyid = await thumbprint(TEST_PUBLIC_JWK);
    const jwk = await cache.getKey(LIVE_ORIGIN, keyid);
    expect(jwk).toEqual({ kty: 'OKP', crv: 'Ed25519', x: TEST_PUBLIC_JWK.x });
  });

  it('verifies a locally signed request against the live directory', async () => {
    const cache = new DirectoryCache();
    const request = await signRequest({ signatureAgent: `"${LIVE_ORIGIN}"` });
    const result = await verifyRequest(request, cache, { clockSkew: 60 });
    expect(result).toMatchObject({ verified: true, agent: LIVE_ORIGIN });
  });
});
