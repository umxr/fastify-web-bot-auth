import type { webcrypto } from 'node:crypto';
import { jwkThumbprint } from 'jsonwebkey-thumbprint';
import { helpers, signatureHeaders } from 'web-bot-auth';
import { Ed25519Signer } from 'web-bot-auth/crypto';

type JsonWebKey = webcrypto.JsonWebKey;
type CryptoKeyPair = webcrypto.CryptoKeyPair;

export const DIRECTORY_MEDIA_TYPE = 'application/http-message-signatures-directory+json';

/** RFC 9421 Appendix B.1.4 Ed25519 test key (`test-key-ed25519`). */
export const TEST_PRIVATE_JWK: JsonWebKey = {
  kty: 'OKP',
  crv: 'Ed25519',
  x: 'JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs',
  d: 'n4Ni-HpISpVObnQMW0wOhCKROaIKqKtW_2ZYb2p9KcU',
};

export const TEST_PUBLIC_JWK: JsonWebKey = {
  kty: 'OKP',
  crv: 'Ed25519',
  x: TEST_PRIVATE_JWK.x,
};

export function thumbprint(jwk: JsonWebKey): Promise<string> {
  return jwkThumbprint(
    { kty: jwk.kty, crv: jwk.crv, x: jwk.x },
    helpers.WEBCRYPTO_SHA256,
    helpers.BASE64URL_DECODE,
  );
}

export async function generateEd25519Jwks(): Promise<{
  privateJwk: JsonWebKey;
  publicJwk: JsonWebKey;
}> {
  const pair = (await crypto.subtle.generateKey({ name: 'Ed25519' }, true, [
    'sign',
    'verify',
  ])) as unknown as CryptoKeyPair;
  const privateJwk = (await crypto.subtle.exportKey('jwk', pair.privateKey)) as JsonWebKey;
  const publicJwk = (await crypto.subtle.exportKey('jwk', pair.publicKey)) as JsonWebKey;
  return { privateJwk, publicJwk };
}

export interface SignRequestInput {
  method?: string;
  url?: string;
  protocol?: string;
  host?: string;
  /** Raw Signature-Agent header value (quoted or bare). Omit to sign without one. */
  signatureAgent?: string;
  privateJwk?: JsonWebKey;
  created?: Date;
  expires?: Date;
  nonce?: string;
}

export interface SignedRequest {
  method: string;
  url: string;
  protocol: string;
  headers: Record<string, string> & {
    host: string;
    signature: string;
    'signature-input': string;
  };
}

/** Sign a request locally with web-bot-auth's signing helpers. */
export async function signRequest(input: SignRequestInput = {}): Promise<SignedRequest> {
  const method = input.method ?? 'GET';
  const url = input.url ?? '/';
  const protocol = input.protocol ?? 'https';
  const host = input.host ?? 'origin.test';
  const created = input.created ?? new Date();
  const expires = input.expires ?? new Date(created.getTime() + 300_000);

  const headers: Record<string, string> = { host };
  if (input.signatureAgent !== undefined) {
    headers['signature-agent'] = input.signatureAgent;
  }

  const signer = await Ed25519Signer.fromJWK(input.privateJwk ?? TEST_PRIVATE_JWK);
  const signed = await signatureHeaders({ method, url, protocol, headers }, signer, {
    created,
    expires,
    ...(input.nonce !== undefined ? { nonce: input.nonce } : {}),
  });

  return {
    method,
    url,
    protocol,
    headers: {
      ...headers,
      host,
      signature: signed.Signature,
      'signature-input': signed['Signature-Input'],
    },
  };
}

export function directoryBody(...publicJwks: JsonWebKey[]): string {
  return JSON.stringify({ keys: publicJwks, purpose: 'rag' });
}

export function directoryResponse(
  body: string,
  init: { status?: number; cacheControl?: string; contentType?: string | null } = {},
): Response {
  const headers = new Headers();
  const contentType = init.contentType === undefined ? DIRECTORY_MEDIA_TYPE : init.contentType;
  if (contentType !== null) headers.set('content-type', contentType);
  if (init.cacheControl) headers.set('cache-control', init.cacheControl);
  return new Response(body, { status: init.status ?? 200, headers });
}
