import Fastify, { type FastifyInstance } from 'fastify';
import { afterEach, beforeAll, describe, expect, it } from 'vitest';
import webBotAuth, {
  optionsSchema,
  type WebBotAuthOptions,
  type WebBotAuthResult,
} from '../src/index.js';
import {
  DIRECTORY_MEDIA_TYPE,
  type SignedRequest,
  TEST_PUBLIC_JWK,
  directoryBody,
  generateEd25519Jwks,
  signRequest,
  thumbprint,
} from './helpers.js';

const AGENT = 'https://web-bot.test';

let keyid: string;
const instances: FastifyInstance[] = [];

beforeAll(async () => {
  keyid = await thumbprint(TEST_PUBLIC_JWK);
});

afterEach(async () => {
  await Promise.all(instances.splice(0).map((app) => app.close()));
});

interface DirectoryServer {
  hits: number;
  setBody: (body: string) => void;
  fetch: typeof fetch;
}

/** In-process Fastify server that serves the key directory, plus a fetch that
 * maps the https agent origin onto it. */
async function startDirectoryServer(initialBody?: string): Promise<DirectoryServer> {
  const app = Fastify();
  instances.push(app);
  const state = { hits: 0, body: initialBody ?? directoryBody(TEST_PUBLIC_JWK) };

  app.get('/.well-known/http-message-signatures-directory', async (_request, reply) => {
    state.hits += 1;
    return reply
      .header('content-type', DIRECTORY_MEDIA_TYPE)
      .header('cache-control', 'max-age=3600')
      .send(state.body);
  });

  await app.listen({ host: '127.0.0.1', port: 0 });
  const address = app.server.address();
  const port = typeof address === 'object' && address !== null ? address.port : 0;

  const mappedFetch: typeof fetch = (input, init) => {
    const url = new URL(String(input));
    if (url.origin !== AGENT) {
      return Promise.reject(new TypeError(`fetch failed: unexpected origin ${url.origin}`));
    }
    return fetch(`http://127.0.0.1:${port}${url.pathname}${url.search}`, init);
  };

  return {
    get hits() {
      return state.hits;
    },
    setBody: (body: string) => {
      state.body = body;
    },
    fetch: mappedFetch,
  };
}

async function buildApp(options: WebBotAuthOptions): Promise<FastifyInstance> {
  const app = Fastify();
  instances.push(app);
  await app.register(webBotAuth, options);

  app.get('/open', async (request) => request.webBotAuth);
  app.get('/enforced', { config: { webBotAuth: { mode: 'enforce' } } }, async (request) => {
    return request.webBotAuth;
  });
  app.get('/relaxed', { config: { webBotAuth: { mode: 'observe' } } }, async (request) => {
    return request.webBotAuth;
  });

  await app.ready();
  return app;
}

/** Sign a request the way fastify.inject will present it. */
function signInjectable(path: string, extra: Parameters<typeof signRequest>[0] = {}) {
  return signRequest({
    url: path,
    protocol: 'http',
    host: 'localhost:80',
    signatureAgent: `"${AGENT}"`,
    ...extra,
  });
}

function inject(app: FastifyInstance, signed: SignedRequest) {
  return app.inject({ method: 'GET', url: signed.url, headers: signed.headers });
}

describe('fastify-web-bot-auth plugin', () => {
  it('observe mode passes unsigned requests through with a verdict', async () => {
    const directory = await startDirectoryServer();
    const app = await buildApp({ fetch: directory.fetch });

    const response = await app.inject({ method: 'GET', url: '/open' });
    expect(response.statusCode).toBe(200);
    const verdict = response.json() as WebBotAuthResult;
    expect(verdict).toMatchObject({ verified: false, reason: 'unsigned' });
    expect(verdict.elapsedMs).toBeGreaterThanOrEqual(0);
    expect(directory.hits).toBe(0);
  });

  it('observe mode passes failing signed requests through with a reason', async () => {
    const directory = await startDirectoryServer();
    const app = await buildApp({ fetch: directory.fetch });

    const signed = await signInjectable('/open');
    signed.headers.host = 'evil.test'; // break the covered @authority
    const response = await app.inject({
      method: 'GET',
      url: signed.url,
      headers: signed.headers,
    });
    expect(response.statusCode).toBe(200);
    expect(response.json()).toMatchObject({ verified: false, reason: 'bad-signature' });
  });

  it('verifies a valid request signed with an sf-string Signature-Agent', async () => {
    const directory = await startDirectoryServer();
    const app = await buildApp({ fetch: directory.fetch });

    const response = await inject(app, await signInjectable('/open'));
    expect(response.statusCode).toBe(200);
    expect(response.json()).toMatchObject({
      verified: true,
      agent: AGENT,
      keyid,
      trusted: true,
    });
  });

  it('verifies a valid request signed with a bare Signature-Agent', async () => {
    const directory = await startDirectoryServer();
    const app = await buildApp({ fetch: directory.fetch });

    const signed = await signInjectable('/open', { signatureAgent: AGENT });
    const response = await inject(app, signed);
    expect(response.statusCode).toBe(200);
    expect(response.json()).toMatchObject({ verified: true, agent: AGENT });
  });

  it('reuses the cached directory across requests', async () => {
    const directory = await startDirectoryServer();
    const app = await buildApp({ fetch: directory.fetch });

    await inject(app, await signInjectable('/open'));
    await inject(app, await signInjectable('/open'));
    expect(directory.hits).toBe(1);
  });

  it('handles key rotation with one forced refresh', async () => {
    const directory = await startDirectoryServer();
    const app = await buildApp({ fetch: directory.fetch });

    expect((await inject(app, await signInjectable('/open'))).json()).toMatchObject({
      verified: true,
    });

    const { privateJwk, publicJwk } = await generateEd25519Jwks();
    directory.setBody(directoryBody(TEST_PUBLIC_JWK, publicJwk));
    const rotated = await signInjectable('/open', { privateJwk });
    expect((await inject(app, rotated)).json()).toMatchObject({
      verified: true,
      keyid: await thumbprint(publicJwk),
    });
    expect(directory.hits).toBe(2);
  });

  it('enforce mode rejects unsigned requests with 401 and a structured body', async () => {
    const directory = await startDirectoryServer();
    const app = await buildApp({ fetch: directory.fetch, mode: 'enforce' });

    const response = await app.inject({ method: 'GET', url: '/open' });
    expect(response.statusCode).toBe(401);
    expect(response.json()).toEqual({
      statusCode: 401,
      error: 'Unauthorized',
      reason: 'unsigned',
    });
  });

  it('enforce mode rejects expired signatures with 401', async () => {
    const directory = await startDirectoryServer();
    const app = await buildApp({ fetch: directory.fetch, mode: 'enforce' });

    const signed = await signInjectable('/open', {
      created: new Date(Date.now() - 600_000),
      expires: new Date(Date.now() - 300_000),
    });
    const response = await inject(app, signed);
    expect(response.statusCode).toBe(401);
    expect(response.json()).toMatchObject({ statusCode: 401, reason: 'expired', agent: AGENT });
  });

  it('enforce mode rejects unknown keys with 401', async () => {
    const directory = await startDirectoryServer();
    const app = await buildApp({ fetch: directory.fetch, mode: 'enforce' });

    const { privateJwk } = await generateEd25519Jwks();
    const response = await inject(app, await signInjectable('/open', { privateJwk }));
    expect(response.statusCode).toBe(401);
    expect(response.json()).toMatchObject({ reason: 'unknown-key' });
  });

  it('enforce mode rejects requests when the directory is unreachable', async () => {
    const app = await buildApp({
      mode: 'enforce',
      fetch: () => Promise.reject(new TypeError('fetch failed')),
    });

    const response = await inject(app, await signInjectable('/open'));
    expect(response.statusCode).toBe(401);
    expect(response.json()).toMatchObject({ reason: 'directory-unreachable' });
  });

  it('per-route enforce overrides a global observe mode', async () => {
    const directory = await startDirectoryServer();
    const app = await buildApp({ fetch: directory.fetch });

    expect((await app.inject({ method: 'GET', url: '/open' })).statusCode).toBe(200);
    expect((await app.inject({ method: 'GET', url: '/enforced' })).statusCode).toBe(401);
  });

  it('per-route observe overrides a global enforce mode', async () => {
    const directory = await startDirectoryServer();
    const app = await buildApp({ fetch: directory.fetch, mode: 'enforce' });

    expect((await app.inject({ method: 'GET', url: '/open' })).statusCode).toBe(401);
    expect((await app.inject({ method: 'GET', url: '/relaxed' })).statusCode).toBe(200);
  });

  it('marks verified-but-untrusted agents and rejects them with 403 in enforce mode', async () => {
    const directory = await startDirectoryServer();
    const app = await buildApp({ fetch: directory.fetch, trust: ['https://other.example'] });

    const observed = await inject(app, await signInjectable('/open'));
    expect(observed.statusCode).toBe(200);
    expect(observed.json()).toMatchObject({ verified: true, trusted: false });

    const enforced = await inject(app, await signInjectable('/enforced'));
    expect(enforced.statusCode).toBe(403);
    expect(enforced.json()).toEqual({
      statusCode: 403,
      error: 'Forbidden',
      reason: 'untrusted',
      agent: AGENT,
    });
  });

  it('accepts trusted agents from an allowlist', async () => {
    const directory = await startDirectoryServer();
    const app = await buildApp({ fetch: directory.fetch, mode: 'enforce', trust: [AGENT] });

    const response = await inject(app, await signInjectable('/open'));
    expect(response.statusCode).toBe(200);
    expect(response.json()).toMatchObject({ verified: true, trusted: true });
  });

  it('supports a trust callback', async () => {
    const directory = await startDirectoryServer();
    const seen: WebBotAuthResult[] = [];
    const app = await buildApp({
      fetch: directory.fetch,
      trust: async (result) => {
        seen.push(result);
        return result.agent === AGENT;
      },
    });

    const response = await inject(app, await signInjectable('/open'));
    expect(response.json()).toMatchObject({ trusted: true });
    expect(seen).toHaveLength(1);
    expect(seen[0]).toMatchObject({ verified: true, agent: AGENT });
  });

  it('treats a throwing trust callback as untrusted', async () => {
    const directory = await startDirectoryServer();
    const app = await buildApp({
      fetch: directory.fetch,
      trust: () => {
        throw new Error('policy exploded');
      },
    });

    const response = await inject(app, await signInjectable('/open'));
    expect(response.statusCode).toBe(200);
    expect(response.json()).toMatchObject({ verified: true, trusted: false });
  });

  it('calls onVerified and onFailed hooks and survives them throwing', async () => {
    const directory = await startDirectoryServer();
    const verified: WebBotAuthResult[] = [];
    const failed: WebBotAuthResult[] = [];
    const app = await buildApp({
      fetch: directory.fetch,
      onVerified: (result) => {
        verified.push(result);
        throw new Error('hook exploded');
      },
      onFailed: (result) => {
        failed.push(result);
        throw new Error('hook exploded');
      },
    });

    expect((await inject(app, await signInjectable('/open'))).statusCode).toBe(200);
    expect((await app.inject({ method: 'GET', url: '/open' })).statusCode).toBe(200);
    expect(verified).toHaveLength(1);
    expect(verified[0]).toMatchObject({ verified: true, agent: AGENT });
    expect(failed).toHaveLength(1);
    expect(failed[0]).toMatchObject({ verified: false, reason: 'unsigned' });
  });

  it('never throws into the request lifecycle on malformed input', async () => {
    const directory = await startDirectoryServer();
    const app = await buildApp({ fetch: directory.fetch });

    const signed = await signInjectable('/open');
    signed.headers['signature-input'] = 'complete garbage ;;;';
    const response = await inject(app, signed);
    expect(response.statusCode).toBe(200);
    expect(response.json()).toMatchObject({ verified: false, reason: 'malformed' });
  });

  it('fires onFailed before an enforce-mode 401 and onVerified before an untrusted 403', async () => {
    const directory = await startDirectoryServer();
    const verified: WebBotAuthResult[] = [];
    const failed: WebBotAuthResult[] = [];
    const app = await buildApp({
      fetch: directory.fetch,
      mode: 'enforce',
      trust: ['https://other.example'],
      onVerified: (result) => {
        verified.push(result);
      },
      onFailed: (result) => {
        failed.push(result);
      },
    });

    const unauthorized = await app.inject({ method: 'GET', url: '/open' });
    expect(unauthorized.statusCode).toBe(401);
    expect(failed).toHaveLength(1);
    expect(failed[0]).toMatchObject({ verified: false, reason: 'unsigned' });

    const forbidden = await inject(app, await signInjectable('/open'));
    expect(forbidden.statusCode).toBe(403);
    expect(verified).toHaveLength(1);
    expect(verified[0]).toMatchObject({ verified: true, trusted: false, agent: AGENT });
  });

  it('wires directoryTimeoutMs through to the cache', async () => {
    const app = await buildApp({
      directoryTimeoutMs: 20,
      fetch: (_input, init) =>
        new Promise<Response>((_resolve, reject) => {
          init?.signal?.addEventListener('abort', () =>
            reject(new DOMException('The operation was aborted', 'AbortError')),
          );
        }),
    });

    const response = await inject(app, await signInjectable('/open'));
    expect(response.json()).toMatchObject({ verified: false, reason: 'directory-unreachable' });
  });

  it('wires directoryMaxBytes through to the cache', async () => {
    const directory = await startDirectoryServer();
    const app = await buildApp({ fetch: directory.fetch, directoryMaxBytes: 10 });

    const response = await inject(app, await signInjectable('/open'));
    expect(response.json()).toMatchObject({ verified: false, reason: 'malformed' });
  });

  it('wires directoryNegativeTtlMs through to the cache', async () => {
    const directory = await startDirectoryServer();
    const makeFlakyFetch = () => {
      let calls = 0;
      const impl: typeof fetch = (input, init) => {
        calls += 1;
        if (calls === 1) return Promise.reject(new TypeError('fetch failed'));
        return directory.fetch(input, init);
      };
      return { impl, calls: () => calls };
    };

    // Long negative TTL: the second request is served from the negative cache.
    const flakyLong = makeFlakyFetch();
    const appLong = await buildApp({ fetch: flakyLong.impl, directoryNegativeTtlMs: 60_000 });
    expect((await inject(appLong, await signInjectable('/open'))).json()).toMatchObject({
      reason: 'directory-unreachable',
    });
    expect((await inject(appLong, await signInjectable('/open'))).json()).toMatchObject({
      reason: 'directory-unreachable',
    });
    expect(flakyLong.calls()).toBe(1);

    // Tiny negative TTL: the origin is retried and the second request verifies.
    const flakyShort = makeFlakyFetch();
    const appShort = await buildApp({ fetch: flakyShort.impl, directoryNegativeTtlMs: 1 });
    expect((await inject(appShort, await signInjectable('/open'))).json()).toMatchObject({
      reason: 'directory-unreachable',
    });
    await new Promise((resolve) => setTimeout(resolve, 10));
    expect((await inject(appShort, await signInjectable('/open'))).json()).toMatchObject({
      verified: true,
    });
  });

  it('throws on double registration', async () => {
    const app = Fastify();
    instances.push(app);
    await app.register(webBotAuth);
    await expect(app.register(webBotAuth).after()).rejects.toThrow(/already registered/);
  });

  it('normalizes trust allowlist entries to origins', async () => {
    const directory = await startDirectoryServer();
    const app = await buildApp({
      fetch: directory.fetch,
      // Uppercase, explicit :443, trailing path — all normalize to the agent origin.
      trust: ['HTTPS://WEB-BOT.TEST:443/some/path'],
    });

    const response = await inject(app, await signInjectable('/open'));
    expect(response.json()).toMatchObject({ verified: true, trusted: true });
  });

  it('rejects invalid trust allowlist entries at registration', async () => {
    for (const entry of ['http://web-bot.test', 'not a url']) {
      const app = Fastify();
      instances.push(app);
      await expect(app.register(webBotAuth, { trust: [entry] }).after()).rejects.toThrow(
        /trust entry/,
      );
    }
  });

  it('rejects invalid options at registration', async () => {
    const cases: [WebBotAuthOptions, RegExp][] = [
      [{ mode: 'enforced' as WebBotAuthOptions['mode'] }, /invalid mode/],
      [{ clockSkew: -1 }, /clockSkew/],
      [{ directoryTimeoutMs: 0 }, /directoryTimeoutMs/],
      [{ directoryMaxBytes: 0 }, /directoryMaxBytes/],
      [{ directoryNegativeTtlMs: -5 }, /directoryNegativeTtlMs/],
    ];
    for (const [options, pattern] of cases) {
      const app = Fastify();
      instances.push(app);
      await expect(app.register(webBotAuth, options).after()).rejects.toThrow(pattern);
    }
  });

  it('rejects invalid route config.webBotAuth at startup', async () => {
    type RouteConfig = { webBotAuth?: { mode?: 'observe' | 'enforce' } };

    const badMode = Fastify();
    instances.push(badMode);
    await badMode.register(webBotAuth);
    expect(() =>
      badMode.get(
        '/typo',
        { config: { webBotAuth: { mode: 'enforced' } } as unknown as RouteConfig },
        async () => ({}),
      ),
    ).toThrow(/invalid config\.webBotAuth\.mode "enforced"/);

    const badShape = Fastify();
    instances.push(badShape);
    await badShape.register(webBotAuth);
    expect(() =>
      badShape.get(
        '/shape',
        { config: { webBotAuth: 'enforce' } as unknown as RouteConfig },
        async () => ({}),
      ),
    ).toThrow(/non-object config\.webBotAuth/);
  });

  it('exports a plain JSON options schema', () => {
    expect(optionsSchema.type).toBe('object');
    expect(optionsSchema.properties.mode.enum).toEqual(['observe', 'enforce']);
    expect(JSON.parse(JSON.stringify(optionsSchema))).toEqual(optionsSchema);
  });
});
