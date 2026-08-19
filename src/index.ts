import type { FastifyPluginAsync, FastifyReply, FastifyRequest } from 'fastify';
import fp from 'fastify-plugin';
import { DirectoryCache } from './directory.js';
import type {
  ResolvedWebBotAuthOptions,
  WebBotAuthMode,
  WebBotAuthOptions,
  WebBotAuthResult,
} from './types.js';
import { verifyRequest } from './verify.js';

const VALID_MODES: readonly WebBotAuthMode[] = ['observe', 'enforce'];

function validateOptions(options: WebBotAuthOptions): void {
  if (options.mode !== undefined && !VALID_MODES.includes(options.mode)) {
    throw new Error(
      `fastify-web-bot-auth: invalid mode "${options.mode}" — expected 'observe' or 'enforce'`,
    );
  }
  if (options.clockSkew !== undefined && !(options.clockSkew >= 0)) {
    throw new Error(
      `fastify-web-bot-auth: clockSkew must be a number >= 0, got ${options.clockSkew}`,
    );
  }
  if (options.directoryTimeoutMs !== undefined && !(options.directoryTimeoutMs > 0)) {
    throw new Error(
      `fastify-web-bot-auth: directoryTimeoutMs must be a positive number, got ${options.directoryTimeoutMs}`,
    );
  }
  if (options.directoryMaxBytes !== undefined && !(options.directoryMaxBytes > 0)) {
    throw new Error(
      `fastify-web-bot-auth: directoryMaxBytes must be a positive number, got ${options.directoryMaxBytes}`,
    );
  }
  if (options.directoryNegativeTtlMs !== undefined && !(options.directoryNegativeTtlMs >= 0)) {
    throw new Error(
      `fastify-web-bot-auth: directoryNegativeTtlMs must be a number >= 0, got ${options.directoryNegativeTtlMs}`,
    );
  }
}

/**
 * Normalize a trust allowlist so entries like `https://Example.com/`,
 * `https://example.com:443`, or `https://example.com/path` match the
 * normalized `result.agent` origin. Throws on invalid or non-https entries.
 */
function normalizeTrustList(entries: string[]): Set<string> {
  const normalized = new Set<string>();
  for (const entry of entries) {
    let url: URL;
    try {
      url = new URL(entry);
    } catch {
      throw new Error(`fastify-web-bot-auth: trust entry is not a valid URL: "${entry}"`);
    }
    if (url.protocol !== 'https:') {
      throw new Error(`fastify-web-bot-auth: trust entry must be an https origin: "${entry}"`);
    }
    normalized.add(url.origin);
  }
  return normalized;
}

const webBotAuthPlugin: FastifyPluginAsync<WebBotAuthOptions> = async (fastify, options) => {
  validateOptions(options);

  const resolved: ResolvedWebBotAuthOptions = {
    mode: options.mode ?? 'observe',
    trust: options.trust,
    clockSkew: options.clockSkew ?? 60,
    directoryTimeoutMs: options.directoryTimeoutMs ?? 5_000,
    directoryMaxBytes: options.directoryMaxBytes ?? 64 * 1024,
    directoryNegativeTtlMs: options.directoryNegativeTtlMs ?? 30_000,
    fetch: options.fetch ?? globalThis.fetch,
    onVerified: options.onVerified,
    onFailed: options.onFailed,
    logger: fastify.log,
  };

  const trustAllowlist = Array.isArray(resolved.trust)
    ? normalizeTrustList(resolved.trust)
    : undefined;

  const cache = new DirectoryCache({
    fetch: resolved.fetch,
    timeoutMs: resolved.directoryTimeoutMs,
    maxBytes: resolved.directoryMaxBytes,
    negativeTtlMs: resolved.directoryNegativeTtlMs,
    logger: fastify.log,
  });

  if (fastify.hasRequestDecorator('webBotAuth')) {
    throw new Error(
      'fastify-web-bot-auth is already registered on this Fastify instance — register it once',
    );
  }
  fastify.decorateRequest('webBotAuth', null);

  // Fail fast at startup on route-config typos such as `mode: 'enforced'`,
  // which would otherwise silently leave the route unenforced.
  fastify.addHook('onRoute', (route) => {
    const config = (route.config as { webBotAuth?: unknown } | undefined)?.webBotAuth;
    if (config === undefined) return;
    if (config === null || typeof config !== 'object') {
      throw new Error(
        `fastify-web-bot-auth: route ${route.method} ${route.url} has a non-object config.webBotAuth`,
      );
    }
    const mode = (config as { mode?: unknown }).mode;
    if (mode !== undefined && !VALID_MODES.includes(mode as WebBotAuthMode)) {
      throw new Error(
        `fastify-web-bot-auth: route ${route.method} ${route.url} has invalid config.webBotAuth.mode "${mode}" — expected 'observe' or 'enforce'`,
      );
    }
  });

  fastify.addHook('onRequest', async (request: FastifyRequest, reply: FastifyReply) => {
    // verifyRequest never throws into the request lifecycle.
    const result = await verifyRequest(
      {
        method: request.method,
        url: request.url,
        protocol: request.protocol,
        headers: request.headers,
      },
      cache,
      { clockSkew: resolved.clockSkew, logger: fastify.log },
    );

    if (result.verified) {
      result.trusted = await evaluateTrust(resolved, result, request);
    }
    request.webBotAuth = result;

    await runHook(result.verified ? resolved.onVerified : resolved.onFailed, result, request);

    const mode = resolveMode(request, resolved);
    if (mode !== 'enforce') return;

    if (!result.verified) {
      await reply.code(401).send({
        statusCode: 401,
        error: 'Unauthorized',
        reason: result.reason,
        ...(result.agent !== undefined ? { agent: result.agent } : {}),
      });
      return;
    }
    if (result.trusted === false) {
      await reply.code(403).send({
        statusCode: 403,
        error: 'Forbidden',
        reason: 'untrusted',
        agent: result.agent,
      });
    }
  });

  function resolveMode(request: FastifyRequest, opts: ResolvedWebBotAuthOptions): WebBotAuthMode {
    return request.routeOptions?.config?.webBotAuth?.mode ?? opts.mode;
  }

  async function evaluateTrust(
    opts: ResolvedWebBotAuthOptions,
    result: WebBotAuthResult,
    request: FastifyRequest,
  ): Promise<boolean> {
    const trust = opts.trust;
    if (trust === undefined) return true;
    try {
      if (trustAllowlist !== undefined) {
        return result.agent !== undefined && trustAllowlist.has(result.agent);
      }
      if (Array.isArray(trust)) {
        // Unreachable in practice (arrays are pre-normalized), kept as a guard.
        return result.agent !== undefined && trust.includes(result.agent);
      }
      // Only a strict `true` counts as trusted; truthy values do not.
      return (await trust(result, request)) === true;
    } catch (err) {
      fastify.log.debug(
        `web-bot-auth: trust callback threw (${(err as Error).message}); treating agent as untrusted`,
      );
      return false;
    }
  }

  async function runHook(
    hook: ((result: WebBotAuthResult, request: FastifyRequest) => void | Promise<void>) | undefined,
    result: WebBotAuthResult,
    request: FastifyRequest,
  ): Promise<void> {
    if (!hook) return;
    try {
      await hook(result, request);
    } catch (err) {
      fastify.log.debug(`web-bot-auth: lifecycle hook threw: ${(err as Error).message}`);
    }
  }
};

/**
 * Fastify plugin that verifies Web Bot Auth signatures (RFC 9421 + IETF
 * web-bot-auth drafts) on inbound requests and decorates
 * `request.webBotAuth` with the verdict.
 */
const plugin = fp(webBotAuthPlugin, {
  fastify: '5.x',
  name: 'fastify-web-bot-auth',
});

export default plugin;
export { plugin as fastifyWebBotAuth };
export { DirectoryCache, DirectoryError } from './directory.js';
export { parseSignatureAgent } from './signature-agent.js';
export { verifyRequest } from './verify.js';
export type { VerifiableRequest, VerifyRequestOptions } from './verify.js';
export { optionsSchema } from './types.js';
export type {
  WebBotAuthMode,
  WebBotAuthOptions,
  WebBotAuthReason,
  WebBotAuthResult,
  WebBotAuthRouteConfig,
  WebBotAuthTrust,
} from './types.js';
