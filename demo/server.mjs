/**
 * Demo server: registers the built plugin (dist/index.js) on a real Fastify
 * instance, mirroring the README quickstart. `/` runs in observe mode and
 * returns the verdict; `/agent-api` enforces verification per route.
 * Run `npm run build` first, then `node demo/server.mjs`.
 */
import Fastify from 'fastify';

let webBotAuth;
try {
  // The demo imports the local build; real consumers import the published
  // package instead: `import webBotAuth from 'fastify-web-bot-auth'`.
  ({ default: webBotAuth } = await import('../dist/index.js'));
} catch (err) {
  console.error('fastify-web-bot-auth demo: could not import ../dist/index.js.');
  console.error('Run `npm run build` first, then start the server again.');
  console.error(`Import error: ${err instanceof Error ? err.message : String(err)}`);
  process.exit(1);
}

const app = Fastify({ logger: true });

// Observe mode (default): every request gets a verdict, nothing is blocked.
await app.register(webBotAuth, {
  onFailed(result, request) {
    request.log.info({ reason: result.reason }, 'web-bot-auth: verification failed');
  },
});

app.get('/', async (request) => {
  const { verified, agent, reason } = request.webBotAuth ?? {};
  return { verified, agent, reason };
});

// Enforce on this route only: unverified requests get a 401 JSON body.
app.get('/agent-api', { config: { webBotAuth: { mode: 'enforce' } } }, async () => ({
  private: 'verified agents only',
}));

// Validate PORT: an integer in 1-65535. Exits 1 on an invalid value.
const rawPort = process.env.PORT ?? '3000';
const port = /^\d+$/.test(rawPort) ? Number(rawPort) : Number.NaN;
if (!Number.isInteger(port) || port < 1 || port > 65535) {
  console.error(
    `fastify-web-bot-auth demo: invalid PORT ${JSON.stringify(rawPort)} — expected an integer in 1-65535.`,
  );
  process.exit(1);
}

await app.listen({ port });
