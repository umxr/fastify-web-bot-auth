/**
 * Built-package smoke test: registers the plugin from both build outputs
 * (dist/index.js via ESM import, dist/index.cjs via require) on a real
 * Fastify instance. Run with `npm run test:dist` (builds first).
 */
import { createRequire } from 'node:module';
import Fastify from 'fastify';

async function checkPlugin(label, pluginModule) {
  const plugin = pluginModule.default ?? pluginModule;
  const app = Fastify();
  await app.register(plugin, { mode: 'observe' });
  app.get('/', async (request) => request.webBotAuth);
  await app.ready();
  const response = await app.inject({ method: 'GET', url: '/' });
  await app.close();
  const verdict = response.json();
  if (response.statusCode !== 200 || verdict.reason !== 'unsigned') {
    throw new Error(`${label}: unexpected response ${response.statusCode} ${response.payload}`);
  }
  if (typeof pluginModule.parseSignatureAgent !== 'function') {
    throw new Error(`${label}: parseSignatureAgent export missing`);
  }
  if (typeof pluginModule.optionsSchema !== 'object') {
    throw new Error(`${label}: optionsSchema export missing`);
  }
  console.log(`${label} OK`);
}

const esm = await import('../dist/index.js');
await checkPlugin('ESM (dist/index.js)', esm);

const require = createRequire(import.meta.url);
const cjs = require('../dist/index.cjs');
await checkPlugin('CJS (dist/index.cjs)', cjs);

console.log('dist smoke test passed');
