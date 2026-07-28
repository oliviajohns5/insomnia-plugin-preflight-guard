'use strict';

const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');

const pluginName = 'insomnia-plugin-preflight-guard';
const plugin = require(pluginName);

function makeContext({ method = 'GET', url = 'https://api.example.com/ping', headers = [], body = '', config = null, outputPath = null } = {}) {
  const alerts = [];
  const store = new Map();
  if (config) store.set('config', JSON.stringify(config));
  return {
    alerts,
    request: {
      getId: () => 'req_real_1',
      getName: () => 'Packaged Harness Request',
      getUrl: () => url,
      setUrl: next => { url = next; },
      getMethod: () => method,
      setMethod: next => { method = next; },
      getHeaders: () => headers,
      getHeader: name => (headers.find(h => h.name.toLowerCase() === name.toLowerCase()) || {}).value || null,
      hasHeader: name => headers.some(h => h.name.toLowerCase() === name.toLowerCase()),
      removeHeader: name => { headers = headers.filter(h => h.name.toLowerCase() !== name.toLowerCase()); },
      setHeader: (name, value) => {
        const existing = headers.find(h => h.name.toLowerCase() === name.toLowerCase());
        if (existing) existing.value = value;
        else headers.push({ name, value });
      },
      addHeader: (name, value) => headers.push({ name, value }),
      getParameter: () => null,
      getParameters: () => [],
      setParameter: () => {},
      hasParameter: () => false,
      addParameter: () => {},
      removeParameter: () => {},
      getBody: () => ({ mimeType: 'application/json', text: body }),
      setBody: next => { body = next && next.text || ''; },
      getEnvironmentVariable: () => null,
      getEnvironment: () => ({}),
      getAuthentication: () => ({}),
      setAuthenticationParameter: () => {},
      setCookie: () => {},
      settingSendCookies: () => {},
      settingStoreCookies: () => {},
      settingEncodeUrl: () => {},
      settingDisableRenderRequestBody: () => {},
      settingFollowRedirects: () => {},
    },
    response: {},
    store: {
      hasItem: async key => store.has(key),
      setItem: async (key, value) => { store.set(key, value); },
      getItem: async key => store.get(key) || null,
      removeItem: async key => { store.delete(key); },
      clear: async () => { store.clear(); },
      all: async () => Array.from(store, ([key, value]) => ({ key, value })),
    },
    app: {
      getInfo: () => ({ version: '13.1.0', platform: process.platform }),
      alert: async (title, message = '') => { alerts.push({ title, message }); },
      prompt: async () => '',
      showSaveDialog: async () => outputPath,
      getPath: name => name === 'userData' ? os.tmpdir() : os.tmpdir(),
      clipboard: { readText: () => '', writeText: () => {}, clear: () => {} },
    },
    data: {
      export: {
        insomnia: async () => JSON.stringify({
          resources: [
            { _type: 'request', name: 'Duplicate', method: 'GET', url: 'https://api.production.example.com/users?access_token=abcdef1234567890' },
            { _type: 'request', name: 'Duplicate', method: 'GET', url: 'https://api.example.com/health' },
            { _type: 'environment', name: 'Env', data: { client_secret: 'abcdefghijklmnopqrstuvwxyz1234567890' } }
          ]
        }),
        har: async () => '{}',
      },
      import: { raw: async () => {}, uri: async () => {} },
    },
    network: { sendRequest: async () => ({ statusCode: 200 }) },
  };
}

async function main() {
  assert(Array.isArray(plugin.requestHooks), 'requestHooks exported');
  assert(Array.isArray(plugin.workspaceActions), 'workspaceActions exported');
  assert(Array.isArray(plugin.requestGroupActions), 'requestGroupActions exported');
  assert(Array.isArray(plugin.requestActions), 'requestActions exported');
  assert(Array.isArray(plugin.templateTags), 'templateTags exported');
  assert.strictEqual(plugin.workspaceActions[0].label, 'Preflight Guard: Export Redacted Audit');
  assert.strictEqual(plugin.requestGroupActions[0].label, 'Preflight Guard: Export Redacted Audit');
  assert.strictEqual(plugin.requestActions[0].label, 'Preflight Guard: Export Redacted Audit');

  const safe = makeContext();
  await plugin.requestHooks[0](safe);
  assert.strictEqual(safe.alerts.length, 0, 'safe request has no alert');

  const prodDelete = makeContext({ method: 'DELETE', url: 'https://api.production.example.com/users/42' });
  await assert.rejects(() => plugin.requestHooks[0](prodDelete), /Preflight Guard blocked request/);
  assert.strictEqual(prodDelete.alerts.length, 1, 'prod DELETE alerts');

  const fakeOpenAi = 'sk-' + 'abcdefghijklmnopqrstuvwxyz123456';
  const querySecret = makeContext({ url: 'https://api.example.com/users?api_key=' + fakeOpenAi });
  await assert.rejects(() => plugin.requestHooks[0](querySecret), /Preflight Guard blocked request/);
  assert(querySecret.alerts[0].message.includes('Auth-like value in query string'), 'query auth detected');

  const mediumHeader = makeContext({ headers: [{ name: 'Authorization', value: 'Bearer short-medium-token' }] });
  await plugin.requestHooks[0](mediumHeader);
  assert.strictEqual(mediumHeader.alerts.length, 1, 'sensitive header warns');

  const warnOnly = makeContext({ method: 'DELETE', url: 'https://prod.example.com/users/42', config: { blockOnHighRisk: false } });
  await plugin.requestHooks[0](warnOnly);
  assert.strictEqual(warnOnly.alerts.length, 1, 'config blockOnHighRisk false warns only');

  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'insomnia-packaged-real-'));
  const auditPath = path.join(tmp, 'audit.md');
  for (const [name, action] of [
    ['workspaceActions', plugin.workspaceActions[0]],
    ['requestGroupActions', plugin.requestGroupActions[0]],
    ['requestActions', plugin.requestActions[0]],
  ]) {
    const aliasAuditPath = path.join(tmp, `${name}.md`);
    const auditCtx = makeContext({ outputPath: aliasAuditPath });
    await action.action(auditCtx, { workspace: {}, requestGroup: [], requests: [] });
    const audit = fs.readFileSync(aliasAuditPath, 'utf8');
    assert(audit.includes('# Insomnia Preflight Guard Audit'), `${name} audit title`);
    assert(audit.includes('query-auth'), `${name} audit query auth`);
    assert(!audit.includes('abcdefghijklmnopqrstuvwxyz1234567890'), `${name} audit redacts secret`);
  }
  fs.rmSync(tmp, { recursive: true, force: true });

  const preview = await plugin.templateTags[0].run({}, 'api_key=' + fakeOpenAi);
  assert(!preview.includes(fakeOpenAi), 'template redacts fake key');

  console.log('PASS: packaged plugin integration harness');
}

main().catch(err => {
  console.error(err && err.stack || err);
  process.exit(1);
});
