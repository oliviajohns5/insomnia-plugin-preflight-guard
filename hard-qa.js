'use strict';

const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const childProcess = require('child_process');
const plugin = require('./main');
const t = plugin.__test;
const fakeGithubToken = 'ghp_' + '1234567890'.repeat(4);
const fakeOpenAiKey = 'sk-' + 'abcdefghijklmnopqrstuvwxyz123456';

function ctx({ method = 'GET', url = 'https://api.example.com/users', headers = [], body = '', storeConfig = null, configPath = null } = {}) {
  const alerts = [];
  return {
    alerts,
    __configPath: configPath,
    request: {
      getId: () => 'req_hard',
      getName: () => 'Hard QA',
      getMethod: () => method,
      getUrl: () => url,
      getHeaders: () => headers,
      getBody: () => ({ text: body }),
    },
    app: { alert: async (title, message) => alerts.push({ title, message }), showSaveDialog: async () => null },
    store: { getItem: async key => key === 'config' && storeConfig ? JSON.stringify(storeConfig) : null },
  };
}

async function run() {
  const results = [];
  async function check(name, fn) {
    await fn();
    results.push(name);
    console.log('PASS | ' + name);
  }

  await check('exports all public plugin surfaces', () => {
    assert(Array.isArray(plugin.requestHooks));
    assert(Array.isArray(plugin.workspaceActions));
    assert(Array.isArray(plugin.requestGroupActions));
    assert(Array.isArray(plugin.requestActions));
    assert(Array.isArray(plugin.templateTags));
  });

  await check('clean request has no findings', () => {
    assert.strictEqual(t.analyzeRequest({ method: 'GET', url: 'https://api.example.com', headers: [], bodyText: '' }).length, 0);
  });

  await check('secret detection covers URL, header, and body', () => {
    const findings = [
      ...t.analyzeRequest({ method: 'GET', url: 'https://api.example.com?token=' + fakeOpenAiKey, headers: [], bodyText: '' }),
      ...t.analyzeRequest({ method: 'GET', url: 'https://api.example.com', headers: [{ name: 'X-Api-Key', value: fakeGithubToken }], bodyText: '' }),
      ...t.analyzeRequest({ method: 'POST', url: 'https://api.example.com', headers: [], bodyText: 'secret=' + fakeGithubToken }),
    ];
    assert(findings.some(f => f.type === 'query-auth'));
    assert(findings.some(f => f.type === 'secret'));
    assert(findings.some(f => f.type === 'sensitive-header'));
  });

  await check('default config blocks destructive production request', async () => {
    const c = ctx({ method: 'DELETE', url: 'https://api.production.example.com/users/1' });
    await assert.rejects(() => t.guardRequest(c), /Preflight Guard blocked request/);
    assert.strictEqual(c.alerts.length, 1);
  });

  await check('local file config allowlists host', async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'preflight-hard-cfg-'));
    try {
      const cfg = path.join(dir, '.insomnia-preflight-guard.json');
      fs.writeFileSync(cfg, JSON.stringify({ allowedHosts: ['api.production.example.com'] }), 'utf8');
      const c = ctx({ method: 'DELETE', url: 'https://api.production.example.com/users/1', configPath: cfg });
      await t.guardRequest(c);
      assert.strictEqual(c.alerts.length, 0);
    } finally { fs.rmSync(dir, { recursive: true, force: true }); }
  });

  await check('env config path is respected', async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'preflight-hard-env-'));
    const old = process.env.INSOMNIA_PREFLIGHT_GUARD_CONFIG;
    try {
      const cfg = path.join(dir, 'guard.json');
      fs.writeFileSync(cfg, JSON.stringify({ blockOnHighRisk: false }), 'utf8');
      process.env.INSOMNIA_PREFLIGHT_GUARD_CONFIG = cfg;
      const c = ctx({ method: 'DELETE', url: 'https://prod.example.com/users/1' });
      await t.guardRequest(c);
      assert.strictEqual(c.alerts.length, 1);
    } finally {
      if (old == null) delete process.env.INSOMNIA_PREFLIGHT_GUARD_CONFIG; else process.env.INSOMNIA_PREFLIGHT_GUARD_CONFIG = old;
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  await check('store config overrides local file config', async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'preflight-hard-override-'));
    try {
      const cfg = path.join(dir, 'guard.json');
      fs.writeFileSync(cfg, JSON.stringify({ allowedHosts: ['prod.example.com'] }), 'utf8');
      const c = ctx({ method: 'DELETE', url: 'https://prod.example.com/users/1', configPath: cfg, storeConfig: { allowedHosts: [] } });
      await assert.rejects(() => t.guardRequest(c), /Preflight Guard blocked request/);
    } finally { fs.rmSync(dir, { recursive: true, force: true }); }
  });

  await check('malformed local config safely falls back to defaults', async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'preflight-hard-bad-'));
    try {
      const cfg = path.join(dir, 'bad.json');
      fs.writeFileSync(cfg, '{bad json', 'utf8');
      const c = ctx({ method: 'DELETE', url: 'https://prod.example.com/users/1', configPath: cfg });
      await assert.rejects(() => t.guardRequest(c), /Preflight Guard blocked request/);
    } finally { fs.rmSync(dir, { recursive: true, force: true }); }
  });

  await check('workspace audit redacts risky content', () => {
    const workspace = JSON.stringify({ resources: [{ name: 'A', url: 'https://prod.example.com/a?access_token=' + fakeOpenAiKey }, { name: 'A', body: 'secret=' + fakeGithubToken }] });
    const findings = t.analyzeWorkspaceExport(workspace);
    const md = t.makeAuditMarkdown(findings);
    assert(findings.some(f => f.type === 'secret'));
    assert(findings.some(f => f.type === 'query-auth'));
    assert(findings.some(f => f.type === 'duplicate-name'));
    assert(!md.includes('abcdefghijklmnopqrstuvwxyz123456'));
  });

  await check('all action aliases write report', async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'preflight-hard-action-'));
    try {
      const workspace = JSON.stringify({ resources: [{ name: 'A', url: 'https://prod.example.com/a?access_token=abc1234567890' }] });
      for (const [name, action] of [['workspace', plugin.workspaceActions[0]], ['group', plugin.requestGroupActions[0]], ['request', plugin.requestActions[0]]]) {
        const out = path.join(dir, name + '.md');
        await action.action({ data: { export: { insomnia: async () => workspace } }, app: { showSaveDialog: async () => out, alert: async () => {} } });
        assert(fs.existsSync(out));
        assert(fs.readFileSync(out, 'utf8').includes('Insomnia Preflight Guard Audit'));
      }
    } finally { fs.rmSync(dir, { recursive: true, force: true }); }
  });

  await check('template tag redacts generated token', async () => {
    const out = await plugin.templateTags[0].run({}, 'Authorization: ' + fakeGithubToken);
    assert(!out.includes('123456789012345678901234567890123456'));
  });

  await check('packaged install harness passes', () => {
    childProcess.execFileSync('node', ['qa-packaged.js'], { cwd: process.cwd(), stdio: 'pipe' });
  });

  console.log('HARD_QA_PASS ' + results.length + ' checks');
}

run().catch(err => { console.error(err.stack || err); process.exit(1); });
