'use strict';

const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const plugin = require('./main');
const t = plugin.__test;
const fakeGithubToken = 'ghp_' + '1234567890'.repeat(4);
const fakeOpenAiKey = 'sk-' + 'abcdefghijklmnopqrstuvwxyz123456';

function mockContext({ method = 'GET', url = 'https://api.example.com/users', headers = [], body = '', storeConfig = null } = {}) {
  const alerts = [];
  return {
    alerts,
    request: {
      getId: () => 'req_1',
      getName: () => 'Example',
      getMethod: () => method,
      getUrl: () => url,
      getHeaders: () => headers,
      getBody: () => ({ mimeType: 'application/json', text: body }),
    },
    app: {
      alert: async (title, message) => alerts.push({ title, message }),
      showSaveDialog: async () => null,
    },
    store: {
      getItem: async key => key === 'config' && storeConfig ? JSON.stringify(storeConfig) : null,
    },
  };
}

async function run() {
  // exports
  assert(Array.isArray(plugin.requestHooks), 'requestHooks must be array');
  assert(Array.isArray(plugin.workspaceActions), 'workspaceActions must be array');
  assert(Array.isArray(plugin.requestGroupActions), 'requestGroupActions must be array');
  assert(Array.isArray(plugin.requestActions), 'requestActions must be array');
  assert(Array.isArray(plugin.templateTags), 'templateTags must be array');
  assert.strictEqual(plugin.workspaceActions[0].label, 'Preflight Guard: Export Redacted Audit');
  assert.strictEqual(plugin.requestGroupActions[0].label, 'Preflight Guard: Export Redacted Audit');
  assert.strictEqual(plugin.requestActions[0].label, 'Preflight Guard: Export Redacted Audit');

  // no finding on harmless request
  let findings = t.analyzeRequest({ method: 'GET', url: 'https://api.example.com/users', headers: [], bodyText: '' });
  assert.strictEqual(findings.length, 0, 'harmless request should be clean');

  // secret in body
  findings = t.analyzeRequest({ method: 'POST', url: 'https://api.example.com/users', headers: [], bodyText: JSON.stringify({ key: fakeGithubToken }) });
  assert(findings.some(f => f.type === 'secret' && f.rule === 'GitHub token'), 'detect GitHub token');

  // OpenAI-like secret in URL
  findings = t.analyzeRequest({ method: 'GET', url: 'https://api.example.com/?token=' + fakeOpenAiKey, headers: [], bodyText: '' });
  assert(findings.some(f => f.rule === 'OpenAI API key'), 'detect OpenAI-style key');
  assert(findings.some(f => f.type === 'query-auth'), 'detect auth-like query');

  // sensitive header medium
  findings = t.analyzeRequest({ method: 'GET', url: 'https://api.example.com', headers: [{ name: 'Authorization', value: 'Bearer abcdefghijklmnop' }], bodyText: '' });
  assert(findings.some(f => f.type === 'sensitive-header'), 'detect sensitive header');

  // destructive prod host high
  findings = t.analyzeRequest({ method: 'DELETE', url: 'https://api.production.example.com/users/42', headers: [], bodyText: '' });
  assert(findings.some(f => f.type === 'prod-mutation'), 'detect prod mutation');

  // risky POST path
  findings = t.analyzeRequest({ method: 'POST', url: 'https://live.example.com/admin/delete-user', headers: [], bodyText: '' });
  assert(findings.some(f => f.type === 'prod-mutation'), 'detect risky POST path to prod');

  // allowed hosts suppress production host mutation
  findings = t.analyzeRequest(
    { method: 'DELETE', url: 'https://api.production.example.com/users/42', headers: [], bodyText: '' },
    { allowedHosts: ['api.production.example.com'] }
  );
  assert(!findings.some(f => f.type === 'prod-mutation'), 'allowed host should not trigger prod mutation');

  // request hook blocks high risk
  const blocked = mockContext({ method: 'DELETE', url: 'https://prod.example.com/users/1' });
  await assert.rejects(() => t.guardRequest(blocked), /Preflight Guard blocked request/);
  assert.strictEqual(blocked.alerts.length, 1, 'blocked request should alert');

  // request hook warns but does not block medium risk
  const medium = mockContext({ headers: [{ name: 'Authorization', value: 'Bearer short-medium-token' }] });
  await t.guardRequest(medium);
  assert.strictEqual(medium.alerts.length, 1, 'medium request should alert');

  // config can disable high-risk block
  const warnOnly = mockContext({ method: 'DELETE', url: 'https://prod.example.com/users/1', storeConfig: { blockOnHighRisk: false } });
  await t.guardRequest(warnOnly);
  assert.strictEqual(warnOnly.alerts.length, 1, 'warn-only high request should alert');

  // redaction
  const redacted = t.redactText('Authorization: Bearer eyJabc.def.ghi\napi_key=' + fakeOpenAiKey);
  assert(!redacted.includes('abcdefghijklmnopqrstuvwxyz123456'), 'redact secret body');
  assert(redacted.includes('…') || redacted.includes('***'), 'redaction marker present');

  // workspace audit
  const workspace = JSON.stringify({
    resources: [
      { name: 'Delete user', url: 'https://api.production.example.com/users?access_token=abcdef1234567890' },
      { name: 'Delete user', url: 'https://api.example.com/foo' },
      { name: 'Secret body', body: 'client_secret=' + 'abcdefghijklmnopqrstuvwxyz1234567890' }
    ]
  });
  findings = t.analyzeWorkspaceExport(workspace);
  assert(findings.some(f => f.type === 'secret'), 'workspace detects secrets');
  assert(findings.some(f => f.type === 'query-auth'), 'workspace detects query auth');
  assert(findings.some(f => f.type === 'duplicate-name'), 'workspace detects duplicate names');

  // audit markdown table
  const md = t.makeAuditMarkdown(findings);
  assert(md.includes('# Insomnia Preflight Guard Audit'), 'audit has title');
  assert(md.includes('| Severity | Type | Location | Preview |'), 'audit has table');

  // fallback path must not use read-only filesystem root when save dialog is unavailable
  const fallbackPath = t.getWritableAuditPath({ app: { getPath: key => key === 'documents' ? '/tmp/preflight-docs' : '' } }, 'audit.md');
  assert.strictEqual(fallbackPath, path.join('/tmp/preflight-docs', 'audit.md'), 'fallback uses writable app path');

  // workspace action writes file fallback
  const cwd = process.cwd();
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'preflight-guard-'));
  process.chdir(tmp);
  try {
    for (const [name, action] of [
      ['workspaceActions', plugin.workspaceActions[0]],
      ['requestGroupActions', plugin.requestGroupActions[0]],
      ['requestActions', plugin.requestActions[0]],
    ]) {
      const out = path.join(tmp, `${name}.md`);
      await action.action({
        data: { export: { insomnia: async () => workspace } },
        app: { alert: async () => {}, showSaveDialog: async () => out },
      });
      assert(fs.existsSync(out), `${name} writes audit`);
      assert(fs.readFileSync(out, 'utf8').includes('Generated:'), `${name} audit file has generated stamp`);
    }

    const fallbackDir = path.join(tmp, 'documents');
    fs.mkdirSync(fallbackDir);
    await plugin.requestActions[0].action({
      data: { export: { insomnia: async () => workspace } },
      app: { alert: async () => {}, showSaveDialog: async () => null, getPath: key => key === 'documents' ? fallbackDir : '' },
    });
    assert(fs.existsSync(path.join(fallbackDir, 'insomnia-preflight-audit.md')), 'null save dialog writes to documents fallback');
  } finally {
    process.chdir(cwd);
    fs.rmSync(tmp, { recursive: true, force: true });
  }

  // template tag
  const preview = await plugin.templateTags[0].run({}, 'token=' + fakeGithubToken);
  assert(!preview.includes('123456789012345678901234567890123456'), 'template tag redacts token');

  console.log('PASS: all tests');
}

run().catch(err => {
  console.error(err && err.stack || err);
  process.exit(1);
});
