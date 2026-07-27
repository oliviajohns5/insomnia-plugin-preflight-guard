'use strict';

const DEFAULT_CONFIG = {
  blockOnHighRisk: true,
  warnOnMediumRisk: true,
  prodHostPatterns: ['prod', 'production', 'live'],
  destructiveMethods: ['DELETE', 'PATCH', 'PUT'],
  riskyPostPathPatterns: ['/delete', '/destroy', '/remove', '/purge', '/admin'],
  allowedHosts: [],
};

const SECRET_RULES = [
  { name: 'OpenAI API key', pattern: /\bsk-[A-Za-z0-9_-]{20,}\b/g },
  { name: 'Anthropic API key', pattern: /\bsk-ant-[A-Za-z0-9_-]{20,}\b/g },
  { name: 'GitHub token', pattern: /\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{20,}\b/g },
  { name: 'Slack token', pattern: /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/g },
  { name: 'AWS access key', pattern: /\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/g },
  { name: 'Stripe secret key', pattern: /\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{20,}\b/g },
  { name: 'JWT bearer token', pattern: /\bBearer\s+eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b/g },
  { name: 'Private key block', pattern: /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g },
  { name: 'Generic API key assignment', pattern: /\b(?:api[_-]?key|access[_-]?token|secret|client[_-]?secret)\s*[:=]\s*["']?[A-Za-z0-9_\-.]{24,}["']?/gi },
];

const AUTH_QUERY_KEYS = new Set([
  'access_token', 'api_key', 'apikey', 'key', 'token', 'auth', 'authorization', 'client_secret', 'secret', 'password', 'signature', 'sig'
]);

function normalizeConfig(input) {
  const cfg = Object.assign({}, DEFAULT_CONFIG, input || {});
  cfg.prodHostPatterns = asArray(cfg.prodHostPatterns, DEFAULT_CONFIG.prodHostPatterns).map(String);
  cfg.destructiveMethods = asArray(cfg.destructiveMethods, DEFAULT_CONFIG.destructiveMethods).map(s => String(s).toUpperCase());
  cfg.riskyPostPathPatterns = asArray(cfg.riskyPostPathPatterns, DEFAULT_CONFIG.riskyPostPathPatterns).map(String);
  cfg.allowedHosts = asArray(cfg.allowedHosts, DEFAULT_CONFIG.allowedHosts).map(String);
  return cfg;
}

function asArray(value, fallback) {
  if (Array.isArray(value)) return value;
  if (typeof value === 'string') return value.split(',').map(s => s.trim()).filter(Boolean);
  return fallback.slice();
}

function safeString(value) {
  if (value == null) return '';
  if (Buffer.isBuffer(value)) return value.toString('utf8');
  if (typeof value === 'string') return value;
  try { return JSON.stringify(value); } catch { return String(value); }
}

function parseUrl(rawUrl) {
  try { return new URL(rawUrl); } catch { return null; }
}

function hostAllowed(hostname, cfg) {
  return cfg.allowedHosts.some(allowed => {
    const value = allowed.toLowerCase();
    const host = String(hostname || '').toLowerCase();
    return value && (host === value || host.endsWith('.' + value));
  });
}

function isProductionLikeHost(hostname, cfg) {
  const host = String(hostname || '').toLowerCase();
  if (!host || hostAllowed(host, cfg)) return false;
  return cfg.prodHostPatterns.some(pattern => {
    const p = String(pattern).toLowerCase();
    return p && (host.includes(p) || new RegExp(`(^|[-.])${escapeRegExp(p)}($|[-.])`).test(host));
  });
}

function isDestructive(method, urlObj, cfg) {
  const m = String(method || '').toUpperCase();
  if (cfg.destructiveMethods.includes(m)) return true;
  if (m === 'POST' && urlObj) {
    const path = urlObj.pathname.toLowerCase();
    return cfg.riskyPostPathPatterns.some(p => path.includes(String(p).toLowerCase()));
  }
  return false;
}

function escapeRegExp(value) {
  return String(value).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function collectRequest(context) {
  const req = context.request;
  const body = req.getBody ? req.getBody() : {};
  return {
    id: call(req, 'getId'),
    name: call(req, 'getName'),
    method: call(req, 'getMethod') || 'GET',
    url: call(req, 'getUrl') || '',
    headers: call(req, 'getHeaders') || [],
    bodyText: body && typeof body.text === 'string' ? body.text : '',
  };
}

function call(obj, method) {
  return obj && typeof obj[method] === 'function' ? obj[method]() : undefined;
}

function findSecretsInText(text, location) {
  const input = safeString(text);
  const findings = [];
  for (const rule of SECRET_RULES) {
    rule.pattern.lastIndex = 0;
    let match;
    while ((match = rule.pattern.exec(input)) !== null) {
      findings.push({
        severity: 'high',
        type: 'secret',
        rule: rule.name,
        location,
        preview: redact(match[0]),
      });
      if (match.index === rule.pattern.lastIndex) rule.pattern.lastIndex += 1;
    }
  }
  return findings;
}

function findAuthInQuery(urlObj) {
  const findings = [];
  if (!urlObj) return findings;
  for (const [key, value] of urlObj.searchParams.entries()) {
    if (AUTH_QUERY_KEYS.has(key.toLowerCase())) {
      findings.push({
        severity: 'high',
        type: 'query-auth',
        rule: 'Auth-like value in query string',
        location: `query.${key}`,
        preview: `${key}=${redact(value)}`,
      });
    }
  }
  return findings;
}

function analyzeRequest(request, config) {
  const cfg = normalizeConfig(config);
  const urlObj = parseUrl(request.url);
  const findings = [];

  findings.push(...findSecretsInText(request.url, 'url'));
  findings.push(...findAuthInQuery(urlObj));

  for (const header of request.headers || []) {
    const name = safeString(header.name);
    const value = safeString(header.value);
    findings.push(...findSecretsInText(`${name}: ${value}`, `header.${name || 'unknown'}`));
    if (/authorization|api[-_]?key|token|secret/i.test(name) && value && value.length > 10) {
      findings.push({
        severity: 'medium',
        type: 'sensitive-header',
        rule: 'Sensitive header present',
        location: `header.${name}`,
        preview: `${name}: ${redact(value)}`,
      });
    }
  }

  findings.push(...findSecretsInText(request.bodyText, 'body'));

  if (urlObj && isProductionLikeHost(urlObj.hostname, cfg) && isDestructive(request.method, urlObj, cfg)) {
    findings.push({
      severity: 'high',
      type: 'prod-mutation',
      rule: 'Destructive request to production-like host',
      location: 'method+host',
      preview: `${String(request.method).toUpperCase()} ${urlObj.hostname}${urlObj.pathname}`,
    });
  }

  return findings;
}

function redact(value) {
  const s = safeString(value);
  if (s.length <= 8) return '***';
  return `${s.slice(0, 4)}…${s.slice(-4)}`;
}

function redactText(text) {
  let out = safeString(text);
  for (const rule of SECRET_RULES) {
    rule.pattern.lastIndex = 0;
    out = out.replace(rule.pattern, match => redact(match));
  }
  out = out.replace(/([?&](?:access_token|api_key|apikey|key|token|auth|authorization|client_secret|secret|password|signature|sig)=)[^&#\s]+/gi, (_, prefix) => `${prefix}${redact('redacted-value')}`);
  out = out.replace(/((?:Authorization|X-Api-Key|X-API-Key|Api-Key|Token|Secret)\s*:\s*)[^\n\r]+/gi, (_, prefix) => `${prefix}${redact('redacted-value')}`);
  return out;
}

function formatFindings(findings) {
  if (!findings.length) return 'No risky request patterns detected.';
  return findings.map((f, index) => `${index + 1}. [${f.severity.toUpperCase()}] ${f.rule} at ${f.location}: ${f.preview}`).join('\n');
}

function riskLevel(findings) {
  if (findings.some(f => f.severity === 'high')) return 'high';
  if (findings.some(f => f.severity === 'medium')) return 'medium';
  return 'low';
}

async function getStoredConfig(context) {
  try {
    const raw = context.store && await context.store.getItem('config');
    return normalizeConfig(raw ? JSON.parse(raw) : {});
  } catch {
    return normalizeConfig({});
  }
}

async function guardRequest(context) {
  const cfg = await getStoredConfig(context);
  const request = collectRequest(context);
  const findings = analyzeRequest(request, cfg);
  const level = riskLevel(findings);
  if (level === 'low') return;

  const title = level === 'high' ? 'Preflight Guard blocked a risky request' : 'Preflight Guard warning';
  const message = `${request.method} ${request.url}\n\n${formatFindings(findings)}\n\nLocal-only: no request data was sent anywhere by this plugin.`;

  if (context.app && typeof context.app.alert === 'function') {
    await context.app.alert(title, message);
  }

  if (level === 'high' && cfg.blockOnHighRisk) {
    throw new Error(`Preflight Guard blocked request:\n${formatFindings(findings)}`);
  }
}

function analyzeWorkspaceExport(raw) {
  const text = safeString(raw);
  let parsed = null;
  try { parsed = JSON.parse(text); } catch { parsed = null; }
  const findings = [];
  findings.push(...findSecretsInText(text, 'workspace-export'));

  const prodUrls = [];
  const authQueryUrls = [];
  const duplicateNames = new Map();

  function walk(value) {
    if (!value || typeof value !== 'object') return;
    if (Array.isArray(value)) return value.forEach(walk);
    if (typeof value.url === 'string') {
      const urlObj = parseUrl(value.url);
      if (urlObj && isProductionLikeHost(urlObj.hostname, normalizeConfig({}))) prodUrls.push(value.url);
      if (urlObj && findAuthInQuery(urlObj).length) authQueryUrls.push(value.url);
    }
    if (typeof value.name === 'string') duplicateNames.set(value.name, (duplicateNames.get(value.name) || 0) + 1);
    Object.keys(value).forEach(k => walk(value[k]));
  }
  walk(parsed);

  for (const url of prodUrls.slice(0, 50)) findings.push({ severity: 'medium', type: 'prod-url', rule: 'Production-like URL in workspace', location: 'workspace.url', preview: redactText(url) });
  for (const url of authQueryUrls.slice(0, 50)) findings.push({ severity: 'high', type: 'query-auth', rule: 'Auth-like query parameter in workspace URL', location: 'workspace.url', preview: redactText(url) });
  for (const [name, count] of duplicateNames.entries()) {
    if (name && count > 1) findings.push({ severity: 'low', type: 'duplicate-name', rule: 'Duplicate request/folder name', location: 'workspace.name', preview: `${name} (${count})` });
  }
  return findings;
}

function makeAuditMarkdown(findings) {
  const now = new Date().toISOString();
  const counts = findings.reduce((acc, f) => { acc[f.severity] = (acc[f.severity] || 0) + 1; return acc; }, {});
  const rows = findings.map(f => `| ${f.severity} | ${f.type} | ${f.location} | ${String(f.preview).replace(/\|/g, '\\|')} |`).join('\n');
  return `# Insomnia Preflight Guard Audit\n\nGenerated: ${now}\n\nLocal-only report. Secrets are redacted.\n\n## Summary\n\n- High: ${counts.high || 0}\n- Medium: ${counts.medium || 0}\n- Low: ${counts.low || 0}\n\n## Findings\n\n| Severity | Type | Location | Preview |\n|---|---|---|---|\n${rows || '| low | none | workspace | No risky patterns detected. |'}\n`;
}

module.exports.requestHooks = [guardRequest];

module.exports.workspaceActions = [{
  label: 'Preflight Guard: Export Redacted Audit',
  icon: 'fa-shield',
  action: async (context) => {
    const exported = await context.data.export.insomnia({ includePrivate: false, format: 'json' });
    const findings = analyzeWorkspaceExport(exported);
    const report = makeAuditMarkdown(findings);
    const fs = require('fs');
    const path = require('path');
    let output = null;
    if (context.app && typeof context.app.showSaveDialog === 'function') {
      output = await context.app.showSaveDialog({ defaultPath: 'insomnia-preflight-audit.md' });
    }
    if (!output) output = path.join(process.cwd(), 'insomnia-preflight-audit.md');
    fs.writeFileSync(output, report, 'utf8');
    if (context.app && typeof context.app.alert === 'function') {
      await context.app.alert('Preflight Guard audit exported', output);
    }
  }
}];

module.exports.templateTags = [{
  name: 'redactedPreview',
  displayName: 'Redacted Preview',
  description: 'Redact common secrets from pasted text.',
  args: [{ displayName: 'Text', type: 'string' }],
  async run(_context, text) {
    return redactText(text);
  }
}];

module.exports.__test = {
  DEFAULT_CONFIG,
  SECRET_RULES,
  analyzeRequest,
  analyzeWorkspaceExport,
  collectRequest,
  findSecretsInText,
  findAuthInQuery,
  formatFindings,
  guardRequest,
  isProductionLikeHost,
  makeAuditMarkdown,
  normalizeConfig,
  redact,
  redactText,
  riskLevel,
};
