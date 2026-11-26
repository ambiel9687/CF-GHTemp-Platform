// 可调整配置。真实密钥请在 Cloudflare Worker Secrets 中设置。
export const CONFIG = Object.freeze({
  DEFAULT_ACCOUNT_HOURS: 2,
  EXTEND_HOURS: 2,
  ADMIN_SESSION_DAYS: 7,
  USER_SESSION_DAYS: 7,
  TIME_ZONE: 'Asia/Shanghai',
  MAX_IMPORT_ACCOUNTS: 100,
  MAX_IMPORT_BYTES: 256 * 1024,
  MAX_REQUEST_BYTES: 512 * 1024,
  MAX_ACCOUNT_HOURS: 24 * 365,
  LOGIN_ATTEMPTS: 10,
  LOGIN_WINDOW_SECONDS: 15 * 60,
});

// 在 Worker 设置 → 变量和机密中配置这三个 Secrets。
const readSecrets = (env) => ({ admin: env.ADMIN_KEY, user: env.USER_KEY, encryption: env.ENCRYPTION_KEY });

const encoder = new TextEncoder();
const decoder = new TextDecoder();
const SESSION_COOKIE = 'gh_access_session';
const TOTP_PERIOD = 30;

class HttpError extends Error {
  constructor(status, message) { super(message); this.status = status; }
}

function base64(bytes) {
  return btoa(String.fromCharCode(...bytes));
}

function unbase64(value) {
  return Uint8Array.from(atob(value), (char) => char.charCodeAt(0));
}

function base64url(bytes) {
  return base64(bytes).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function unbase64url(value) {
  if (!/^[A-Za-z0-9_-]+$/.test(value)) throw new Error('Invalid encoding');
  return unbase64(value.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - value.length % 4) % 4));
}

async function hmacKey(secret, algorithm = 'SHA-256') {
  return crypto.subtle.importKey('raw', typeof secret === 'string' ? encoder.encode(secret) : secret,
    { name: 'HMAC', hash: algorithm }, false, ['sign', 'verify']);
}

async function sameSecret(provided, expected) {
  const key = await hmacKey(expected);
  const signature = await crypto.subtle.sign('HMAC', key, encoder.encode('login-key:' + provided));
  return crypto.subtle.verify('HMAC', key, signature, encoder.encode('login-key:' + expected));
}

function validateEnvironment(env) {
  const secrets = readSecrets(env);
  try {
    if (!env.DB || typeof secrets.admin !== 'string' || typeof secrets.user !== 'string'
      || secrets.admin.length < 32 || secrets.user.length < 32 || secrets.admin === secrets.user
      || typeof secrets.encryption !== 'string' || unbase64(secrets.encryption).length !== 32) throw new Error();
  } catch {
    throw new HttpError(503, '服务配置不完整，请检查 D1 绑定和三个 Secrets。');
  }
  return secrets;
}

async function encryptionKey(secret) {
  return crypto.subtle.importKey('raw', unbase64(secret), 'AES-GCM', false, ['encrypt', 'decrypt']);
}

export async function encryptValue(value, secret, context) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encrypted = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv, additionalData: encoder.encode(context) },
    await encryptionKey(secret), encoder.encode(value));
  return base64(iv) + '.' + base64(new Uint8Array(encrypted));
}

export async function decryptValue(value, secret, context) {
  const [iv, encrypted] = value.split('.');
  return decoder.decode(await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: unbase64(iv), additionalData: encoder.encode(context) },
    await encryptionKey(secret), unbase64(encrypted)));
}

export function decodeTotpSecret(value) {
  const normalized = value.toUpperCase().replace(/[\s-]/g, '');
  if (!/^[A-Z2-7]+={0,6}$/.test(normalized)) throw new Error('Invalid TOTP secret');
  const raw = normalized.replace(/=+$/, '');
  if (![0, 2, 4, 5, 7].includes(raw.length % 8)) throw new Error('Invalid Base32 length');
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  const bytes = [];
  let buffer = 0;
  let bits = 0;
  for (const character of raw) {
    buffer = (buffer << 5) | alphabet.indexOf(character);
    bits += 5;
    if (bits >= 8) { bits -= 8; bytes.push((buffer >>> bits) & 255); }
    buffer &= (1 << bits) - 1;
  }
  if (buffer !== 0 || bytes.length < 10 || bytes.length > 128) throw new Error('Invalid TOTP secret');
  if (normalized.includes('=') && normalized.length % 8 !== 0) throw new Error('Invalid Base32 padding');
  return { normalized: raw, bytes: Uint8Array.from(bytes) };
}

export async function generateTotp(secret, now = Date.now(), digits = 6) {
  const { bytes } = decodeTotpSecret(secret);
  const counter = new ArrayBuffer(8);
  new DataView(counter).setBigUint64(0, BigInt(Math.floor(now / 1000 / TOTP_PERIOD)));
  const digest = new Uint8Array(await crypto.subtle.sign('HMAC', await hmacKey(bytes, 'SHA-1'), counter));
  const offset = digest[digest.length - 1] & 15;
  const binary = ((digest[offset] & 127) << 24) | (digest[offset + 1] << 16)
    | (digest[offset + 2] << 8) | digest[offset + 3];
  return String(binary % (10 ** digits)).padStart(digits, '0');
}

export function parseImport(text) {
  if (typeof text !== 'string' || encoder.encode(text).length > CONFIG.MAX_IMPORT_BYTES) {
    throw new HttpError(400, '导入内容过大或格式不正确。');
  }
  const lines = text.replace(/^\uFEFF/, '').replace(/\r\n?/g, '\n').split('\n');
  const accounts = [];
  const seen = new Set();
  for (let index = 0; index < lines.length;) {
    if (!lines[index].trim()) { index++; continue; }
    const line = index + 1;
    const username = lines[index].trim();
    const password = lines[index + 1];
    const secret = lines[index + 2];
    if (!/^[a-z\d](?:[a-z\d-]{0,37}[a-z\d])?$/i.test(username)) {
      throw new HttpError(400, '第 ' + line + ' 行：GitHub 账号格式不正确。');
    }
    if (typeof password !== 'string' || password.length === 0 || password.length > 4096 || !secret?.trim()) {
      throw new HttpError(400, '第 ' + line + ' 行开始的记录不完整，应依次填写账号、密码、TOTP 种子。');
    }
    let normalized;
    try { normalized = decodeTotpSecret(secret).normalized; }
    catch { throw new HttpError(400, '第 ' + (line + 2) + ' 行：TOTP 种子无效，请填写 Base32 种子而非验证码。'); }
    const canonical = username.toLowerCase();
    if (seen.has(canonical)) throw new HttpError(409, '第 ' + line + ' 行：本次导入包含重复账号 ' + username + '。');
    seen.add(canonical);
    accounts.push({ username, password, secret: normalized });
    if (accounts.length > CONFIG.MAX_IMPORT_ACCOUNTS) {
      throw new HttpError(400, '每次最多导入 ' + CONFIG.MAX_IMPORT_ACCOUNTS + ' 个账号。');
    }
    index += 3;
  }
  if (!accounts.length) throw new HttpError(400, '请填写至少一条账号记录。');
  return accounts;
}

function sessionSeconds(role) {
  return (role === 'admin' ? CONFIG.ADMIN_SESSION_DAYS : CONFIG.USER_SESSION_DAYS) * 86400;
}

export async function createSession(role, secrets, now = Date.now()) {
  const iat = Math.floor(now / 1000);
  const payload = base64url(encoder.encode(JSON.stringify({ role, iat, exp: iat + sessionSeconds(role) })));
  const signature = await crypto.subtle.sign('HMAC', await hmacKey(secrets[role]), encoder.encode('session:' + payload));
  return payload + '.' + base64url(new Uint8Array(signature));
}

export async function verifySession(token, secrets, now = Date.now()) {
  try {
    if (!token || token.length > 1024) return null;
    const parts = token.split('.');
    if (parts.length !== 2) return null;
    const session = JSON.parse(decoder.decode(unbase64url(parts[0])));
    const seconds = Math.floor(now / 1000);
    if (!['admin', 'user'].includes(session.role) || !Number.isInteger(session.iat) || !Number.isInteger(session.exp)
      || session.iat > seconds + 60 || session.exp <= seconds || session.exp <= session.iat
      || seconds >= session.iat + sessionSeconds(session.role)
      || session.exp > session.iat + sessionSeconds(session.role)) return null;
    const valid = await crypto.subtle.verify('HMAC', await hmacKey(secrets[session.role]),
      unbase64url(parts[1]), encoder.encode('session:' + parts[0]));
    return valid ? session : null;
  } catch { return null; }
}

function cookieToken(request) {
  return request.headers.get('Cookie')?.split(';').map((part) => part.trim())
    .find((part) => part.startsWith(SESSION_COOKIE + '='))?.slice(SESSION_COOKIE.length + 1);
}

function cookie(value, maxAge) {
  return SESSION_COOKIE + '=' + value + '; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=' + maxAge;
}

function json(data, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(data), {
    status, headers: { 'Content-Type': 'application/json; charset=utf-8', ...extraHeaders },
  });
}

async function readJson(request) {
  if (!request.headers.get('Content-Type')?.toLowerCase().startsWith('application/json')) {
    throw new HttpError(415, '请使用 JSON 请求。');
  }
  if (!request.body) throw new HttpError(400, '请求内容不能为空。');
  const reader = request.body.getReader();
  let length = 0;
  const chunks = [];
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    length += value.byteLength;
    if (length > CONFIG.MAX_REQUEST_BYTES) {
      await reader.cancel();
      throw new HttpError(413, '请求内容过大。');
    }
    chunks.push(value);
  }
  const bytes = new Uint8Array(length);
  let offset = 0;
  for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.length; }
  try {
    const data = JSON.parse(decoder.decode(bytes));
    if (!data || typeof data !== 'object' || Array.isArray(data)) throw new Error();
    return data;
  } catch { throw new HttpError(400, 'JSON 格式不正确。'); }
}

function localDay(now) {
  const parts = new Intl.DateTimeFormat('en-US', {
    timeZone: CONFIG.TIME_ZONE, year: 'numeric', month: '2-digit', day: '2-digit',
  }).formatToParts(now);
  const get = (type) => parts.find((part) => part.type === type).value;
  return get('year') + '-' + get('month') + '-' + get('day');
}

async function throttleLogin(request, env, secrets, role, now) {
  // ponytail: 用现有 D1 做低流量登录限速；高流量时改用 Cloudflare 原生限速规则。
  const ip = request.headers.get('CF-Connecting-IP') || 'local';
  const digest = await crypto.subtle.sign('HMAC', await hmacKey(secrets.encryption), encoder.encode(ip + ':' + role));
  const bucket = base64url(new Uint8Array(digest));
  const windowStart = Math.floor(now / 1000 / CONFIG.LOGIN_WINDOW_SECONDS) * CONFIG.LOGIN_WINDOW_SECONDS;
  const results = await env.DB.batch([
    env.DB.prepare('DELETE FROM login_attempts WHERE window_start < ?').bind(windowStart - 86400),
    env.DB.prepare(`INSERT INTO login_attempts (bucket, window_start, attempts) VALUES (?, ?, 1)
      ON CONFLICT(bucket) DO UPDATE SET window_start = excluded.window_start,
      attempts = CASE WHEN login_attempts.window_start = excluded.window_start THEN login_attempts.attempts + 1 ELSE 1 END
      RETURNING attempts`).bind(bucket, windowStart),
  ]);
  if (results[1].results[0].attempts > CONFIG.LOGIN_ATTEMPTS) {
    throw new HttpError(429, '登录尝试过于频繁，请在 ' + Math.ceil(CONFIG.LOGIN_WINDOW_SECONDS / 60) + ' 分钟后重试。');
  }
}

async function importAccounts(env, data, secrets, now) {
  const accounts = parseImport(data.text);
  const hours = data.durationHours ?? CONFIG.DEFAULT_ACCOUNT_HOURS;
  if (typeof hours !== 'number' || !Number.isFinite(hours) || hours < 1 / 60 || hours > CONFIG.MAX_ACCOUNT_HOURS) {
    throw new HttpError(400, '有效时长应在 1 分钟至 ' + CONFIG.MAX_ACCOUNT_HOURS + ' 小时之间。');
  }
  const placeholders = accounts.map(() => '?').join(',');
  const existing = await env.DB.prepare('SELECT username FROM accounts WHERE username COLLATE NOCASE IN (' + placeholders + ')')
    .bind(...accounts.map((account) => account.username)).all();
  if (existing.results.length) {
    throw new HttpError(409, '以下账号已存在，整批未导入：' + existing.results.map((row) => row.username).join('、'));
  }
  const day = localDay(now);
  const expiresAt = now + Math.round(hours * 3600000);
  const statements = await Promise.all(accounts.map(async (account) => {
    const canonical = account.username.toLowerCase();
    const [password, secret] = await Promise.all([
      encryptValue(account.password, secrets.encryption, canonical + ':password'),
      encryptValue(account.secret, secrets.encryption, canonical + ':totp'),
    ]);
    return env.DB.prepare(`INSERT INTO accounts
      (username, password_enc, totp_enc, created_at, created_day, day_sequence, expires_at)
      VALUES (?, ?, ?, ?, ?, (SELECT COALESCE(MAX(day_sequence), 0) + 1 FROM accounts WHERE created_day = ?), ?)`)
      .bind(account.username, password, secret, now, day, day, expiresAt);
  }));
  try { await env.DB.batch(statements); }
  catch (error) {
    if (/UNIQUE constraint failed/i.test(String(error.message))) {
      throw new HttpError(409, '账号已存在，整批未导入，请刷新后检查重复账号。');
    }
    throw error;
  }
  return json({ count: accounts.length, expiresAt }, 201);
}

async function route(request, env) {
  const url = new URL(request.url);
  if (url.pathname === '/' && request.method === 'GET') return renderPage();
  if (url.pathname === '/favicon.ico' && request.method === 'GET') return new Response(null, { status: 204 });
  if (!url.pathname.startsWith('/api/')) throw new HttpError(404, '页面不存在。');
  if (request.method !== 'GET' && request.headers.get('Origin') !== url.origin) {
    throw new HttpError(403, '请求来源无效。');
  }
  if (request.headers.get('Sec-Fetch-Site') === 'cross-site') throw new HttpError(403, '不允许跨站访问。');
  const secrets = validateEnvironment(env);
  const now = Date.now();

  if (url.pathname === '/api/login' && request.method === 'POST') {
    const data = await readJson(request);
    if (!['admin', 'user'].includes(data.role) || typeof data.key !== 'string' || data.key.length > 512) {
      throw new HttpError(400, '请选择身份并填写密钥。');
    }
    await throttleLogin(request, env, secrets, data.role, now);
    if (!await sameSecret(data.key, secrets[data.role])) throw new HttpError(401, '密钥不正确。');
    const token = await createSession(data.role, secrets, now);
    return json({ role: data.role }, 200, { 'Set-Cookie': cookie(token, sessionSeconds(data.role)) });
  }
  if (url.pathname === '/api/logout' && request.method === 'POST') {
    return json({ ok: true }, 200, { 'Set-Cookie': cookie('', 0) });
  }
  const session = await verifySession(cookieToken(request), secrets, now);
  if (!session) throw new HttpError(401, '登录已失效，请重新登录。');
  if (url.pathname === '/api/session' && request.method === 'GET') {
    return json({ role: session.role, expiresAt: session.exp * 1000, serverNow: now });
  }
  if (url.pathname === '/api/accounts' && request.method === 'GET') {
    const { results } = await env.DB.prepare(`SELECT id, username, password_enc, created_at, created_day,
      day_sequence, expires_at FROM accounts ORDER BY created_day DESC, day_sequence ASC`).all();
    const accounts = await Promise.all(results.map(async (row) => ({
      id: row.id, username: row.username,
      password: await decryptValue(row.password_enc, secrets.encryption, row.username.toLowerCase() + ':password'),
      createdAt: row.created_at, createdDay: row.created_day, sequence: row.day_sequence, expiresAt: row.expires_at,
    })));
    return json({ accounts, serverNow: now });
  }
  if (url.pathname === '/api/codes' && request.method === 'POST') {
    const data = await readJson(request);
    if (!Array.isArray(data.ids) || data.ids.length > 100 || data.ids.some((id) => !Number.isSafeInteger(id) || id < 1)) {
      throw new HttpError(400, '每次最多查询 100 条有效账号。');
    }
    const ids = [...new Set(data.ids)];
    if (!ids.length) return json({ codes: [], serverNow: now });
    const { results } = await env.DB.prepare('SELECT id, username, totp_enc, expires_at FROM accounts WHERE id IN ('
      + ids.map(() => '?').join(',') + ')').bind(...ids).all();
    const codes = await Promise.all(results.filter((row) => row.expires_at > now).map(async (row) => {
      const secret = await decryptValue(row.totp_enc, secrets.encryption, row.username.toLowerCase() + ':totp');
      return { id: row.id, code: await generateTotp(secret, now),
        validUntil: Math.min(row.expires_at, (Math.floor(now / 30000) + 1) * 30000) };
    }));
    const responseTime = Date.now();
    return json({ codes: codes.filter((code) => code.validUntil > responseTime), serverNow: responseTime });
  }
  if (session.role !== 'admin') throw new HttpError(403, '此操作仅限管理员。');
  if (url.pathname === '/api/accounts/import' && request.method === 'POST') {
    return importAccounts(env, await readJson(request), secrets, now);
  }
  const match = /^\/api\/accounts\/([1-9]\d*)(\/extend)?$/.exec(url.pathname);
  if (match) {
    const id = Number(match[1]);
    if (!Number.isSafeInteger(id)) throw new HttpError(400, '账号编号无效。');
    let result;
    if (match[2] && request.method === 'POST') {
      result = await env.DB.prepare('UPDATE accounts SET expires_at = ? WHERE id = ? RETURNING id, expires_at')
        .bind(now + CONFIG.EXTEND_HOURS * 3600000, id).first();
    } else if (!match[2] && request.method === 'DELETE') {
      result = await env.DB.prepare('DELETE FROM accounts WHERE id = ? RETURNING id').bind(id).first();
    } else throw new HttpError(405, '请求方法不支持。');
    if (!result) throw new HttpError(404, '账号不存在，可能已被删除。');
    return json({ ok: true, expiresAt: result.expires_at });
  }
  throw new HttpError(404, '接口不存在。');
}

export async function handleRequest(request, env) {
  let response;
  try { response = await route(request, env); }
  catch (error) {
    if (!(error instanceof HttpError)) console.error('Request failed:', error.name || 'Error');
    response = json({ error: error instanceof HttpError ? error.message : '请求失败，请检查部署配置后重试。' },
      error instanceof HttpError ? error.status : 500);
  }
  response.headers.set('Cache-Control', 'no-store');
  response.headers.set('X-Content-Type-Options', 'nosniff');
  response.headers.set('Referrer-Policy', 'no-referrer');
  response.headers.set('X-Frame-Options', 'DENY');
  response.headers.set('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
  response.headers.set('Strict-Transport-Security', 'max-age=31536000');
  return response;
}

export default { fetch: handleRequest };

function renderPage() {
  const nonce = base64url(crypto.getRandomValues(new Uint8Array(18)));
  const publicConfig = {
    defaultHours: CONFIG.DEFAULT_ACCOUNT_HOURS, extendHours: CONFIG.EXTEND_HOURS,
    adminDays: CONFIG.ADMIN_SESSION_DAYS, userDays: CONFIG.USER_SESSION_DAYS,
    timeZone: CONFIG.TIME_ZONE, maxImportBytes: CONFIG.MAX_IMPORT_BYTES,
    maxImportAccounts: CONFIG.MAX_IMPORT_ACCOUNTS, maxAccountHours: CONFIG.MAX_ACCOUNT_HOURS,
  };
  return new Response(PAGE.replaceAll('__NONCE__', nonce).replace('__PUBLIC_CONFIG__', JSON.stringify(publicConfig)), {
    headers: {
      'Content-Type': 'text/html; charset=utf-8',
      'Content-Security-Policy': "default-src 'none'; script-src 'nonce-" + nonce + "'; style-src 'nonce-" + nonce
        + "'; connect-src 'self'; img-src 'self' data:; base-uri 'none'; form-action 'self'; frame-ancestors 'none'",
    },
  });
}

const PAGE = String.raw`<!doctype html>
<html lang="zh-CN" data-theme="light">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="color-scheme" content="light dark">
  <title>GitHub Access · 账号访问平台</title>
  <style nonce="__NONCE__">
    :root{--bg:#f6f7f9;--surface:#fff;--surface-2:#f0f2f5;--text:#18212f;--muted:#647184;--line:#e4e8ee;--accent:#087f65;--accent-hover:#076b56;--accent-soft:#e6f5ef;--danger:#c23945;--danger-soft:#fff0f1;--shadow:0 8px 30px #1b263508;--ring:#0b997a55;color-scheme:light}
    [data-theme=dark]{--bg:#10151d;--surface:#181f2a;--surface-2:#202a37;--text:#e8edf5;--muted:#99a8bc;--line:#2d3747;--accent:#67d8b5;--accent-hover:#8ae6c8;--accent-soft:#183b34;--danger:#ff929d;--danger-soft:#3d222b;--shadow:0 8px 30px #0002;--ring:#67d8b555;color-scheme:dark}
    *{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:14px/1.6 -apple-system,BlinkMacSystemFont,"Segoe UI","PingFang SC","Microsoft YaHei",sans-serif}button,input,textarea{font:inherit}button{cursor:pointer}button:disabled{cursor:not-allowed;opacity:.55}button,input,textarea{border-radius:9px}button:focus-visible,input:focus-visible,textarea:focus-visible,a:focus-visible{outline:3px solid var(--ring);outline-offset:2px}button{border:1px solid var(--line);background:var(--surface);color:var(--text);padding:9px 15px;transition:background .15s,border-color .15s}button:hover:not(:disabled){background:var(--surface-2)}button.primary{background:var(--accent);border-color:var(--accent);color:var(--surface);font-weight:650}button.primary:hover:not(:disabled){background:var(--accent-hover)}input,textarea{width:100%;border:1px solid var(--line);background:var(--surface);color:var(--text);padding:11px 13px}input::placeholder,textarea::placeholder{color:var(--muted);opacity:.8}textarea{resize:vertical;min-height:210px;font-family:ui-monospace,SFMono-Regular,Consolas,monospace;line-height:1.65}label{display:block;font-size:13px;font-weight:600;margin-bottom:7px}[hidden]{display:none!important}.muted{color:var(--muted)}.mono{font-family:ui-monospace,SFMono-Regular,Consolas,monospace}.small{font-size:12px}.shell{max-width:1180px;margin:auto;padding:0 32px}.topbar{border-bottom:1px solid var(--line);background:var(--surface)}.topbar-inner{min-height:76px;display:flex;align-items:center;justify-content:space-between;gap:16px}.brand{display:flex;gap:12px;align-items:center}.brand-mark{width:37px;height:37px;border-radius:11px;background:var(--text);color:var(--surface);display:grid;place-items:center;font-size:17px;font-weight:750;letter-spacing:-3px;padding-right:3px}.brand-name{font-weight:750;font-size:16px;letter-spacing:-.4px}.brand-sub{font-size:10px;letter-spacing:2px;color:var(--muted)}.top-actions{display:flex;align-items:center;gap:10px}.icon-button{width:37px;height:37px;padding:0;display:grid;place-items:center;font-size:18px}.badge{display:inline-flex;align-items:center;gap:6px;border:1px solid var(--line);border-radius:20px;padding:3px 10px;font-size:12px;color:var(--muted)}.badge.active{background:var(--accent-soft);color:var(--accent);border-color:transparent}.badge.expired{background:var(--surface-2);border-color:transparent}.dot{width:6px;height:6px;border-radius:50%;background:currentColor}.login-layout{min-height:calc(100vh - 140px);display:grid;grid-template-columns:1.15fr 1fr;align-items:center;gap:80px;padding-top:56px;padding-bottom:70px}.eyebrow{font-size:11px;letter-spacing:2px;color:var(--accent);font-weight:700}.hero h1{font-size:clamp(32px,4.5vw,49px);line-height:1.3;letter-spacing:-1.8px;margin:18px 0 22px;font-weight:750}.hero p{color:var(--muted);max-width:340px;line-height:1.9}.hero-rule{width:45px;height:3px;background:var(--accent);margin-top:34px}.login-card{background:var(--surface);border:1px solid var(--line);border-radius:18px;padding:32px;box-shadow:var(--shadow)}h2,h3,p{margin-top:0}.login-card h2{font-size:22px;margin-bottom:4px}.role-switch{display:flex;background:var(--surface-2);border-radius:10px;padding:4px;margin:24px 0}.role-switch button{flex:1;background:transparent;border:0;color:var(--muted);padding:8px}.role-switch button[aria-pressed=true]{background:var(--surface);color:var(--text);box-shadow:0 1px 5px #0000000c}.key-field{position:relative}.key-field input{padding-right:60px}.key-field button{position:absolute;right:5px;top:5px;border:0;padding:7px 9px;color:var(--muted);font-size:12px}.full{width:100%}.login-submit{margin-top:20px}.login-note{font-size:12px;text-align:center;color:var(--muted);margin-top:15px}.inline-error{color:var(--danger);font-size:13px;margin:12px 0 0;white-space:pre-wrap;overflow-wrap:anywhere}.workspace{padding-top:36px;padding-bottom:48px}.workspace-head{display:flex;align-items:flex-start;justify-content:space-between;gap:20px;margin-bottom:26px}.workspace-head h1{font-size:28px;letter-spacing:-.8px;line-height:1.3;margin:0 0 8px}.stats{display:flex;gap:8px;flex-wrap:wrap}.stat{font-size:12px;color:var(--muted)}.stat strong{color:var(--text);font-size:13px}.stat+.stat::before{content:"/";margin-right:8px;color:var(--line)}.head-actions{display:flex;gap:8px}.toolbar{display:flex;gap:12px;align-items:center;margin-bottom:27px}.search-field{position:relative;flex:1;max-width:420px}.search-field input{padding-left:38px}.search-icon{position:absolute;left:13px;top:9px;font-size:18px;color:var(--muted);pointer-events:none}.toolbar-note{margin-left:auto;font-size:12px;color:var(--muted)}.day-group{margin-bottom:29px}.day-title{display:flex;align-items:center;gap:11px;margin-bottom:12px}.day-title h2{font-size:14px;margin:0;letter-spacing:.2px}.day-title span{font-size:12px;color:var(--muted)}.day-title::after{content:"";height:1px;background:var(--line);flex:1}.account-list{display:grid;gap:12px}.account-card{background:var(--surface);border:1px solid var(--line);border-radius:13px;box-shadow:var(--shadow);padding:19px 21px}.card-top{display:flex;align-items:center;justify-content:space-between;gap:12px;margin-bottom:17px}.account-title{display:flex;align-items:center;gap:9px;min-width:0}.sequence{font-size:11px;color:var(--muted);min-width:24px}.account-title h3{font-size:15px;margin:0;overflow-wrap:anywhere}.card-meta{display:flex;align-items:center;gap:10px;flex-wrap:wrap}.card-fields{display:grid;grid-template-columns:1fr 1fr .9fr;gap:22px}.field-label{color:var(--muted);font-size:11px;margin-bottom:5px}.field-value{min-width:0;display:flex;align-items:center;gap:6px}.field-content{font-size:14px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;flex:1;min-width:0}.copy-button,.reveal-button{border:0;background:transparent;padding:4px 6px;color:var(--muted);font-size:12px;flex-shrink:0}.copy-button:hover:not(:disabled),.reveal-button:hover:not(:disabled){color:var(--accent);background:var(--accent-soft)}.totp-value{font-size:21px;letter-spacing:4px;font-weight:700;color:var(--accent);line-height:1.3}.totp-placeholder{font-size:13px;color:var(--muted)}.totp-details{display:flex;align-items:center;gap:8px;height:20px;margin-top:4px;font-size:10px;color:var(--muted)}progress{appearance:none;width:62px;height:3px;border:0;background:var(--line);border-radius:4px;overflow:hidden}progress::-webkit-progress-bar{background:var(--line)}progress::-webkit-progress-value{background:var(--accent);border-radius:4px}progress::-moz-progress-bar{background:var(--accent)}.card-footer{margin-top:15px;padding-top:12px;border-top:1px solid var(--line);display:flex;align-items:center;justify-content:space-between;gap:12px}.expiry{font-size:11px;color:var(--muted)}.card-actions{display:flex;gap:5px}.card-actions button{font-size:11px;padding:5px 10px}.card-actions .delete{border-color:transparent;color:var(--muted)}.card-actions .delete:hover{color:var(--danger);background:var(--danger-soft)}.empty-state{text-align:center;padding:70px 20px;background:var(--surface);border:1px dashed var(--line);border-radius:14px}.empty-symbol{font-size:27px;color:var(--muted);margin-bottom:12px}.empty-state h2{font-size:16px;margin-bottom:6px}.empty-state p{font-size:13px;color:var(--muted);margin:0}.footer{padding:22px 32px;text-align:center;font-size:11px;color:var(--muted);letter-spacing:.5px}.status-banner{background:var(--danger-soft);color:var(--danger);padding:12px 15px;border-radius:9px;font-size:13px;margin-bottom:20px}.status-banner button{background:transparent;border:0;color:inherit;padding:0 5px;text-decoration:underline}.modal{border:1px solid var(--line);border-radius:16px;padding:0;background:var(--surface);color:var(--text);width:min(540px,calc(100% - 32px));max-height:90vh;box-shadow:0 20px 90px #0004}.modal::backdrop{background:#0d152770;backdrop-filter:blur(3px)}.modal-inner{padding:26px}.modal-header{display:flex;justify-content:space-between;align-items:center;margin-bottom:8px}.modal-header h2{font-size:20px;margin:0}.modal-description{font-size:13px;color:var(--muted);margin-bottom:20px}.import-tools{display:flex;align-items:center;justify-content:space-between;gap:12px;margin-bottom:9px}.import-tools label{margin:0}.file-button{font-size:12px;padding:5px 11px}.form-row{margin-top:17px;display:flex;align-items:center;justify-content:space-between;gap:12px}.form-row label{margin:0}.duration-input{display:flex;align-items:center;gap:9px;color:var(--muted);font-size:12px}.duration-input input{width:96px;padding:7px 10px}.modal-actions{display:flex;justify-content:flex-end;gap:8px;margin-top:24px}.toast{position:fixed;bottom:30px;left:50%;transform:translateX(-50%);background:var(--text);color:var(--surface);padding:11px 21px;border-radius:10px;box-shadow:0 6px 30px #0002;font-size:13px;z-index:10;max-width:calc(100% - 32px);text-align:center}.toast.error{background:var(--danger);color:var(--surface)}.loading-note{text-align:center;padding:60px;color:var(--muted)}
    @media(min-width:1000px){.account-list{grid-template-columns:1fr 1fr}.card-fields{grid-template-columns:1fr 1fr;gap:14px 22px}.totp-field{grid-column:1/-1;display:flex;gap:14px;align-items:center;padding-top:12px;border-top:1px solid var(--line)}.totp-field .field-label{margin:0;min-width:68px}.totp-field .field-value{flex:1}.totp-field .field-content{flex:none}.totp-details{margin:0}}
    @media(max-width:760px){.shell{padding-left:18px;padding-right:18px}.topbar-inner{min-height:66px}.brand-sub{font-size:9px}.login-layout{grid-template-columns:1fr;gap:28px;padding-top:35px;padding-bottom:35px;min-height:auto;max-width:460px}.hero h1{font-size:31px;margin:10px 0}.hero p{font-size:13px;margin-bottom:0}.hero-rule{display:none}.login-card{padding:25px}.workspace{padding-top:26px}.workspace-head h1{font-size:24px}.workspace-head{gap:12px}.head-actions button{padding:8px 11px;font-size:12px}.toolbar{margin-bottom:22px}.toolbar-note{display:none}.search-field{max-width:none}.card-fields{grid-template-columns:1fr 1fr;gap:15px}.totp-field{grid-column:1/-1;display:flex;gap:12px;align-items:center;padding-top:12px;border-top:1px solid var(--line)}.totp-field .field-label{margin:0;min-width:65px}.totp-field .field-value{flex:1}.totp-field .field-content{flex:none}.totp-details{margin:0}.account-card{padding:17px}.card-top{margin-bottom:14px}.card-footer{align-items:flex-start;flex-wrap:wrap}.top-actions{gap:7px}.top-actions .badge{font-size:11px;padding:3px 8px}.top-actions #logout-button{padding:7px 9px;font-size:12px}.modal-inner{padding:22px}}
    .account-card,.account-field{min-width:0}
    @media(max-width:420px){.topbar-inner{gap:8px}.brand{gap:8px}.brand-mark{width:32px;height:32px;flex-shrink:0}.brand-name{font-size:14px;white-space:nowrap}.brand-sub{font-size:8px;letter-spacing:1.2px}.top-actions{gap:5px;flex-shrink:0}.top-actions .badge{font-size:10px;padding:3px 6px;white-space:nowrap}.top-actions .icon-button{width:32px;height:32px}.top-actions #logout-button{font-size:11px;padding:6px 7px;white-space:nowrap}.workspace-head{flex-direction:column}.head-actions{align-self:stretch}.head-actions button{white-space:nowrap}.card-fields{grid-template-columns:repeat(2,minmax(0,1fr))}.totp-field{flex-wrap:wrap;gap:8px 12px}.totp-field .field-value{flex:1 0 160px}.totp-details{margin-left:77px}}
    @media(prefers-reduced-motion:reduce){*{transition:none!important}}
  </style>
</head>
<body>
  <header class="topbar"><div class="shell topbar-inner">
    <div class="brand"><div class="brand-mark" aria-hidden="true">&gt;_</div><div><div class="brand-name">GitHub Access</div><div class="brand-sub">账号访问平台</div></div></div>
    <div class="top-actions"><span id="role-badge" class="badge" hidden></span><button id="theme-button" class="icon-button" type="button" aria-label="切换深色模式" title="切换明暗模式">◐</button><button id="logout-button" type="button" hidden>退出</button></div>
  </div></header>
  <main>
    <section id="login-view" class="shell login-layout" hidden>
      <div class="hero"><div class="eyebrow">YOUR ACCESS, SIMPLIFIED</div><h1>账号与验证码，<br>随取随用。</h1><p>在一个地方查看账号信息与动态验证码。<br>少一点切换，多一点从容。</p><div class="hero-rule"></div></div>
      <div class="login-card"><h2>欢迎回来</h2><p class="muted small">选择身份，输入密钥后继续</p>
        <div class="role-switch" role="group" aria-label="登录身份"><button type="button" data-role="user" aria-pressed="true">使用方</button><button type="button" data-role="admin" aria-pressed="false">管理员</button></div>
        <form id="login-form"><label for="login-key" id="key-label">用户密钥</label><div class="key-field"><input id="login-key" type="password" required maxlength="512" autocomplete="current-password" placeholder="输入用户密钥"><button id="reveal-key" type="button" aria-label="显示登录密钥" aria-pressed="false">显示</button></div><p id="login-error" class="inline-error" role="alert" hidden></p><button id="login-submit" type="submit" class="primary full login-submit">进入平台 <span aria-hidden="true">→</span></button></form>
        <div id="login-note" class="login-note"></div>
      </div>
    </section>
    <section id="workspace" class="shell workspace" hidden>
      <div class="workspace-head"><div><div class="eyebrow small">ACCOUNT WORKSPACE</div><h1 id="workspace-title">账号列表</h1><div class="stats"><span class="stat">全部 <strong id="total-count">0</strong></span><span class="stat">有效 <strong id="active-count">0</strong></span><span class="stat">已到期 <strong id="expired-count">0</strong></span></div></div><div class="head-actions"><button id="refresh-button" type="button">↻ 刷新</button><button id="open-import" type="button" class="primary" hidden>＋ 录入账号</button></div></div>
      <div id="workspace-error" class="status-banner" role="alert" hidden><span id="workspace-error-text"></span><button id="retry-button" type="button">重试</button></div>
      <div class="toolbar"><div class="search-field"><span class="search-icon" aria-hidden="true">⌕</span><label for="search" hidden>搜索 GitHub 账号</label><input id="search" type="search" placeholder="搜索 GitHub 账号…" autocomplete="off"></div><span class="toolbar-note">日期倒序 · 日期内按录入顺序</span></div>
      <div id="accounts" aria-live="polite"></div>
    </section>
    <div id="initial-loading" class="loading-note" role="status">正在加载…</div>
  </main>
  <footer class="footer">GitHub Access · 简单，有序。</footer>
  <dialog id="import-dialog" class="modal" aria-labelledby="import-title"><form id="import-form" class="modal-inner">
    <div class="modal-header"><h2 id="import-title">录入账号</h2><button id="close-import" type="button" class="icon-button" aria-label="关闭录入窗口">×</button></div><p class="modal-description">每条记录占三行：账号、密码、TOTP 种子。记录间可留空行，也可直接上传 TXT。</p>
    <div class="import-tools"><label for="import-text">账号信息</label><button id="choose-file" type="button" class="file-button">↑ 导入 TXT</button><input id="import-file" type="file" accept=".txt,text/plain" hidden></div>
    <textarea id="import-text" required spellcheck="false" autocomplete="off" placeholder="github-account&#10;password&#10;JBSWY3DPEHPK3PXP&#10;&#10;next-account&#10;password&#10;JBSWY3DPEHPK3PXP"></textarea>
    <div class="form-row"><label for="duration-hours">有效时长</label><div class="duration-input"><input id="duration-hours" type="number" min="0.017" step="any" required><span>小时</span></div></div><p id="import-limit" class="muted small"></p><p id="import-error" class="inline-error" role="alert" hidden></p>
    <div class="modal-actions"><button id="cancel-import" type="button">取消</button><button id="import-submit" type="submit" class="primary">确认录入</button></div>
  </form></dialog>
  <dialog id="delete-dialog" class="modal" aria-labelledby="delete-title"><form id="delete-form" class="modal-inner"><div class="modal-header"><h2 id="delete-title">删除账号</h2></div><p id="delete-description" class="muted"></p><p id="delete-error" class="inline-error" role="alert" hidden></p><div class="modal-actions"><button id="cancel-delete" type="button">取消</button><button id="confirm-delete" type="submit" class="primary">确认删除</button></div></form></dialog>
  <div id="toast" class="toast" role="status" hidden></div>
  <script nonce="__NONCE__">
  'use strict';
  const settings = __PUBLIC_CONFIG__;
  const $ = (id) => document.getElementById(id);
  let loginRole = 'user';
  let currentRole = null;
  let accounts = [];
  let codes = new Map();
  let clockOffset = 0;
  let lastCodeStep = -1;
  let refreshingCodes = false;
  let refreshingAccounts = false;
  let revealedPasswords = new Set();
  let deletingId = null;
  let toastTimer;
  let sessionGeneration = 0;
  let workspaceLoadedAt = 0;
  const dateFormat = new Intl.DateTimeFormat('zh-CN', { timeZone: settings.timeZone, month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', hour12: false });
  const media = window.matchMedia('(prefers-color-scheme: dark)');
  let explicitTheme;
  try { explicitTheme = localStorage.getItem('theme'); } catch {}
  function setTheme(theme) {
    document.documentElement.dataset.theme = theme;
    $('theme-button').textContent = theme === 'dark' ? '☀' : '◐';
    $('theme-button').setAttribute('aria-label', theme === 'dark' ? '切换浅色模式' : '切换深色模式');
  }
  setTheme(explicitTheme === 'light' || explicitTheme === 'dark' ? explicitTheme : media.matches ? 'dark' : 'light');
  $('theme-button').addEventListener('click', () => {
    explicitTheme = document.documentElement.dataset.theme === 'dark' ? 'light' : 'dark';
    setTheme(explicitTheme);
    try { localStorage.setItem('theme', explicitTheme); } catch {}
  });
  media.addEventListener('change', () => { if (!explicitTheme) setTheme(media.matches ? 'dark' : 'light'); });

  const now = () => Date.now() + clockOffset;
  function syncClock(serverNow) { if (typeof serverNow === 'number') clockOffset = serverNow - Date.now(); }
  function message(id, text) { $(id).textContent = text || ''; $(id).hidden = !text; }
  function toast(text, isError = false) {
    clearTimeout(toastTimer); $('toast').textContent = text;
    $('toast').className = 'toast' + (isError ? ' error' : ''); $('toast').hidden = false;
    toastTimer = setTimeout(() => { $('toast').hidden = true; }, 3000);
  }
  async function api(path, options = {}) {
    const response = await fetch(path, {
      ...options, credentials: 'same-origin', cache: 'no-store',
      headers: { ...(options.body ? { 'Content-Type': 'application/json' } : {}), ...options.headers },
    });
    let data;
    try { data = await response.json(); } catch { throw new Error('服务响应异常，请稍后重试。'); }
    if (!response.ok) {
      if (response.status === 401 && currentRole) showLogin();
      throw new Error(data.error || '请求失败，请重试。');
    }
    return data;
  }
  function showLogin() {
    sessionGeneration++; currentRole = null; accounts = []; codes.clear(); revealedPasswords.clear();
    $('accounts').replaceChildren(); $('search').value = ''; $('workspace').hidden = true;
    $('login-view').hidden = false; $('role-badge').hidden = true; $('logout-button').hidden = true;
    $('initial-loading').hidden = true; $('login-key').value = ''; $('import-text').value = '';
    $('import-dialog').close(); $('delete-dialog').close();
  }
  function showWorkspace(role) {
    sessionGeneration++; currentRole = role; workspaceLoadedAt = 0;
    $('login-view').hidden = true; $('workspace').hidden = false; $('initial-loading').hidden = true;
    $('role-badge').textContent = role === 'admin' ? '管理员' : '使用方'; $('role-badge').hidden = false;
    $('logout-button').hidden = false; $('open-import').hidden = role !== 'admin';
    $('workspace-title').textContent = role === 'admin' ? '账号管理' : '账号列表';
  }
  function updateLoginRole() {
    document.querySelectorAll('[data-role]').forEach((button) => button.setAttribute('aria-pressed', String(button.dataset.role === loginRole)));
    $('key-label').textContent = loginRole === 'admin' ? '管理密钥' : '用户密钥';
    $('login-key').placeholder = '输入' + $('key-label').textContent;
    $('login-note').textContent = '登录状态保留 ' + (loginRole === 'admin' ? settings.adminDays : settings.userDays) + ' 天';
    message('login-error', '');
  }
  document.querySelectorAll('[data-role]').forEach((button) => button.addEventListener('click', () => {
    loginRole = button.dataset.role; $('login-key').value = ''; updateLoginRole();
  }));
  updateLoginRole();
  $('reveal-key').addEventListener('click', () => {
    const revealed = $('login-key').type === 'password'; $('login-key').type = revealed ? 'text' : 'password';
    $('reveal-key').textContent = revealed ? '隐藏' : '显示';
    $('reveal-key').setAttribute('aria-pressed', String(revealed));
    $('reveal-key').setAttribute('aria-label', revealed ? '隐藏登录密钥' : '显示登录密钥');
  });
  $('login-form').addEventListener('submit', async (event) => {
    event.preventDefault(); $('login-submit').disabled = true; message('login-error', '');
    try {
      const data = await api('/api/login', { method: 'POST', body: JSON.stringify({ role: loginRole, key: $('login-key').value }) });
      $('login-key').value = ''; showWorkspace(data.role); await loadAccounts();
    } catch (error) { message('login-error', error.message); }
    finally { $('login-submit').disabled = false; }
  });
  $('logout-button').addEventListener('click', async () => {
    $('logout-button').disabled = true;
    try { await api('/api/logout', { method: 'POST' }); showLogin(); }
    catch (error) { toast(error.message, true); }
    finally { $('logout-button').disabled = false; }
  });

  function element(tag, className, text) {
    const node = document.createElement(tag); if (className) node.className = className;
    if (text !== undefined) node.textContent = text; return node;
  }
  function actionButton(text, className, action, id, label) {
    const button = element('button', className, text); button.type = 'button';
    button.dataset.action = action; button.dataset.id = id;
    if (label) button.setAttribute('aria-label', label); return button;
  }
  function accountField(label, value, action, account) {
    const field = element('div', 'account-field'); field.append(element('div', 'field-label', label));
    const row = element('div', 'field-value');
    const text = element('span', 'field-content mono', value);
    if (action === 'password') {
      text.dataset.password = account.id;
      const toggle = actionButton(revealedPasswords.has(account.id) ? '隐藏' : '显示', 'reveal-button', 'reveal', account.id, '切换密码显示');
      toggle.setAttribute('aria-pressed', String(revealedPasswords.has(account.id)));
      row.append(text, toggle);
    } else row.append(text);
    row.append(actionButton('复制', 'copy-button', action, account.id, '复制' + label));
    field.append(row); return field;
  }
  function accountCard(account) {
    const expired = account.expiresAt <= now();
    const card = element('article', 'account-card'); card.dataset.account = account.id;
    const top = element('div', 'card-top'); const title = element('div', 'account-title');
    title.append(element('span', 'sequence mono', '#' + String(account.sequence).padStart(2, '0')), element('h3', '', account.username));
    const badge = element('span', 'badge ' + (expired ? 'expired' : 'active'), expired ? '已到期' : '有效期内');
    badge.dataset.status = account.id; top.append(title, badge);
    const fields = element('div', 'card-fields');
    fields.append(accountField('GitHub 账号', account.username, 'username', account),
      accountField('登录密码', revealedPasswords.has(account.id) ? account.password : '••••••••••••', 'password', account));
    const totp = element('div', 'totp-field'); totp.append(element('div', 'field-label', '动态验证码'));
    const codeRow = element('div', 'field-value');
    const code = element('span', 'field-content mono totp-placeholder', expired ? '已到期' : '获取中…'); code.dataset.code = account.id;
    const copy = actionButton('复制', 'copy-button', 'code', account.id, '复制动态验证码'); copy.disabled = true;
    codeRow.append(code, copy); totp.append(codeRow);
    const detail = element('div', 'totp-details'); detail.dataset.codeDetails = account.id;
    const progress = element('progress'); progress.max = 30; progress.value = 0; progress.setAttribute('aria-label', '验证码剩余有效时间');
    detail.append(progress, element('span', '')); totp.append(detail); fields.append(totp);
    const footer = element('div', 'card-footer'); footer.append(element('span', 'expiry', '到期 ' + dateFormat.format(account.expiresAt)));
    if (currentRole === 'admin') {
      const actions = element('div', 'card-actions');
      actions.append(actionButton('延期 ' + settings.extendHours + 'h', '', 'extend', account.id), actionButton('删除', 'delete', 'delete', account.id)); footer.append(actions);
    }
    card.append(top, fields, footer); return card;
  }
  function visibleAccounts() {
    const query = $('search').value.trim().toLowerCase();
    return accounts.filter((account) => account.username.toLowerCase().includes(query));
  }
  function renderAccounts() {
    const visible = visibleAccounts(); const fragment = document.createDocumentFragment();
    if (!visible.length) {
      const empty = element('div', 'empty-state');
      empty.append(element('div', 'empty-symbol', '⌘'), element('h2', '', accounts.length ? '没有匹配的账号' : '还没有账号'),
        element('p', '', accounts.length ? '试试其他账号名称。' : currentRole === 'admin' ? '点击「录入账号」，粘贴信息或上传 TXT。' : '等待管理员录入账号后，点击刷新查看。'));
      fragment.append(empty);
    }
    let group;
    let previousDay;
    for (const account of visible) {
      if (account.createdDay !== previousDay) {
        const section = element('section', 'day-group'); const header = element('div', 'day-title');
        header.append(element('h2', 'mono', account.createdDay), element('span', '', visible.filter((item) => item.createdDay === account.createdDay).length + ' 个账号'));
        group = element('div', 'account-list'); section.append(header, group); fragment.append(section); previousDay = account.createdDay;
      }
      group.append(accountCard(account));
    }
    $('accounts').replaceChildren(fragment); updateCounters(); updateCodeDisplay();
  }
  function updateCounters() {
    const active = accounts.filter((account) => account.expiresAt > now()).length;
    $('total-count').textContent = accounts.length; $('active-count').textContent = active; $('expired-count').textContent = accounts.length - active;
  }
  async function loadAccounts() {
    if (!currentRole || refreshingAccounts) return;
    const generation = sessionGeneration; refreshingAccounts = true; workspaceLoadedAt = Date.now(); $('refresh-button').disabled = true;
    try {
      const data = await api('/api/accounts');
      if (generation !== sessionGeneration) return;
      syncClock(data.serverNow); accounts = data.accounts; codes.clear(); revealedPasswords.clear();
      workspaceLoadedAt = Date.now(); $('workspace-error').hidden = true; renderAccounts();
      await refreshCodes();
    } catch (error) {
      if (generation === sessionGeneration && currentRole) {
        codes.clear(); updateCodeDisplay(); $('workspace-error-text').textContent = error.message; $('workspace-error').hidden = false;
      }
    } finally { refreshingAccounts = false; $('refresh-button').disabled = false; }
  }
  async function refreshCodes() {
    if (!currentRole || refreshingCodes || document.hidden) return;
    const generation = sessionGeneration; refreshingCodes = true;
    lastCodeStep = Math.floor(now() / 30000);
    const ids = visibleAccounts().filter((account) => account.expiresAt > now()).map((account) => account.id);
    try {
      for (let start = 0; start < ids.length; start += 100) {
        const data = await api('/api/codes', { method: 'POST', body: JSON.stringify({ ids: ids.slice(start, start + 100) }) });
        if (generation !== sessionGeneration) return;
        syncClock(data.serverNow);
        for (const id of ids.slice(start, start + 100)) codes.delete(id);
        for (const code of data.codes) codes.set(code.id, code);
      }
      if (generation === sessionGeneration) { $('workspace-error').hidden = true; updateCodeDisplay(); }
    } catch (error) {
      if (generation === sessionGeneration && currentRole) {
        codes.clear(); updateCodeDisplay(); $('workspace-error-text').textContent = error.message; $('workspace-error').hidden = false;
      }
    } finally { refreshingCodes = false; }
  }
  function updateCodeDisplay() {
    for (const card of $('accounts').querySelectorAll('[data-account]')) {
      const id = Number(card.dataset.account); const account = accounts.find((item) => item.id === id);
      if (!account) continue;
      const expired = account.expiresAt <= now(); const code = codes.get(id);
      const valid = !expired && code && code.validUntil > now();
      const value = card.querySelector('[data-code]'); const copy = card.querySelector('[data-action=code]');
      const detail = card.querySelector('[data-code-details]');
      value.className = 'field-content mono ' + (valid ? 'totp-value' : 'totp-placeholder');
      value.textContent = expired ? '已到期' : valid ? code.code.slice(0, 3) + ' ' + code.code.slice(3) : '等待刷新';
      copy.disabled = !valid; detail.hidden = !valid;
      if (valid) {
        const remaining = Math.max(0, Math.ceil((code.validUntil - now()) / 1000));
        detail.querySelector('progress').value = remaining; detail.querySelector('span').textContent = remaining + 's';
      }
      const badge = card.querySelector('[data-status]'); badge.className = 'badge ' + (expired ? 'expired' : 'active'); badge.textContent = expired ? '已到期' : '有效期内';
      if (expired) codes.delete(id);
    }
    updateCounters();
  }
  let searchTimer;
  $('search').addEventListener('input', () => {
    renderAccounts(); lastCodeStep = -1; clearTimeout(searchTimer); searchTimer = setTimeout(refreshCodes, 200);
  });
  $('refresh-button').addEventListener('click', loadAccounts); $('retry-button').addEventListener('click', loadAccounts);
  async function copyValue(value) {
    try { await navigator.clipboard.writeText(value); toast('已复制'); }
    catch { toast('复制失败，请允许浏览器访问剪贴板后重试。', true); }
  }
  $('accounts').addEventListener('click', async (event) => {
    const button = event.target.closest('button[data-action]'); if (!button || button.disabled) return;
    const id = Number(button.dataset.id); const account = accounts.find((item) => item.id === id); if (!account) return;
    const action = button.dataset.action;
    if (action === 'username' || action === 'password') return copyValue(account[action]);
    if (action === 'code') {
      const code = codes.get(id);
      if (account.expiresAt <= now() || !code || code.validUntil <= now()) { updateCodeDisplay(); return toast('验证码已失效，请等待刷新。', true); }
      return copyValue(code.code);
    }
    if (action === 'reveal') {
      if (revealedPasswords.has(id)) revealedPasswords.delete(id); else revealedPasswords.add(id);
      button.closest('.field-value').querySelector('[data-password]').textContent = revealedPasswords.has(id) ? account.password : '••••••••••••';
      button.textContent = revealedPasswords.has(id) ? '隐藏' : '显示'; button.setAttribute('aria-pressed', String(revealedPasswords.has(id))); return;
    }
    if (action === 'delete') {
      deletingId = id; $('delete-description').textContent = '确定删除 ' + account.username + '？删除后无法恢复。'; message('delete-error', ''); $('delete-dialog').showModal(); return;
    }
    if (action === 'extend') {
      button.disabled = true;
      try {
        await api('/api/accounts/' + id + '/extend', { method: 'POST' });
        toast('已更新有效期'); await loadAccounts();
      } catch (error) { toast(error.message, true); }
      finally { button.disabled = false; }
    }
  });

  $('duration-hours').value = settings.defaultHours; $('duration-hours').max = settings.maxAccountHours;
  $('import-limit').textContent = '单次最多 ' + settings.maxImportAccounts + ' 条记录，TXT 文件不超过 ' + (settings.maxImportBytes / 1024) + ' KB。';
  $('open-import').addEventListener('click', () => { message('import-error', ''); $('import-dialog').showModal(); });
  $('close-import').addEventListener('click', () => $('import-dialog').close());
  $('cancel-import').addEventListener('click', () => $('import-dialog').close());
  $('choose-file').addEventListener('click', () => $('import-file').click());
  $('import-file').addEventListener('change', async () => {
    const file = $('import-file').files[0]; if (!file) return;
    try {
      if (!file.name.toLowerCase().endsWith('.txt')) throw new Error('请选择 TXT 文件。');
      if (file.size > settings.maxImportBytes) throw new Error('文件过大，请拆分后导入。');
      const bytes = await file.arrayBuffer();
      $('import-text').value = new TextDecoder('utf-8', { fatal: true }).decode(bytes); message('import-error', '');
    } catch (error) { message('import-error', error instanceof TypeError ? '文件应使用 UTF-8 编码，请转换后重试。' : error.message); }
    finally { $('import-file').value = ''; }
  });
  let importing = false;
  $('import-dialog').addEventListener('cancel', (event) => { if (importing) event.preventDefault(); });
  $('import-form').addEventListener('submit', async (event) => {
    event.preventDefault(); if (importing) return; importing = true;
    $('import-submit').disabled = true; $('cancel-import').disabled = true; $('close-import').disabled = true; message('import-error', '');
    try {
      const data = await api('/api/accounts/import', { method: 'POST', body: JSON.stringify({ text: $('import-text').value, durationHours: Number($('duration-hours').value) }) });
      $('import-text').value = ''; $('import-dialog').close(); $('search').value = ''; toast('已录入 ' + data.count + ' 个账号'); await loadAccounts();
    } catch (error) { message('import-error', error.message); }
    finally { importing = false; $('import-submit').disabled = false; $('cancel-import').disabled = false; $('close-import').disabled = false; }
  });
  $('cancel-delete').addEventListener('click', () => $('delete-dialog').close());
  $('delete-form').addEventListener('submit', async (event) => {
    event.preventDefault(); $('confirm-delete').disabled = true; message('delete-error', '');
    try { await api('/api/accounts/' + deletingId, { method: 'DELETE' }); $('delete-dialog').close(); toast('账号已删除'); await loadAccounts(); }
    catch (error) { message('delete-error', error.message); }
    finally { $('confirm-delete').disabled = false; }
  });
  async function resume() {
    if (document.hidden || !currentRole) return;
    updateCodeDisplay();
    if (Date.now() - workspaceLoadedAt > 60000) await loadAccounts(); else await refreshCodes();
  }
  document.addEventListener('visibilitychange', () => { if (!document.hidden) resume(); });
  window.addEventListener('pageshow', (event) => { if (event.persisted) resume(); });
  setInterval(() => {
    if (!currentRole || document.hidden) return;
    updateCodeDisplay();
    if (Date.now() - workspaceLoadedAt > 60000 && !refreshingAccounts) loadAccounts();
    else if (Math.floor(now() / 30000) !== lastCodeStep) refreshCodes();
  }, 1000);
  (async () => {
    try { const session = await api('/api/session'); syncClock(session.serverNow); showWorkspace(session.role); await loadAccounts(); }
    catch (error) { showLogin(); if (!error.message.includes('登录已失效')) message('login-error', error.message); }
    finally { $('initial-loading').hidden = true; }
  })();
  </script>
</body>
</html>`;
