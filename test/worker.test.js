import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { DatabaseSync } from 'node:sqlite';
import {
  CONFIG, parseImport, generateTotp, decodeTotpSecret, encryptValue, decryptValue,
  createSession, verifySession, handleRequest,
} from '../worker.js';

const source = readFileSync(new URL('../worker.js', import.meta.url), 'utf8');
const schema = readFileSync(new URL('../schema.sql', import.meta.url), 'utf8');
const SEED = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ';
const secrets = {
  admin: 'admin-' + 'a'.repeat(40),
  user: 'user-' + 'b'.repeat(40),
  encryption: Buffer.alloc(32, 7).toString('base64'),
};
const ORIGIN = 'https://access.example.com';

// 使用真实 SQLite 执行生产 SQL，仅适配 D1 的 prepare/bind/batch 接口。
function environment(t) {
  const sqlite = new DatabaseSync(':memory:');
  sqlite.exec(schema);
  t.after(() => sqlite.close());
  const DB = {
    prepare(sql) {
      const statement = {
        parameters: [],
        bind(...parameters) { return { ...this, parameters }; },
        async all() { return { results: sqlite.prepare(sql).all(...this.parameters), success: true }; },
        async first() { return sqlite.prepare(sql).get(...this.parameters) ?? null; },
      };
      return statement;
    },
    async batch(statements) {
      sqlite.exec('BEGIN');
      try {
        const results = [];
        for (const statement of statements) results.push(await statement.all());
        sqlite.exec('COMMIT');
        return results;
      } catch (error) { sqlite.exec('ROLLBACK'); throw error; }
    },
  };
  return { DB, ADMIN_KEY: secrets.admin, USER_KEY: secrets.user, ENCRYPTION_KEY: secrets.encryption, sqlite };
}

function request(env, path, { method = 'GET', body, token, origin = ORIGIN, headers = {} } = {}) {
  return handleRequest(new Request(ORIGIN + path, {
    method,
    headers: {
      Origin: origin,
      ...(body !== undefined ? { 'Content-Type': 'application/json' } : {}),
      ...(token ? { Cookie: 'gh_access_session=' + token } : {}),
      ...headers,
    },
    ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
  }), env);
}

async function token(role = 'admin') { return createSession(role, secrets); }

test('三行解析：BOM、换行、空行及密码首尾字符保真', () => {
  const parsed = parseImport('\uFEFF\r\nAlice\r\n  a password  \r\n' + SEED + '\r\n\r\nBob\r\npass\r\n' + SEED);
  assert.equal(parsed.length, 2);
  assert.deepEqual(parsed[0], { username: 'Alice', password: '  a password  ', secret: SEED });
  assert.equal(parseImport('Alice\npw\n' + SEED + '\nBob\npw\n' + SEED).length, 2);
  assert.equal(parseImport('Alice\npw\n' + SEED.toLowerCase()).at(0).secret, SEED);
});

test('三行解析：拒绝残缺、验证码、重复账号、过大输入和超量记录', () => {
  assert.throws(() => parseImport(''), /至少一条/);
  assert.throws(() => parseImport('Alice\npw'), /不完整/);
  assert.throws(() => parseImport('Alice\n\n' + SEED), /不完整/);
  assert.throws(() => parseImport('Alice\npw\n123456'), /种子无效/);
  assert.throws(() => parseImport('<script>\npw\n' + SEED), /账号格式/);
  assert.throws(() => parseImport('Alice\npw\n' + SEED + '\nalice\npw\n' + SEED), /重复账号/);
  assert.throws(() => parseImport('a'.repeat(CONFIG.MAX_IMPORT_BYTES + 1)), /过大/);
  assert.throws(() => parseImport(Array.from({ length: 101 }, (_, i) => 'user' + i + '\npw\n' + SEED).join('\n')), /最多导入/);
  assert.throws(() => decodeTotpSecret('ABC'), /length/);
  assert.throws(() => decodeTotpSecret('JBSWY3DPEHPK3PXQZ'), /length/);
  assert.throws(() => decodeTotpSecret('JBSWY3DPEHPK3PXP='), /padding/);
});

test('TOTP 符合 RFC 6238 的六组 SHA-1 标准向量', async () => {
  const vectors = [[59, '94287082'], [1111111109, '07081804'], [1111111111, '14050471'],
    [1234567890, '89005924'], [2000000000, '69279037'], [20000000000, '65353130']];
  for (const [seconds, expected] of vectors) {
    assert.equal(await generateTotp(SEED, seconds * 1000, 8), expected);
    assert.equal(await generateTotp(SEED, seconds * 1000), expected.slice(-6));
  }
});

test('AES-GCM 随机 IV、解密往返和字段绑定', async () => {
  const value = '  密码 with spaces  ';
  const encrypted = await encryptValue(value, secrets.encryption, 'alice:password');
  assert.equal(await decryptValue(encrypted, secrets.encryption, 'alice:password'), value);
  assert.notEqual(encrypted, await encryptValue(value, secrets.encryption, 'alice:password'));
  assert.ok(!encrypted.includes(value));
  await assert.rejects(() => decryptValue(encrypted, secrets.encryption, 'bob:password'));
  await assert.rejects(() => decryptValue(encrypted, Buffer.alloc(32, 8).toString('base64'), 'alice:password'));
});

test('两种角色默认七天登录，到期、篡改、角色伪造和密钥轮换均失效', async () => {
  const now = 1800000000000;
  for (const role of ['admin', 'user']) {
    const value = await createSession(role, secrets, now);
    const session = await verifySession(value, secrets, now);
    assert.equal(session.role, role);
    assert.equal(session.exp - session.iat, 7 * 86400);
    assert.ok(await verifySession(value, secrets, now + 7 * 86400000 - 1000));
    assert.equal(await verifySession(value, secrets, now + 7 * 86400000), null);
    assert.equal(await verifySession(value + 'x', secrets, now), null);
    assert.equal(await verifySession(value, { ...secrets, [role]: 'rotated'.repeat(8) }, now), null);
  }
  const forged = await createSession('admin', { ...secrets, admin: secrets.user }, now);
  assert.equal(await verifySession(forged, secrets, now), null);
  assert.equal(await verifySession('nonsense', secrets, now), null);
});

test('顶部变量可分别配置两种角色的登录时长', async () => {
  const customized = source.replace('ADMIN_SESSION_DAYS: 7', 'ADMIN_SESSION_DAYS: 1')
    .replace('USER_SESSION_DAYS: 7', 'USER_SESSION_DAYS: 3');
  const module = await import('data:text/javascript;base64,' + Buffer.from(customized).toString('base64'));
  const now = 1800000000000;
  for (const [role, days] of [['admin', 1], ['user', 3]]) {
    const value = await module.createSession(role, secrets, now);
    assert.equal((await module.verifySession(value, secrets, now)).exp - now / 1000, days * 86400);
    assert.equal(await module.verifySession(value, secrets, now + days * 86400000), null);
  }
});

test('页面包含 CSP nonce，所有响应禁用缓存和框架嵌入', async (t) => {
  const env = environment(t);
  const response = await request(env, '/');
  const html = await response.text();
  assert.equal(response.status, 200);
  const nonce = /<script nonce="([^"]+)">/.exec(html)[1];
  assert.ok(response.headers.get('Content-Security-Policy').includes("script-src 'nonce-" + nonce + "'"));
  assert.ok(!html.includes('__PUBLIC_CONFIG__'));
  assert.ok(!html.includes('__NONCE__'));
  assert.equal(response.headers.get('Cache-Control'), 'no-store');
  assert.equal(response.headers.get('X-Frame-Options'), 'DENY');
  const script = /<script nonce="[^"]+">([\s\S]*?)<\/script>/.exec(html)[1];
  assert.doesNotThrow(() => new Function(script));
});

test('登录签发安全 Cookie，退出清除；错误密钥限速', async (t) => {
  const env = environment(t);
  const success = await request(env, '/api/login', { method: 'POST', body: { role: 'admin', key: secrets.admin } });
  assert.equal(success.status, 200);
  const setCookie = success.headers.get('Set-Cookie');
  for (const flag of ['HttpOnly', 'Secure', 'SameSite=Strict', 'Max-Age=604800']) assert.ok(setCookie.includes(flag));
  const value = setCookie.split(';')[0].slice('gh_access_session='.length);
  assert.equal((await request(env, '/api/session', { token: value })).status, 200);
  const logout = await request(env, '/api/logout', { method: 'POST' });
  assert.ok(logout.headers.get('Set-Cookie').includes('Max-Age=0'));
  for (let index = 0; index < CONFIG.LOGIN_ATTEMPTS; index++) {
    assert.equal((await request(env, '/api/login', { method: 'POST', body: { role: 'user', key: 'wrong' } })).status, 401);
  }
  assert.equal((await request(env, '/api/login', { method: 'POST', body: { role: 'user', key: secrets.user } })).status, 429);
  const row = env.sqlite.prepare('SELECT bucket FROM login_attempts LIMIT 1').get();
  assert.ok(!row.bucket.includes('local'));
});

test('鉴权边界：未登录、跨站、用户越权及配置缺失', async (t) => {
  const env = environment(t);
  const user = await token('user');
  assert.equal((await request(env, '/api/accounts')).status, 401);
  assert.equal((await request(env, '/api/login', { method: 'POST', origin: 'https://evil.example', body: {} })).status, 403);
  assert.equal((await request(env, '/api/accounts', { token: user, headers: { 'Sec-Fetch-Site': 'cross-site' } })).status, 403);
  for (const [path, method] of [['/api/accounts/import', 'POST'], ['/api/accounts/1/extend', 'POST'], ['/api/accounts/1', 'DELETE']]) {
    assert.equal((await request(env, path, { method, token: user, body: {} })).status, 403);
  }
  assert.equal((await request({ ...env, ENCRYPTION_KEY: 'invalid' }, '/api/accounts')).status, 503);
  assert.equal((await request({ ...env, USER_KEY: env.ADMIN_KEY }, '/api/accounts')).status, 503);
  assert.equal((await request(env, '/api/login', { method: 'POST', body: { role: '__proto__', key: 'x' } })).status, 400);
});

test('导入、加密落库、稳定编号、重复拒绝和按日期倒序', async (t) => {
  const env = environment(t); const admin = await token();
  let response = await request(env, '/api/accounts/import', {
    method: 'POST', token: admin, body: { text: 'Alice\n  password  \n' + SEED + '\n\nBob\npw\n' + SEED },
  });
  assert.equal(response.status, 201);
  assert.equal((await response.json()).count, 2);
  const row = env.sqlite.prepare('SELECT * FROM accounts WHERE username = ?').get('alice');
  assert.notEqual(row.password_enc, '  password  ');
  assert.notEqual(row.totp_enc, SEED);
  const list = await (await request(env, '/api/accounts', { token: await token('user') })).json();
  assert.deepEqual(list.accounts.map((account) => account.username), ['Alice', 'Bob']);
  assert.deepEqual(list.accounts.map((account) => account.sequence), [1, 2]);
  assert.equal(list.accounts[0].password, '  password  ');
  assert.ok(!JSON.stringify(list).includes(SEED));
  response = await request(env, '/api/accounts/import', {
    method: 'POST', token: admin, body: { text: 'Fresh\npw\n' + SEED + '\nalice\npw\n' + SEED },
  });
  assert.equal(response.status, 409);
  assert.equal(env.sqlite.prepare('SELECT COUNT(*) AS n FROM accounts').get().n, 2);
  env.sqlite.prepare("UPDATE accounts SET created_day = '2020-01-01' WHERE username = 'Alice'").run();
  const sorted = await (await request(env, '/api/accounts', { token: admin })).json();
  assert.deepEqual(sorted.accounts.map((account) => account.username), ['Bob', 'Alice']);
  assert.equal(sorted.accounts[1].sequence, 1);
});

test('并发重复撞唯一约束时，整批插入确实回滚', async (t) => {
  const env = environment(t); const admin = await token();
  const batch = env.DB.batch.bind(env.DB);
  env.DB.batch = async (statements) => {
    env.sqlite.prepare(`INSERT INTO accounts (username, password_enc, totp_enc, created_at, created_day, day_sequence, expires_at)
      VALUES ('Racer', 'encrypted', 'encrypted', 0, '2000-01-01', 1, 0)`).run();
    return batch(statements);
  };
  const response = await request(env, '/api/accounts/import', {
    method: 'POST', token: admin, body: { text: 'Fresh\npw\n' + SEED + '\nRacer\npw\n' + SEED },
  });
  assert.equal(response.status, 409);
  assert.deepEqual(env.sqlite.prepare('SELECT username FROM accounts').all().map((row) => row.username), ['Racer']);
});

test('到期保留账密但停止验证码；延期始终从当前时间起算', async (t) => {
  const env = environment(t); const admin = await token(); const user = await token('user');
  assert.equal((await request(env, '/api/accounts/import', {
    method: 'POST', token: admin, body: { text: 'Alice\npw\n' + SEED, durationHours: 1 },
  })).status, 201);
  const id = env.sqlite.prepare('SELECT id FROM accounts').get().id;
  let response = await request(env, '/api/codes', { method: 'POST', token: user, body: { ids: [id] } });
  let data = await response.json();
  assert.match(data.codes[0].code, /^\d{6}$/);
  assert.ok(data.codes[0].validUntil > data.serverNow);
  env.sqlite.prepare('UPDATE accounts SET expires_at = ? WHERE id = ?').run(Date.now() - 1, id);
  data = await (await request(env, '/api/codes', { method: 'POST', token: user, body: { ids: [id] } })).json();
  assert.deepEqual(data.codes, []);
  data = await (await request(env, '/api/accounts', { token: user })).json();
  assert.equal(data.accounts[0].password, 'pw');
  const now = Date.now(); t.mock.method(Date, 'now', () => now);
  for (let index = 0; index < 2; index++) {
    data = await (await request(env, '/api/accounts/' + id + '/extend', { method: 'POST', token: admin })).json();
    assert.equal(data.expiresAt, now + 2 * 3600000);
  }
  data = await (await request(env, '/api/codes', { method: 'POST', token: user, body: { ids: [id] } })).json();
  assert.equal(data.codes.length, 1);
  assert.equal((await request(env, '/api/accounts/' + id, { method: 'DELETE', token: admin })).status, 200);
  assert.equal((await request(env, '/api/accounts/' + id + '/extend', { method: 'POST', token: admin })).status, 404);
});

test('输入边界：时长、验证码批次、请求体与接口路径', async (t) => {
  const env = environment(t); const admin = await token();
  for (const hours of [0, -1, '2', CONFIG.MAX_ACCOUNT_HOURS + 1]) {
    assert.equal((await request(env, '/api/accounts/import', {
      method: 'POST', token: admin, body: { text: 'Alice\npw\n' + SEED, durationHours: hours },
    })).status, 400);
  }
  for (const ids of [[-1], ['1'], [1.5], Array.from({ length: 101 }, (_, index) => index + 1)]) {
    assert.equal((await request(env, '/api/codes', { method: 'POST', token: admin, body: { ids } })).status, 400);
  }
  const empty = await (await request(env, '/api/codes', { method: 'POST', token: admin, body: { ids: [] } })).json();
  assert.deepEqual(empty.codes, []);
  assert.equal((await request(env, '/api/codes', { method: 'POST', token: admin, body: { ids: Array.from({ length: 100 }, (_, i) => i + 1) } })).status, 200);
  assert.equal((await request(env, '/api/login', { method: 'POST', body: { key: 'x'.repeat(CONFIG.MAX_REQUEST_BYTES) } })).status, 413);
  const malformed = await handleRequest(new Request(ORIGIN + '/api/login', {
    method: 'POST', headers: { Origin: ORIGIN, 'Content-Type': 'application/json' }, body: '{bad',
  }), env);
  assert.equal(malformed.status, 400);
  assert.equal((await request(env, '/api/login', { method: 'POST' })).status, 415);
  assert.equal((await request(env, '/unknown')).status, 404);
});
