import test from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { RealmCredentials, certValidUntil, findRealmHost, loadRealms, normalizeHost, realmSshOptions } from '../realm.mjs';

function realmsFile(dir, value) {
  const file = join(dir, 'realms.json');
  writeFileSync(file, JSON.stringify(value));
  return file;
}

const HOMELAB = {
  homelab: {
    vault: 'https://vault.example/',
    signPath: 'ssh-user-ca/sign/mcp-homelab',
    principal: 'mcp-homelab',
    hosts: {
      thanos: { hostname: '10.0.0.7', user: 'nstam' },
      pve: { hostname: '10.0.0.5', user: 'root', port: 2222 },
      'media-ai': { hostname: '10.0.0.4', user: 'root', auth: 'key' },
    },
  },
};

test('loadRealms reads hosts and applies per-host overrides', () => {
  const dir = mkdtempSync(join(tmpdir(), 'realm-'));
  const [realm] = loadRealms(realmsFile(dir, HOMELAB), {
    MCP_SSH_HOMELAB_VAULT_ADDR: 'http://vault:8200',
    MCP_SSH_HOMELAB_APPROLE_DIR: '/auth/homelab',
  });
  assert.equal(realm.vault, 'http://vault:8200');
  assert.equal(realm.approleDir, '/auth/homelab');
  assert.equal(realm.ttl, '4h');
  assert.deepEqual(realm.hosts[1], { alias: 'pve', hostname: '10.0.0.5', user: 'root', port: 2222, auth: 'certificate' });
  assert.equal(realm.hosts[2].auth, 'key');
  const [plain] = loadRealms(realmsFile(dir, HOMELAB), {});
  assert.equal(plain.vault, 'https://vault.example');
  assert.equal(plain.approleDir, '/run/ssh-mcp/homelab');
  assert.deepEqual(loadRealms(join(dir, 'missing.json')), []);
});

test('findRealmHost matches alias or address, nothing else', () => {
  const dir = mkdtempSync(join(tmpdir(), 'realm-'));
  const realms = loadRealms(realmsFile(dir, HOMELAB), {});
  assert.equal(findRealmHost(realms, 'thanos').host.hostname, '10.0.0.7');
  assert.equal(findRealmHost(realms, '10.0.0.5').host.alias, 'pve');
  assert.equal(findRealmHost(realms, 'root@10.0.0.5'), null);
  assert.equal(findRealmHost(realms, 'truenas'), null);
});

test('certValidUntil reads the end of validity as UTC', () => {
  assert.equal(certValidUntil('        Valid: from 2026-11-16T02:17:46 to 2026-11-16T10:18:16'), Date.UTC(2026, 10, 16, 10, 18, 16));
  assert.equal(certValidUntil('Valid: forever'), null);
  assert.equal(certValidUntil('Valid: from always to forever'), Infinity);
});

test('realmSshOptions ignores the mounted config and offers only the realm identity', () => {
  const host = { user: 'root', port: 22 };
  const opts = realmSshOptions(host, { key: '/k', cert: '/k-cert.pub' }, '/h/homelab-connect');
  assert.deepEqual(opts.slice(0, 2), ['-F', '/dev/null']);
  assert.ok(opts.includes('CertificateFile=/k-cert.pub'));
  assert.ok(opts.includes('IdentitiesOnly=yes'));
  assert.ok(opts.includes('ProxyCommand=/h/homelab-connect %h %p'));
  const scan = realmSshOptions(host, null, null);
  assert.ok(!scan.includes('-i'));
  assert.ok(!scan.some((o) => o.startsWith('ProxyCommand')));
});

function fakeVault(parent, { denyLogin = false, ttlSeconds = 4 * 3600 } = {}) {
  const dir = mkdtempSync(join(parent, 'vault-'));
  const ca = join(dir, 'ca');
  execFileSync('ssh-keygen', ['-q', '-t', 'ed25519', '-N', '', '-f', ca]);
  const calls = [];
  const kv = new Map();
  const fetchImpl = async (url, init) => {
    const path = url.replace(/^.*?\/v1\//, '');
    const body = init.body ? JSON.parse(init.body) : null;
    calls.push({ path, token: init.headers['X-Vault-Token'], body });
    const reply = (status, json) => ({ ok: status < 300, status, json: async () => json });
    if (path === 'auth/approle/login') {
      if (denyLogin || body.secret_id !== 'sid') return reply(400, { errors: ['invalid secret id'] });
      return reply(200, { auth: { client_token: 'tok' } });
    }
    if (path === 'auth/token/revoke-self') return reply(204, null);
    if (path.startsWith('secret/data/')) {
      if (init.headers['X-Vault-Token'] !== 'tok') return reply(403, {});
      const doc = kv.get(path);
      if (init.method === 'GET') {
        return doc ? reply(200, { data: { data: doc.data, metadata: { version: doc.version } } }) : reply(404, { errors: [] });
      }
      const current = doc ? doc.version : 0;
      if (body.options?.cas !== undefined && body.options.cas !== current) {
        return reply(400, { errors: ['check-and-set parameter did not match the current version'] });
      }
      kv.set(path, { data: body.data, version: current + 1 });
      return reply(200, { data: { version: current + 1 } });
    }
    if (path === 'ssh-user-ca/sign/mcp-homelab') {
      if (init.headers['X-Vault-Token'] !== 'tok') return reply(403, {});
      const pub = join(dir, 'request.pub');
      writeFileSync(pub, `${body.public_key}\n`);
      execFileSync('ssh-keygen', ['-q', '-s', ca, '-I', 'test', '-n', body.valid_principals, '-V', `-1m:+${ttlSeconds}s`, pub]);
      return reply(200, { data: { signed_key: readFileSync(join(dir, 'request-cert.pub'), 'utf8') } });
    }
    return reply(404, {});
  };
  return { fetchImpl, calls, kv };
}

function credentialsFor(dir, fetchImpl, options = {}) {
  const auth = join(dir, 'auth');
  mkdirSync(auth, { recursive: true });
  writeFileSync(join(auth, 'role_id'), 'rid\n');
  writeFileSync(join(auth, 'secret_id'), options.secretId ?? 'sid\n');
  const realm = {
    name: 'homelab', vault: 'https://vault.example', signPath: 'ssh-user-ca/sign/mcp-homelab', principal: 'mcp-homelab', ttl: '4h', approleDir: auth, hosts: [],
    staticKeyPath: 'secret/data/homelab/ssh-mcp/static-key', adhocPath: 'secret/data/homelab/ssh-mcp/adhoc-hosts',
  };
  return new RealmCredentials(realm, { stateDir: join(dir, 'state'), keyDir: join(dir, 'shm'), fetchImpl, ...options });
}

test('issues a certificate once, reuses it, and renews near expiry', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'realm-'));
  const vault = fakeVault(dir);
  const creds = credentialsFor(dir, vault.fetchImpl);

  const first = await creds.ensureCertificate();
  assert.equal(first.renewed, true);
  const info = execFileSync('ssh-keygen', ['-L', '-f', first.cert], { encoding: 'utf8' });
  assert.match(info, /mcp-homelab/);
  const sign = vault.calls.find((c) => c.path.startsWith('ssh-user-ca/'));
  assert.equal(sign.body.valid_principals, 'mcp-homelab');
  assert.equal(sign.body.ttl, '4h');
  assert.ok(vault.calls.some((c) => c.path === 'auth/token/revoke-self'));

  const again = await creds.ensureCertificate();
  assert.equal(again.renewed, false, 'a valid certificate is reused');

  // 10 minutes before the 4h certificate ends: inside the 15 minute margin.
  const later = credentialsFor(dir, vault.fetchImpl, { now: () => Date.now() + (4 * 60 - 10) * 60 * 1000 });
  assert.equal((await later.ensureCertificate()).renewed, true, 'renewed inside the margin');
});

test('concurrent callers share one renewal', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'realm-'));
  const vault = fakeVault(dir);
  const creds = credentialsFor(dir, vault.fetchImpl);
  await Promise.all([creds.ensureCertificate(), creds.ensureCertificate(), creds.ensureCertificate()]);
  assert.equal(vault.calls.filter((c) => c.path === 'auth/approle/login').length, 1);
});

test('reports why a certificate could not be issued', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'realm-'));
  const denied = credentialsFor(dir, fakeVault(dir, { denyLogin: true }).fetchImpl);
  await assert.rejects(denied.ensureCertificate(), { kind: 'vault_denied', message: /AppRole login/ });

  const missing = credentialsFor(join(dir, 'b'), fakeVault(dir).fetchImpl, { secretId: '' });
  await assert.rejects(missing.ensureCertificate(), { kind: 'vault_setup' });

  const down = credentialsFor(join(dir, 'c'), async () => { throw Object.assign(new Error('fetch failed'), { cause: { code: 'ECONNREFUSED' } }); });
  await assert.rejects(down.ensureCertificate(), { kind: 'vault_unavailable', message: /ECONNREFUSED/ });

  const status = await down.status();
  assert.equal(status.approleConfigured, true);
  assert.equal(status.certificate.valid, false);
});

test('normalizeHost rejects entries that could turn into ssh options', () => {
  assert.throws(() => normalizeHost('-x', { hostname: 'h', user: 'u' }, 'r'), /invalid alias/);
  assert.throws(() => normalizeHost('a', { hostname: '-oProxyCommand=id', user: 'u' }, 'r'), /hostname/);
  assert.throws(() => normalizeHost('a', { hostname: 'h', user: '-l' }, 'r'), /user/);
  assert.throws(() => normalizeHost('a', { hostname: 'h', user: 'u', auth: 'password' }, 'r'), /auth/);
  assert.throws(() => normalizeHost('a', { hostname: 'h', user: 'u', port: 70000 }, 'r'), /port/);
  assert.deepEqual(normalizeHost('a', { hostname: 'h', user: 'u' }, 'r'), { alias: 'a', hostname: 'h', user: 'u', port: 22, auth: 'certificate' });
});

test('realmSshOptions without a certificate offers only the key', () => {
  const opts = realmSshOptions({ user: 'root', port: 22 }, { key: '/k', cert: null }, null);
  assert.ok(opts.includes('/k'));
  assert.ok(!opts.some((o) => o.startsWith('CertificateFile')));
});

test('the static key is fetched from Vault once and kept outside the state dir', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'realm-'));
  const vault = fakeVault(dir);
  const keyFile = join(dir, 'gen');
  execFileSync('ssh-keygen', ['-q', '-t', 'ed25519', '-N', '', '-f', keyFile]);
  vault.kv.set('secret/data/homelab/ssh-mcp/static-key', {
    version: 1,
    data: { private_key: readFileSync(keyFile, 'utf8'), public_key: readFileSync(`${keyFile}.pub`, 'utf8') },
  });
  const creds = credentialsFor(dir, vault.fetchImpl);
  const [a, b] = await Promise.all([creds.ensureStaticKey(), creds.ensureStaticKey()]);
  assert.equal(a.key, b.key);
  assert.ok(a.key.startsWith(join(dir, 'shm')));
  assert.equal(readFileSync(a.key, 'utf8').trim(), readFileSync(keyFile, 'utf8').trim());
  assert.equal(vault.calls.filter((c) => c.path === 'secret/data/homelab/ssh-mcp/static-key').length, 1);
  await creds.ensureStaticKey();
  assert.equal(vault.calls.filter((c) => c.path === 'secret/data/homelab/ssh-mcp/static-key').length, 1, 'cached after the first read');
  assert.match((await creds.status()).staticKey.publicKey, /^ssh-ed25519 /);

  const empty = credentialsFor(join(dir, 'x'), fakeVault(dir).fetchImpl);
  await assert.rejects(empty.ensureStaticKey(), { kind: 'vault_denied' });
});

test('ad-hoc hosts are shared through Vault with check-and-set', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'realm-'));
  const vault = fakeVault(dir);
  const one = credentialsFor(dir, vault.fetchImpl);
  const two = credentialsFor(dir, vault.fetchImpl);
  assert.deepEqual(await one.adhocHosts(), []);

  await one.updateAdhoc((hosts) => { hosts.box = { hostname: '10.0.0.9', user: 'root', auth: 'key' }; });
  await two.updateAdhoc((hosts) => { hosts.other = { hostname: '10.0.0.8', user: 'admin' }; });
  const seen = await one.adhocHosts({ fresh: true });
  assert.deepEqual(seen.map((h) => h.alias).sort(), ['box', 'other'], 'neither write is lost');
  assert.equal(seen.find((h) => h.alias === 'other').auth, 'certificate');

  // A concurrent write between read and write is retried, not overwritten.
  let raced = false;
  const racing = credentialsFor(dir, async (url, init) => {
    if (!raced && init.method === 'POST' && url.endsWith('adhoc-hosts')) {
      raced = true;
      await two.updateAdhoc((hosts) => { hosts.third = { hostname: '10.0.0.7', user: 'u' }; });
    }
    return vault.fetchImpl(url, init);
  });
  await racing.updateAdhoc((hosts) => { delete hosts.box; });
  const after = (await one.adhocHosts({ fresh: true })).map((h) => h.alias).sort();
  assert.deepEqual(after, ['other', 'third']);

  vault.kv.set('secret/data/homelab/ssh-mcp/adhoc-hosts', { version: 9, data: { hosts: { ok: { hostname: 'h', user: 'u' }, bad: { hostname: '-x', user: 'u' } } } });
  assert.deepEqual((await one.adhocHosts({ fresh: true })).map((h) => h.alias), ['ok'], 'a malformed entry is skipped');
});
