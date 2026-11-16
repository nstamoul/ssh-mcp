import test from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { RealmCredentials, certValidUntil, findRealmHost, loadRealms, realmSshOptions } from '../realm.mjs';

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
  assert.deepEqual(realm.hosts[1], { alias: 'pve', hostname: '10.0.0.5', user: 'root', port: 2222 });
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
  assert.equal(findRealmHost(realms, 'media-ai'), null);
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
    if (path === 'ssh-user-ca/sign/mcp-homelab') {
      if (init.headers['X-Vault-Token'] !== 'tok') return reply(403, {});
      const pub = join(dir, 'request.pub');
      writeFileSync(pub, `${body.public_key}\n`);
      execFileSync('ssh-keygen', ['-q', '-s', ca, '-I', 'test', '-n', body.valid_principals, '-V', `-1m:+${ttlSeconds}s`, pub]);
      return reply(200, { data: { signed_key: readFileSync(join(dir, 'request-cert.pub'), 'utf8') } });
    }
    return reply(404, {});
  };
  return { fetchImpl, calls };
}

function credentialsFor(dir, fetchImpl, options = {}) {
  const auth = join(dir, 'auth');
  mkdirSync(auth, { recursive: true });
  writeFileSync(join(auth, 'role_id'), 'rid\n');
  writeFileSync(join(auth, 'secret_id'), options.secretId ?? 'sid\n');
  const realm = { name: 'homelab', vault: 'https://vault.example', signPath: 'ssh-user-ca/sign/mcp-homelab', principal: 'mcp-homelab', ttl: '4h', approleDir: auth, hosts: [] };
  return new RealmCredentials(realm, { stateDir: join(dir, 'state'), fetchImpl, ...options });
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
