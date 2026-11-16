import test from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, writeFileSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import {
  assertSafeTarget,
  classifySshFailure,
  ensureKnownHosts,
  fingerprintsOf,
  removeHosts,
  replaceHostKeyInFile,
  sshOptions,
} from '../ssh-exec.mjs';

const CHANGED = `@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@    WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!     @
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
IT IS POSSIBLE THAT SOMEONE IS DOING SOMETHING NASTY!
The fingerprint for the ED25519 key sent by the remote host is
SHA256:abcDEF123+/xyz.
Please contact your system administrator.
Offending ED25519 key in /home/mcp/.ssh-mcp/known_hosts:12
Host key verification failed.`;

function newKey(dir, name) {
  const path = join(dir, name);
  execFileSync('ssh-keygen', ['-q', '-t', 'ed25519', '-N', '', '-C', '', '-f', path]);
  return readFileSync(`${path}.pub`, 'utf8').trim().split(' ').slice(0, 2).join(' ');
}

test('sshOptions never prompts, accepts new keys and uses the MCP known_hosts', () => {
  const opts = sshOptions('/state/known_hosts');
  const pairs = opts.filter((_, i) => i % 2 === 1);
  assert.ok(opts.filter((_, i) => i % 2 === 0).every((flag) => flag === '-o'));
  assert.ok(pairs.includes('BatchMode=yes'));
  assert.ok(pairs.includes('StrictHostKeyChecking=accept-new'));
  assert.ok(pairs.includes('UserKnownHostsFile=/state/known_hosts'));
});

test('assertSafeTarget rejects option injection and empty aliases', () => {
  assert.throws(() => assertSafeTarget('-oProxyCommand=id'), /Invalid host/);
  assert.throws(() => assertSafeTarget(''), /Invalid host/);
  assert.throws(() => assertSafeTarget('host name'), /Invalid host/);
  assert.equal(assertSafeTarget('nstam@10.64.110.222'), 'nstam@10.64.110.222');
  assert.equal(assertSafeTarget('docker-core'), 'docker-core');
});

test('a remote command that exits non-zero is not an ssh failure', () => {
  assert.equal(classifySshFailure({ code: 3 }, 'grep: nope'), null);
});

test('classifies a changed host key and extracts the presented fingerprint', () => {
  const failure = classifySshFailure({ code: 255 }, CHANGED);
  assert.equal(failure.kind, 'host_key_changed');
  assert.equal(failure.presentedFingerprint, 'SHA256:abcDEF123+/xyz');
  assert.equal(failure.keyType, 'ED25519');
  assert.match(failure.hint, /replaceHostKey/);
});

test('classifies the common connection failures', () => {
  const kind = (stderr, error = { code: 255 }) => classifySshFailure(error, stderr).kind;
  assert.equal(kind('nstam@host: Permission denied (publickey,password).'), 'auth_failed');
  assert.equal(kind('ssh: connect to host 10.0.0.1 port 22: Connection timed out'), 'no_route');
  assert.equal(kind('ssh: Could not resolve hostname nope: Name does not resolve'), 'no_route');
  assert.equal(kind('homelab-connect: no route to 10.64.1.1:22 (direct, tailnet, 443 and 2222 all failed)'), 'no_route');
  assert.equal(kind('vault-ssh: Vault request rejected (HTTP 403); run login'), 'vault_denied');
  assert.equal(kind('Host key verification failed.'), 'host_key_unknown');
  assert.equal(kind('ssh: connect to host 192.168.1.72 port 22: Host is unreachable'), 'no_route');
  assert.equal(kind('Cannot execute command-line and remote command.'), 'client_setup');
  assert.equal(kind("env: can't execute 'python3': No such file or directory\nbanner exchange: Connection to UNKNOWN port 65535: Broken pipe"), 'client_setup');
  assert.equal(kind('', { killed: true, signal: 'SIGTERM' }), 'timeout');
  assert.equal(kind('something odd'), 'ssh_error');
});

test('ensureKnownHosts seeds the MCP file once from the mounted known_hosts', () => {
  const dir = mkdtempSync(join(tmpdir(), 'sshmcp-'));
  const seed = join(dir, 'seed');
  writeFileSync(seed, 'host-a ssh-ed25519 AAAA\n');
  const state = join(dir, 'state', 'known_hosts');
  ensureKnownHosts(state, seed);
  assert.equal(readFileSync(state, 'utf8'), 'host-a ssh-ed25519 AAAA\n');
  writeFileSync(state, 'changed\n');
  ensureKnownHosts(state, seed);
  assert.equal(readFileSync(state, 'utf8'), 'changed\n', 'an existing file is never reseeded');
  const empty = join(dir, 'state2', 'known_hosts');
  ensureKnownHosts(empty, join(dir, 'missing'));
  assert.ok(existsSync(empty));
});

test('replaceHostKeyInFile replaces only when the confirmed fingerprint matches', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'sshmcp-'));
  const oldKey = newKey(dir, 'old');
  const newK = newKey(dir, 'new');
  const other = newKey(dir, 'other');
  const state = join(dir, 'known_hosts');
  // The owner's real known_hosts has a malformed line; replacement must survive it.
  writeFileSync(state, `10.9.9.9 ${oldKey}\nthis line is broken\nkeep.example ${other}\n`);
  const scanned = `10.9.9.9 ${newK}\n`;
  const [{ fingerprint }] = await fingerprintsOf(scanned);
  assert.match(fingerprint, /^SHA256:/);

  const refused = await replaceHostKeyInFile(state, scanned, 'SHA256:not-the-one');
  assert.equal(refused.replaced, false);
  assert.equal(refused.presented[0].fingerprint, fingerprint);
  assert.ok(readFileSync(state, 'utf8').includes(oldKey), 'file untouched on mismatch');

  const missing = await replaceHostKeyInFile(state, scanned, undefined);
  assert.equal(missing.replaced, false);

  const done = await replaceHostKeyInFile(state, scanned, fingerprint);
  assert.equal(done.replaced, true);
  const after = readFileSync(state, 'utf8');
  assert.ok(!after.includes(oldKey));
  assert.ok(after.includes(`10.9.9.9 ${newK}`));
  assert.ok(after.includes(`keep.example ${other}`), 'other hosts are kept');
  assert.ok(after.includes('this line is broken'), 'malformed lines are left alone');
  assert.ok(readFileSync(`${state}.old`, 'utf8').includes(oldKey), 'previous file is kept as .old');
});

test('removeHosts handles plain, shared, hashed and special lines', () => {
  const dir = mkdtempSync(join(tmpdir(), 'sshmcp-'));
  const key = newKey(dir, 'k');
  const hashedFile = join(dir, 'hashed');
  writeFileSync(hashedFile, `secret.example ${key}\n`);
  execFileSync('ssh-keygen', ['-H', '-f', hashedFile], { stdio: 'ignore' });
  const hashed = readFileSync(hashedFile, 'utf8').trim();
  assert.ok(hashed.startsWith('|1|'));
  const text = [
    `gone.example ${key}`,
    `gone.example,10.1.1.1 ${key}`,
    `[gone.example]:2222 ${key}`,
    hashed,
    `@cert-authority *.example ${key}`,
    '# comment',
    'broken',
  ].join('\n');
  const out = removeHosts(text, ['gone.example', 'secret.example']).split('\n');
  assert.deepEqual(out, [
    `10.1.1.1 ${key}`,
    `[gone.example]:2222 ${key}`,
    `@cert-authority *.example ${key}`,
    '# comment',
    'broken',
  ]);
});
