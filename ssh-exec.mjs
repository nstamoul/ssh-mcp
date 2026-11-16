/**
 * How the MCP invokes ssh/scp: never prompt, trust a host on first contact,
 * refuse a changed host key until the caller confirms the new fingerprint,
 * and say why a connection failed.
 *
 * The MCP keeps its own writable known_hosts (the mounted ~/.ssh is read-only
 * and belongs to someone else). It is seeded once from ~/.ssh/known_hosts.
 */
import { execFile } from 'node:child_process';
import { createHmac } from 'node:crypto';
import { copyFileSync, existsSync, mkdirSync, mkdtempSync, readFileSync, renameSync, rmSync, writeFileSync } from 'node:fs';
import { homedir, tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { promisify } from 'node:util';

const execFileAsync = promisify(execFile);

export const STATE_DIR = process.env.MCP_SSH_STATE_DIR || join(homedir(), '.ssh-mcp');
export const KNOWN_HOSTS = join(STATE_DIR, 'known_hosts');
const CONNECT_TIMEOUT = process.env.MCP_SSH_CONNECT_TIMEOUT || '20';

export function sshOptions(knownHosts = KNOWN_HOSTS) {
  return [
    '-o', 'BatchMode=yes',
    '-o', 'StrictHostKeyChecking=accept-new',
    '-o', `UserKnownHostsFile=${knownHosts}`,
    '-o', `ConnectTimeout=${CONNECT_TIMEOUT}`,
  ];
}

/** A host argument must not be able to turn into an ssh option. */
export function assertSafeTarget(hostAlias) {
  if (typeof hostAlias !== 'string' || !/^[A-Za-z0-9_.@:\[\]%][A-Za-z0-9_.@:\[\]%-]*$/.test(hostAlias)) {
    throw new Error(`Invalid host alias: ${JSON.stringify(hostAlias)}`);
  }
  return hostAlias;
}

export function ensureKnownHosts(knownHosts = KNOWN_HOSTS, seed = join(homedir(), '.ssh', 'known_hosts')) {
  if (existsSync(knownHosts)) return;
  mkdirSync(dirname(knownHosts), { recursive: true, mode: 0o700 });
  try {
    copyFileSync(seed, knownHosts);
  } catch {
    writeFileSync(knownHosts, '');
  }
}

/**
 * Explain an ssh/scp failure. Returns null when ssh itself worked and the
 * remote command merely exited non-zero (ssh reserves 255 for its own errors).
 */
export function classifySshFailure(error, stderr = '') {
  if (error?.killed) {
    return { kind: 'timeout', message: 'The command did not finish within the time limit.' };
  }
  if (typeof error?.code === 'number' && error.code !== 255) return null;

  if (/REMOTE HOST IDENTIFICATION HAS CHANGED/.test(stderr)) {
    const sent = stderr.match(/fingerprint for the (\S+) key sent by the remote host is\s+(SHA256:[A-Za-z0-9+/=]+)/);
    return {
      kind: 'host_key_changed',
      message: 'The host presented a different key than the one on record. Nothing was executed.',
      keyType: sent?.[1],
      presentedFingerprint: sent?.[2],
      hint: 'Tell the user the presented fingerprint. Only if they confirm it is expected (for example the host was reinstalled), call replaceHostKey with this hostAlias and that fingerprint.',
    };
  }
  const table = [
    [/vault-ssh:/, 'vault_denied', 'Vault did not issue an SSH certificate for this host.'],
    [/can't execute|exec: .*not found|Bad configuration option|Cannot execute command-line and remote command/, 'client_setup', "This host's ssh config cannot be used by the MCP as it is."],
    [/Permission denied|Too many authentication failures/, 'auth_failed', 'The host refused the credentials.'],
    [/Host key verification failed/, 'host_key_unknown', 'The host key could not be verified.'],
    [/Connection timed out|Connection refused|No route to host|Host is unreachable|Operation timed out|Could not resolve hostname|Name does not resolve|Temporary failure in name resolution|Network is unreachable|homelab-connect: no route|banner exchange|Connection closed by/, 'no_route', 'The host could not be reached.'],
  ];
  for (const [pattern, kind, message] of table) {
    if (pattern.test(stderr)) return { kind, message };
  }
  return { kind: 'ssh_error', message: 'ssh failed; see stderr.' };
}

/** Fingerprints of known_hosts-format lines: [{ names, keyType, fingerprint }]. */
export async function fingerprintsOf(knownHostsText) {
  const lines = knownHostsText.split('\n').filter((line) => line.trim() && !line.startsWith('#'));
  if (!lines.length) return [];
  const dir = mkdtempSync(join(tmpdir(), 'sshmcp-fp-'));
  try {
    const out = [];
    for (const line of lines) {
      const file = join(dir, 'line');
      writeFileSync(file, `${line}\n`);
      const { stdout } = await execFileAsync('ssh-keygen', ['-l', '-f', file]);
      const match = stdout.match(/(SHA256:\S+).*\((\S+)\)\s*$/m);
      if (match) out.push({ names: line.split(/\s+/)[0].split(','), keyType: match[2], fingerprint: match[1] });
    }
    return out;
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

/** What is on record for a host name, as fingerprints. */
export async function knownFingerprints(name, knownHosts = KNOWN_HOSTS) {
  try {
    const { stdout } = await execFileAsync('ssh-keygen', ['-l', '-F', name, '-f', knownHosts]);
    return [...stdout.matchAll(/^\S+ (\S+) (SHA256:\S+)/gm)].map((m) => ({ keyType: m[1], fingerprint: m[2] }));
  } catch {
    return [];
  }
}

/**
 * Ask the host for its current key over the same route ssh would use
 * (config, ProxyCommand, HostKeyAlias), without authenticating and without
 * touching the real known_hosts. Returns known_hosts-format text.
 */
export async function scanHostKey(hostAlias, extraOpts = []) {
  assertSafeTarget(hostAlias);
  const dir = mkdtempSync(join(tmpdir(), 'sshmcp-scan-'));
  const file = join(dir, 'known_hosts');
  let stderr = '';
  try {
    await execFileAsync('ssh', [
      '-o', 'BatchMode=yes',
      '-o', 'StrictHostKeyChecking=no',
      '-o', `UserKnownHostsFile=${file}`,
      '-o', 'GlobalKnownHostsFile=/dev/null',
      '-o', 'HashKnownHosts=no',
      '-o', 'UpdateHostKeys=no',
      '-o', 'PreferredAuthentications=none',
      '-o', `ConnectTimeout=${CONNECT_TIMEOUT}`,
      ...extraOpts,
      '--', hostAlias, 'true',
    ], { timeout: 45000 });
  } catch (error) {
    stderr = error.stderr || error.message; // authentication is expected to fail
  }
  try {
    const scanned = existsSync(file) ? readFileSync(file, 'utf8') : '';
    return { scanned, stderr };
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

/**
 * Drop every entry for the given host names from known_hosts text. Done here
 * rather than with `ssh-keygen -R`, which refuses to touch a file that has
 * even one malformed line. Unparseable lines, @cert-authority lines and
 * wildcard patterns are kept as they are.
 */
export function removeHosts(text, names) {
  const wanted = new Set(names);
  const matches = (pattern) => {
    if (pattern.startsWith('|1|')) {
      const [, , salt, hash] = pattern.split('|');
      return names.some((n) => createHmac('sha1', Buffer.from(salt, 'base64')).update(n).digest('base64') === hash);
    }
    return wanted.has(pattern);
  };
  return text.split('\n').flatMap((line) => {
    const fields = line.trim().split(/\s+/);
    if (!line.trim() || line.startsWith('#') || line.startsWith('@') || fields.length < 3) return [line];
    const patterns = fields[0].split(',');
    const rest = patterns.filter((p) => !matches(p));
    if (rest.length === patterns.length) return [line];
    return rest.length ? [[rest.join(','), ...fields.slice(1)].join(' ')] : [];
  }).join('\n');
}

/**
 * Replace the recorded key(s) of the scanned host, but only when the caller
 * hands back a fingerprint the host actually presented.
 */
export async function replaceHostKeyInFile(knownHosts, scanned, confirmedFingerprint) {
  const presented = await fingerprintsOf(scanned);
  const names = [...new Set(presented.flatMap((p) => p.names))];
  const known = (await Promise.all(names.map((n) => knownFingerprints(n, knownHosts)))).flat();
  const view = presented.map(({ keyType, fingerprint }) => ({ keyType, fingerprint }));
  if (!presented.some((p) => p.fingerprint === confirmedFingerprint)) {
    return {
      replaced: false,
      presented: view,
      known,
      message: 'The fingerprint given does not match what the host presents now. Nothing was changed.',
    };
  }
  const current = readFileSync(knownHosts, 'utf8');
  const kept = removeHosts(current, names);
  writeFileSync(`${knownHosts}.old`, current, { mode: 0o600 });
  const next = `${knownHosts}.new`;
  writeFileSync(next, `${kept}${kept && !kept.endsWith('\n') ? '\n' : ''}${scanned.trimEnd()}\n`, { mode: 0o600 });
  renameSync(next, knownHosts);
  return { replaced: true, presented: view, previous: known };
}

export async function replaceHostKey(hostAlias, confirmedFingerprint, { knownHosts = KNOWN_HOSTS, target = hostAlias, opts = [] } = {}) {
  ensureKnownHosts(knownHosts);
  const { scanned, stderr } = await scanHostKey(target, opts);
  if (!scanned.trim()) {
    return { replaced: false, error: classifySshFailure({ code: 255 }, stderr), stderr };
  }
  return replaceHostKeyInFile(knownHosts, scanned, confirmedFingerprint);
}
