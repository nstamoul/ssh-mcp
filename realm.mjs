/**
 * Realms: groups of hosts that trust a Vault SSH CA. For a host in a realm the
 * MCP logs in with its own key and a short-lived certificate that it gets from
 * that realm's Vault through AppRole, instead of whatever key the mounted
 * ~/.ssh happens to hold.
 *
 * realms.json (mounted read-only, path in MCP_SSH_REALMS_FILE):
 *   {
 *     "homelab": {
 *       "vault": "https://vault.nstam.eu",
 *       "signPath": "ssh-user-ca/sign/mcp-homelab",
 *       "principal": "mcp-homelab",
 *       "ttl": "4h",
 *       "hosts": { "thanos": { "hostname": "10.64.110.227", "user": "nstam" } }
 *     }
 *   }
 * Per host the Vault address and AppRole directory can be overridden with
 * MCP_SSH_<REALM>_VAULT_ADDR and MCP_SSH_<REALM>_APPROLE_DIR. The AppRole
 * directory holds role_id and secret_id (default /run/ssh-mcp/<realm>).
 */
import { execFile } from 'node:child_process';
import { existsSync, mkdirSync, readFileSync, renameSync, rmSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { promisify } from 'node:util';

import { STATE_DIR } from './ssh-exec.mjs';

const run = promisify(execFile);

export const REALMS_FILE = process.env.MCP_SSH_REALMS_FILE || '/etc/ssh-mcp/realms.json';

export class RealmError extends Error {
  constructor(kind, message) {
    super(message);
    this.kind = kind;
  }
}

export function loadRealms(file = REALMS_FILE, env = process.env) {
  let raw;
  try {
    raw = JSON.parse(readFileSync(file, 'utf8'));
  } catch (error) {
    if (error.code === 'ENOENT') return [];
    throw new Error(`Cannot read realms file ${file}: ${error.message}`);
  }
  return Object.entries(raw).map(([name, realm]) => {
    const key = name.toUpperCase().replace(/[^A-Z0-9]/g, '_');
    const vault = env[`MCP_SSH_${key}_VAULT_ADDR`] || realm.vault;
    if (!vault || !realm.signPath || !realm.principal) {
      throw new Error(`Realm ${name} needs vault, signPath and principal`);
    }
    return {
      name,
      vault: vault.replace(/\/+$/, ''),
      signPath: realm.signPath,
      principal: realm.principal,
      ttl: realm.ttl || '4h',
      approleDir: env[`MCP_SSH_${key}_APPROLE_DIR`] || realm.approleDir || `/run/ssh-mcp/${name}`,
      hosts: Object.entries(realm.hosts || {}).map(([alias, host]) => ({
        alias,
        hostname: host.hostname,
        user: host.user,
        port: host.port || 22,
      })),
    };
  });
}

/** The realm host a tool argument names, by alias or address. */
export function findRealmHost(realms, target) {
  for (const realm of realms) {
    for (const host of realm.hosts) {
      if (host.alias === target || host.hostname === target) return { realm, host };
    }
  }
  return null;
}

/** End of validity (ms since epoch) from `ssh-keygen -L` output run with TZ=UTC. */
export function certValidUntil(text) {
  const match = text.match(/Valid: from \S+ to (\S+)/);
  if (!match) return null;
  if (match[1] === 'forever') return Infinity;
  const end = Date.parse(`${match[1]}Z`);
  return Number.isNaN(end) ? null : end;
}

const defaultProxy = () => {
  const helper = join(homedir(), '.ssh', 'homelab-connect');
  return existsSync(helper) ? helper : null;
};

/**
 * ssh options for a realm host. With -F /dev/null nothing from the mounted
 * config applies, so a personal certificate helper there cannot interfere.
 * Without credentials (host key scans) no identity is offered.
 */
export function realmSshOptions(host, credentials, proxyCommand = defaultProxy()) {
  const opts = ['-F', '/dev/null'];
  if (credentials) {
    opts.push('-i', credentials.key, '-o', `CertificateFile=${credentials.cert}`, '-o', 'IdentitiesOnly=yes');
  }
  opts.push('-o', `User=${host.user}`, '-o', `Port=${host.port}`, '-o', 'ServerAliveInterval=30');
  if (proxyCommand) opts.push('-o', `ProxyCommand=${proxyCommand} %h %p`);
  return opts;
}

export class RealmCredentials {
  constructor(realm, { stateDir = STATE_DIR, fetchImpl = globalThis.fetch, now = () => Date.now(), marginMs = 15 * 60 * 1000 } = {}) {
    this.realm = realm;
    this.fetch = fetchImpl;
    this.now = now;
    this.marginMs = marginMs;
    this.dir = join(stateDir, realm.name);
    this.key = join(this.dir, 'id_ed25519');
    this.cert = `${this.key}-cert.pub`;
    this.pending = null;
  }

  async ensureKey() {
    if (existsSync(this.key)) return;
    mkdirSync(this.dir, { recursive: true, mode: 0o700 });
    await run('ssh-keygen', ['-q', '-t', 'ed25519', '-N', '', '-C', `ssh-mcp-${this.realm.name}`, '-f', this.key]);
  }

  async validUntil(path = this.cert) {
    if (!existsSync(path)) return null;
    try {
      const { stdout } = await run('ssh-keygen', ['-L', '-f', path], { env: { ...process.env, TZ: 'UTC', LC_ALL: 'C' } });
      return certValidUntil(stdout);
    } catch {
      return null;
    }
  }

  approleFiles() {
    const read = (name) => {
      try {
        return readFileSync(join(this.realm.approleDir, name), 'utf8').trim();
      } catch {
        return '';
      }
    };
    return { role_id: read('role_id'), secret_id: read('secret_id') };
  }

  async status() {
    const until = await this.validUntil();
    const { role_id, secret_id } = this.approleFiles();
    return {
      realm: this.realm.name,
      vault: this.realm.vault,
      principal: this.realm.principal,
      hosts: this.realm.hosts.map((h) => h.alias),
      approleConfigured: Boolean(role_id && secret_id),
      certificate: until
        ? { validUntil: new Date(until).toISOString(), valid: until > this.now() }
        : { valid: false },
    };
  }

  /** A certificate valid for at least the margin; concurrent callers share one renewal. */
  ensureCertificate({ force = false } = {}) {
    if (!this.pending) this.pending = this.renewIfNeeded(force).finally(() => { this.pending = null; });
    return this.pending;
  }

  async renewIfNeeded(force) {
    await this.ensureKey();
    const until = await this.validUntil();
    if (!force && until && until - this.now() > this.marginMs) {
      return { key: this.key, cert: this.cert, validUntil: until, renewed: false };
    }
    const { role_id, secret_id } = this.approleFiles();
    if (!role_id || !secret_id) {
      throw new RealmError('vault_setup', `No AppRole credentials for realm ${this.realm.name} in ${this.realm.approleDir}.`);
    }
    const login = await this.vault('auth/approle/login', null, { role_id, secret_id });
    const token = login?.auth?.client_token;
    if (!token) throw new RealmError('vault_denied', `Vault returned no token for realm ${this.realm.name}.`);
    try {
      const signed = await this.vault(this.realm.signPath, token, {
        public_key: readFileSync(`${this.key}.pub`, 'utf8').trim(),
        valid_principals: this.realm.principal,
        ttl: this.realm.ttl,
        cert_type: 'user',
      });
      const value = signed?.data?.signed_key;
      if (!value) throw new RealmError('vault_denied', `Vault returned no certificate for realm ${this.realm.name}.`);
      const next = `${this.cert}.new`;
      writeFileSync(next, `${value.trim()}\n`, { mode: 0o600 });
      const nextUntil = await this.validUntil(next);
      if (!nextUntil || nextUntil <= this.now()) {
        rmSync(next, { force: true });
        throw new RealmError('vault_denied', `Vault returned an unusable certificate for realm ${this.realm.name}.`);
      }
      renameSync(next, this.cert);
      return { key: this.key, cert: this.cert, validUntil: nextUntil, renewed: true };
    } finally {
      this.vault('auth/token/revoke-self', token, {}).catch(() => {});
    }
  }

  async vault(path, token, body) {
    let response;
    try {
      response = await this.fetch(`${this.realm.vault}/v1/${path}`, {
        method: body ? 'POST' : 'GET',
        headers: { 'Content-Type': 'application/json', ...(token ? { 'X-Vault-Token': token } : {}) },
        body: body ? JSON.stringify(body) : undefined,
        signal: AbortSignal.timeout(15000),
      });
    } catch (error) {
      throw new RealmError('vault_unavailable', `Vault for realm ${this.realm.name} is unreachable (${error.cause?.code || error.message}).`);
    }
    if (response.status === 204) return {};
    if (response.status >= 500) {
      throw new RealmError('vault_unavailable', `Vault for realm ${this.realm.name} answered HTTP ${response.status}.`);
    }
    if (!response.ok) {
      const step = path.startsWith('auth/approle') ? 'AppRole login' : 'certificate signing';
      throw new RealmError('vault_denied', `Vault refused ${step} for realm ${this.realm.name} (HTTP ${response.status}).`);
    }
    return response.json();
  }
}
