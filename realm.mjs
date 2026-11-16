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
 *       "staticKeyPath": "secret/data/homelab/ssh-mcp/static-key",
 *       "adhocPath": "secret/data/homelab/ssh-mcp/adhoc-hosts",
 *       "hosts": {
 *         "thanos": { "hostname": "10.64.110.227", "user": "nstam" },
 *         "media-ai": { "hostname": "10.64.110.224", "user": "root", "auth": "key" }
 *       }
 *     }
 *   }
 * auth "certificate" (default): the host trusts the realm's SSH CA.
 * auth "key": the host lists the realm's static MCP key in authorized_keys.
 * The static key lives in the realm's Vault (KV v2, fields private_key and
 * public_key) and is held only in memory-backed /dev/shm. Ad-hoc hosts, added
 * at runtime with addHost, are one KV v2 document per realm (adhocPath) that
 * every MCP instance reads, so a host added from one is usable from all.
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
export const KEY_DIR = process.env.MCP_SSH_KEY_DIR || '/dev/shm/ssh-mcp';
const ADHOC_CACHE_MS = 30 * 1000;
const AUTH_KINDS = new Set(['certificate', 'key']);

/** One host entry from the realms file or the ad-hoc store, validated. */
export function normalizeHost(alias, host, realmName) {
  const entry = {
    alias,
    hostname: host?.hostname,
    user: host?.user,
    port: Number(host?.port || 22),
    auth: host?.auth || 'certificate',
  };
  const word = /^[A-Za-z0-9_][A-Za-z0-9_.-]*$/;
  if (!word.test(alias)) throw new Error(`Realm ${realmName}: invalid alias ${JSON.stringify(alias)}`);
  if (typeof entry.hostname !== 'string' || !/^[A-Za-z0-9_.:\[\]%-]+$/.test(entry.hostname) || entry.hostname.startsWith('-')) {
    throw new Error(`Realm ${realmName}: host ${alias} needs a hostname or address`);
  }
  if (typeof entry.user !== 'string' || !/^[A-Za-z0-9_][A-Za-z0-9_.-]*$/.test(entry.user)) {
    throw new Error(`Realm ${realmName}: host ${alias} needs a user`);
  }
  if (!Number.isInteger(entry.port) || entry.port < 1 || entry.port > 65535) throw new Error(`Realm ${realmName}: host ${alias} has a bad port`);
  if (!AUTH_KINDS.has(entry.auth)) throw new Error(`Realm ${realmName}: host ${alias} auth must be certificate or key`);
  if (host?.note) entry.note = String(host.note).slice(0, 200);
  return entry;
}

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
      staticKeyPath: realm.staticKeyPath || null,
      adhocPath: realm.adhocPath || null,
      customers: realm.customers ? {
        nautobot: realm.customers.nautobot,
        nautobotTokenPath: realm.customers.nautobotTokenPath,
        nautobotTokenField: realm.customers.nautobotTokenField || 'token',
        loginPath: realm.customers.loginPath || 'kv/data/{tenant}/login',
        jump: realm.customers.jump,
        skipTenants: realm.customers.skipTenants || [],
      } : null,
      hosts: Object.entries(realm.hosts || {}).map(([alias, host]) => normalizeHost(alias, host, name)),
    };
  });
}

/** The realm host a tool argument names, by alias or address. */
export function findRealmHost(realms, target, hostsOf = (realm) => realm.hosts) {
  for (const realm of realms) {
    for (const host of hostsOf(realm)) {
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
    opts.push('-i', credentials.key, '-o', 'IdentitiesOnly=yes');
    if (credentials.cert) opts.push('-o', `CertificateFile=${credentials.cert}`);
  }
  opts.push('-o', `User=${host.user}`, '-o', `Port=${host.port}`, '-o', 'ServerAliveInterval=30');
  if (proxyCommand) opts.push('-o', `ProxyCommand=${proxyCommand} %h %p`);
  return opts;
}

export class RealmCredentials {
  constructor(realm, { stateDir = STATE_DIR, keyDir = KEY_DIR, fetchImpl = globalThis.fetch, now = () => Date.now(), marginMs = 15 * 60 * 1000 } = {}) {
    this.realm = realm;
    this.staticKey = join(keyDir, realm.name, 'static_key');
    this.staticPending = null;
    this.adhocCache = null;
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
    const out = {
      realm: this.realm.name,
      vault: this.realm.vault,
      principal: this.realm.principal,
      hosts: this.realm.hosts.map((h) => `${h.alias} (${h.auth})`),
      approleConfigured: Boolean(role_id && secret_id),
      certificate: until
        ? { validUntil: new Date(until).toISOString(), valid: until > this.now() }
        : { valid: false },
    };
    if (this.realm.staticKeyPath) {
      out.staticKey = existsSync(`${this.staticKey}.pub`)
        ? { loaded: true, publicKey: readFileSync(`${this.staticKey}.pub`, 'utf8').trim() }
        : { loaded: false, vaultPath: this.realm.staticKeyPath };
    }
    return out;
  }

  /** Log in with AppRole, run fn(token), always revoke the token. */
  async withToken(fn) {
    const { role_id, secret_id } = this.approleFiles();
    if (!role_id || !secret_id) {
      throw new RealmError('vault_setup', `No AppRole credentials for realm ${this.realm.name} in ${this.realm.approleDir}.`);
    }
    const login = await this.vault('auth/approle/login', null, { role_id, secret_id });
    const token = login?.auth?.client_token;
    if (!token) throw new RealmError('vault_denied', `Vault returned no token for realm ${this.realm.name}.`);
    try {
      return await fn(token);
    } finally {
      this.vault('auth/token/revoke-self', token, {}).catch(() => {});
    }
  }

  /** A tenant's device login (username/password) from the realm's Vault. Never cached. */
  async customerLogin(tenant) {
    const template = this.realm.customers?.loginPath;
    if (!template) throw new RealmError('vault_setup', `Realm ${this.realm.name} has no customer login path.`);
    const path = template.replace('{tenant}', encodeURIComponent(tenant));
    return this.withToken(async (token) => {
      const doc = await this.vault(path, token, undefined, { allow404: true });
      const data = doc?.data?.data;
      if (!data?.username || !data?.password) {
        throw new RealmError('vault_setup', `No username/password for tenant ${tenant} at ${path}.`);
      }
      return { username: String(data.username), password: String(data.password) };
    });
  }

  /** The Nautobot API token, read from Vault once and kept in memory. */
  async nautobotToken() {
    if (this.nautobotTokenValue) return this.nautobotTokenValue;
    const c = this.realm.customers;
    if (!c?.nautobotTokenPath) throw new RealmError('vault_setup', `Realm ${this.realm.name} has no Nautobot token path.`);
    const value = await this.withToken(async (token) => {
      const doc = await this.vault(c.nautobotTokenPath, token);
      return doc?.data?.data?.[c.nautobotTokenField];
    });
    if (!value) throw new RealmError('vault_setup', `No ${c.nautobotTokenField} at ${c.nautobotTokenPath}.`);
    this.nautobotTokenValue = String(value);
    return this.nautobotTokenValue;
  }

  /** The realm's static MCP key, fetched from Vault once per container start. */
  ensureStaticKey() {
    if (!this.realm.staticKeyPath) {
      return Promise.reject(new RealmError('vault_setup', `Realm ${this.realm.name} has no static key configured.`));
    }
    if (existsSync(this.staticKey)) return Promise.resolve({ key: this.staticKey });
    if (!this.staticPending) {
      this.staticPending = this.withToken(async (token) => {
        const secret = await this.vault(this.realm.staticKeyPath, token);
        const { private_key: privateKey, public_key: publicKey } = secret?.data?.data || {};
        if (!privateKey || !publicKey) {
          throw new RealmError('vault_setup', `No private_key/public_key at ${this.realm.staticKeyPath}.`);
        }
        mkdirSync(join(this.staticKey, '..'), { recursive: true, mode: 0o700 });
        writeFileSync(`${this.staticKey}.new`, `${privateKey.trim()}\n`, { mode: 0o600 });
        writeFileSync(`${this.staticKey}.pub`, `${publicKey.trim()}\n`, { mode: 0o644 });
        renameSync(`${this.staticKey}.new`, this.staticKey);
        return { key: this.staticKey };
      }).finally(() => { this.staticPending = null; });
    }
    return this.staticPending;
  }

  async publicStaticKey() {
    await this.ensureStaticKey();
    return readFileSync(`${this.staticKey}.pub`, 'utf8').trim();
  }

  /** Ad-hoc hosts of this realm: [{alias, hostname, user, port, auth, ...}], cached briefly. */
  async adhocHosts({ fresh = false } = {}) {
    if (!this.realm.adhocPath) return [];
    const cached = this.adhocCache;
    if (!fresh && cached && this.now() - cached.at < ADHOC_CACHE_MS) {
      if (cached.error) throw cached.error;
      return cached.hosts;
    }
    try {
      const { hosts } = await this.readAdhoc();
      this.adhocCache = { at: this.now(), hosts };
      return hosts;
    } catch (error) {
      this.adhocCache = { at: this.now(), error };
      throw error;
    }
  }

  async readAdhoc(token) {
    const read = async (t) => {
      const doc = await this.vault(this.realm.adhocPath, t, undefined, { allow404: true });
      const raw = doc?.data?.data?.hosts || {};
      const hosts = [];
      for (const [alias, host] of Object.entries(raw)) {
        try {
          hosts.push({ ...normalizeHost(alias, host, this.realm.name), addedAt: host.addedAt, addedBy: host.addedBy });
        } catch {
          // A malformed entry is skipped rather than breaking every other host.
        }
      }
      return { hosts, raw, version: doc?.data?.metadata?.version || 0 };
    };
    return token ? read(token) : this.withToken(read);
  }

  /** Change the ad-hoc document with check-and-set, retrying once on a concurrent write. */
  async updateAdhoc(mutate) {
    const result = await this.withToken(async (token) => {
      for (let attempt = 0; attempt < 2; attempt += 1) {
        const { raw, version } = await this.readAdhoc(token);
        const next = { ...raw };
        const outcome = mutate(next);
        try {
          await this.vault(this.realm.adhocPath, token, { options: { cas: version }, data: { hosts: next } });
          return outcome;
        } catch (error) {
          if (attempt === 0 && error.status === 400) continue;
          throw error;
        }
      }
      throw new RealmError('vault_unavailable', 'Concurrent change to the ad-hoc host list; try again.');
    });
    this.adhocCache = null;
    return result;
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
    return this.withToken(async (token) => {
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
    });
  }

  async vault(path, token, body, { allow404 = false } = {}) {
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
    if (response.status === 404 && allow404) return null;
    if (response.status >= 500) {
      throw new RealmError('vault_unavailable', `Vault for realm ${this.realm.name} answered HTTP ${response.status}.`);
    }
    if (!response.ok) {
      const step = path.startsWith('auth/approle')
        ? 'AppRole login'
        : path === this.realm.signPath ? 'certificate signing' : `access to ${path}`;
      const error = new RealmError('vault_denied', `Vault refused ${step} for realm ${this.realm.name} (HTTP ${response.status}).`);
      error.status = response.status;
      throw error;
    }
    return response.json();
  }
}
