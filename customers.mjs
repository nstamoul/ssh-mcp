/**
 * Customer hosts: devices and VMs that are in Nautobot but in no realm file.
 *
 * A realm that sets `customers` (see realms.json) resolves unknown aliases in
 * Nautobot (name or primary IPv4 -> address, tenant, platform), reaches them
 * through the open SHMS VPN slot whose routes cover the address (a container
 * on the jump host, entered with `docker exec`), and logs in with the
 * tenant's credentials from the realm's Vault (username/password, given to
 * ssh through SSH_ASKPASS only).
 *
 *   "customers": {
 *     "nautobot": "https://sot.space.gr",
 *     "nautobotTokenPath": "kv/data/nautobot/token",
 *     "nautobotTokenField": "ro_token",
 *     "loginPath": "kv/data/{tenant}/login",
 *     "jump": "nb-ha-01",
 *     "skipTenants": ["SHMS"]
 *   }
 */
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';

import { RealmError } from './realm.mjs';

const run = promisify(execFile);

export const ASKPASS = process.env.MCP_SSH_ASKPASS || '/app/askpass.sh';

const NAME_QUERY = 'query($n:[String]){ devices(name__ie:$n){ name primary_ip4{ host } tenant{ name } platform{ network_driver } } '
  + 'virtual_machines(name__ie:$n){ name primary_ip4{ host } tenant{ name } platform{ network_driver } } }';
const IP_QUERY = 'query($ip:[String]){ ip_addresses(address:$ip){ host tenant{ name } '
  + 'primary_ip4_for{ name tenant{ name } platform{ network_driver } } } }';

export function isIPv4(value) {
  const parts = String(value).split('.');
  return parts.length === 4 && parts.every((p) => /^\d{1,3}$/.test(p) && Number(p) <= 255);
}

function ipToInt(ip) {
  return ip.split('.').reduce((acc, octet) => ((acc << 8) | Number(octet)) >>> 0, 0);
}

/** "10.0.0.0/8" or "10.1.2.3" -> { base, bits } */
export function parseNet(text) {
  const [ip, len] = text.split('/');
  if (!isIPv4(ip)) return null;
  const bits = len === undefined ? 32 : Number(len);
  if (!Number.isInteger(bits) || bits < 0 || bits > 32) return null;
  const mask = bits === 0 ? 0 : (~0 << (32 - bits)) >>> 0;
  return { base: (ipToInt(ip) & mask) >>> 0, bits, mask };
}

/** Lines of `slug|worker|up|routes,...` (from DISCOVER) -> slots. */
export function parseSlots(text) {
  return text.split('\n').filter((l) => l.includes('|')).map((line) => {
    const [slug, worker, up, routes = ''] = line.split('|');
    return {
      slug,
      worker,
      up: up === 'up',
      nets: routes.split(',').map((r) => r.trim()).filter(Boolean).map(parseNet).filter(Boolean),
    };
  });
}

/** The running slot with the most specific route containing ip. */
export function pickSlot(slots, ip) {
  if (!isIPv4(ip)) return null;
  const addr = ipToInt(ip);
  let best = null;
  for (const slot of slots) {
    if (!slot.up) continue;
    for (const net of slot.nets) {
      if (((addr & net.mask) >>> 0) === net.base && (!best || net.bits > best.bits)) best = { slot, bits: net.bits };
    }
  }
  return best ? best.slot : null;
}

// Run on the jump host: one line per VPN slot with a running worker.
export const DISCOVER = [
  "for vpn in $(docker ps --format '{{.Names}}' | grep -E '^shms-vpn-.+-vpn-1$'); do",
  '  slug=${vpn#shms-vpn-}; slug=${slug%-vpn-1}',
  '  worker=shms-vpn-$slug-celery_worker_vpn-1',
  '  wk=$(docker ps -q -f name="^${worker}\\$" | head -1)',
  "  routes=$(docker exec $vpn ip -o route 2>/dev/null | awk '$0 ~ / dev (ppp|tun|vpn|wg)[0-9]*/ {print $1}' | grep -v default | paste -sd, -)",
  '  echo "$slug|$worker|${wk:+up}|$routes"',
  'done',
].join('\n');

// Byte relay between stdin/stdout and host:port, run inside the slot worker.
const RELAY = `import os,socket,sys,threading
s=socket.create_connection((sys.argv[2],int(sys.argv[3])),15)
def up():
    while True:
        d=os.read(0,65536)
        if not d: break
        s.sendall(d)
    try: s.shutdown(socket.SHUT_WR)
    except OSError: pass
threading.Thread(target=up,daemon=True).start()
while True:
    d=s.recv(65536)
    if not d: break
    os.write(1,d)
`;
const RELAY_B64 = Buffer.from(RELAY).toString('base64');

export function relayCommand(worker, ip, port) {
  if (!/^[A-Za-z0-9_.-]+$/.test(worker)) throw new Error(`bad worker name ${worker}`);
  if (!isIPv4(ip)) throw new Error(`bad address ${ip}`);
  return `docker exec -i ${worker} python3 -c "import base64,sys;exec(base64.b64decode(sys.argv[1]))" ${RELAY_B64} ${ip} ${Number(port)}`;
}

const shq = (s) => `'${String(s).replace(/'/g, `'\\''`)}'`;

/** ProxyCommand value: ssh to the jump host and relay to ip:port from the slot. */
export function proxyCommand(jumpArgs, jumpTarget, worker, ip, port) {
  const words = ['ssh', ...jumpArgs, jumpTarget, relayCommand(worker, ip, port)];
  return words.map(shq).join(' ').replace(/%/g, '%%');
}

// Options for customer devices: password login, no keys offered, and the
// older algorithms some network operating systems still need.
export function customerSshOptions(login, port, proxy) {
  return [
    '-F', '/dev/null',
    '-o', `User=${login.username}`,
    '-o', `Port=${port}`,
    '-o', 'PubkeyAuthentication=no',
    '-o', 'PreferredAuthentications=keyboard-interactive,password',
    '-o', 'NumberOfPasswordPrompts=1',
    '-o', 'KexAlgorithms=+diffie-hellman-group14-sha1,diffie-hellman-group-exchange-sha1',
    '-o', 'HostKeyAlgorithms=+ssh-rsa',
    '-o', 'Ciphers=+aes128-cbc,aes256-cbc',
    '-o', 'ServerAliveInterval=30',
    '-o', `ProxyCommand=${proxy}`,
  ];
}

export function askpassEnv(password) {
  return { SSH_ASKPASS: ASKPASS, SSH_ASKPASS_REQUIRE: 'force', DISPLAY: 'none', MCP_SSH_SECRET: password };
}

export class NautobotClient {
  constructor({ url, token, fetchImpl = globalThis.fetch, now = () => Date.now(), cacheMs = 5 * 60 * 1000 }) {
    this.url = url.replace(/\/+$/, '');
    this.token = token; // async () => string
    this.fetch = fetchImpl;
    this.now = now;
    this.cacheMs = cacheMs;
    this.cache = new Map();
  }

  async graphql(query, variables) {
    const token = await this.token();
    let response;
    try {
      response = await this.fetch(`${this.url}/api/graphql/`, {
        method: 'POST',
        headers: { Authorization: `Token ${token}`, 'Content-Type': 'application/json', Accept: 'application/json' },
        body: JSON.stringify({ query, variables }),
        signal: AbortSignal.timeout(15000),
      });
    } catch (error) {
      throw new RealmError('nautobot_unavailable', `Nautobot is unreachable (${error.cause?.code || error.message}).`);
    }
    if (!response.ok) throw new RealmError('nautobot_unavailable', `Nautobot answered HTTP ${response.status}.`);
    const body = await response.json();
    if (body.errors?.length) throw new RealmError('nautobot_unavailable', `Nautobot query failed: ${body.errors[0].message}`);
    return body.data;
  }

  /** { name, hostname, tenant, platform } or null. */
  async lookup(target) {
    const key = String(target).toLowerCase();
    const hit = this.cache.get(key);
    if (hit && this.now() - hit.at < this.cacheMs) return hit.value;
    let value = null;
    if (isIPv4(target)) {
      const data = await this.graphql(IP_QUERY, { ip: [target] });
      const ip = data.ip_addresses?.[0];
      if (ip) {
        const owner = ip.primary_ip4_for?.[0];
        value = {
          name: owner?.name || target,
          hostname: ip.host,
          tenant: owner?.tenant?.name || ip.tenant?.name || null,
          platform: owner?.platform?.network_driver || null,
        };
      }
    } else {
      const data = await this.graphql(NAME_QUERY, { n: [target] });
      const item = data.devices?.[0] || data.virtual_machines?.[0];
      if (item) {
        value = {
          name: item.name,
          hostname: item.primary_ip4?.host || null,
          tenant: item.tenant?.name || null,
          platform: item.platform?.network_driver || null,
        };
      }
    }
    this.cache.set(key, { at: this.now(), value });
    return value;
  }
}

/** VPN slots on the jump host, cached briefly. */
export class SlotDirectory {
  constructor({ discover, now = () => Date.now(), cacheMs = 60 * 1000 }) {
    this.discover = discover; // async () => text
    this.now = now;
    this.cacheMs = cacheMs;
    this.cached = null;
  }

  async slots({ fresh = false } = {}) {
    if (!fresh && this.cached && this.now() - this.cached.at < this.cacheMs) return this.cached.slots;
    const slots = parseSlots(await this.discover());
    this.cached = { at: this.now(), slots };
    return slots;
  }
}

export async function runDiscover(jumpArgs, jumpTarget) {
  try {
    const { stdout } = await run('ssh', [...jumpArgs, jumpTarget, DISCOVER], { timeout: 45000, maxBuffer: 1024 * 1024 });
    return stdout;
  } catch (error) {
    throw new RealmError('no_route', `Cannot list VPN slots on the jump host: ${(error.stderr || error.message).trim().split('\n').pop()}`);
  }
}
