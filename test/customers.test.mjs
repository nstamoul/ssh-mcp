import test from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync, spawn } from 'node:child_process';
import { createServer } from 'node:net';
import { fileURLToPath } from 'node:url';

import {
  NautobotClient,
  SlotDirectory,
  askpassEnv,
  customerSshOptions,
  isIPv4,
  parseNet,
  parseSlots,
  pickSlot,
  proxyCommand,
  relayCommand,
} from '../customers.mjs';

const SLOTS = [
  'axepa|shms-vpn-axepa-celery_worker_vpn-1|up|10.0.0.0/8,172.18.0.0/16,172.18.18.0/24,169.254.2.1',
  'zenith|shms-vpn-zenith-celery_worker_vpn-1|up|10.32.0.0/13,172.30.0.0/15',
  'dodoni|shms-vpn-dodoni-celery_worker_vpn-1||10.40.0.0/16',
  '',
].join('\n');

test('isIPv4 and parseNet', () => {
  assert.ok(isIPv4('172.18.18.26'));
  assert.ok(!isIPv4('172.18.18.256'));
  assert.ok(!isIPv4('Ahepa_9800w'));
  assert.deepEqual(parseNet('10.0.0.0/8'), { base: 0x0a000000, bits: 8, mask: 0xff000000 });
  assert.equal(parseNet('169.254.2.1').bits, 32);
  assert.equal(parseNet('bogus/8'), null);
});

test('pickSlot takes the most specific route of a running slot', () => {
  const slots = parseSlots(SLOTS);
  assert.equal(slots.length, 3);
  assert.equal(pickSlot(slots, '172.18.18.26').slug, 'axepa');
  assert.equal(pickSlot(slots, '10.33.1.1').slug, 'zenith', '/13 beats /8');
  assert.equal(pickSlot(slots, '10.1.1.1').slug, 'axepa');
  assert.equal(pickSlot(slots, '10.40.1.1').slug, 'axepa', 'a slot without a running worker is skipped');
  assert.equal(pickSlot(slots, '192.168.1.1'), null);
  assert.equal(pickSlot(slots, 'name'), null);
});

test('relayCommand refuses values that could break the shell', () => {
  assert.throws(() => relayCommand('w;rm', '1.2.3.4', 22), /worker/);
  assert.throws(() => relayCommand('w', '1.2.3.4;id', 22), /address/);
  assert.match(relayCommand('shms-vpn-axepa-celery_worker_vpn-1', '172.18.18.26', 22), /^docker exec -i shms-vpn-axepa-celery_worker_vpn-1 python3 -c ".*" [A-Za-z0-9+/=]+ 172\.18\.18\.26 22$/);
});

test('proxyCommand survives the shell as exactly the intended words', () => {
  const jumpArgs = ['-F', '/dev/null', '-i', "/state/it's key", '-o', 'User=nstam', '-o', 'UserKnownHostsFile=/x/100%/known_hosts'];
  const value = proxyCommand(jumpArgs, '172.20.11.211', 'shms-vpn-axepa-celery_worker_vpn-1', '172.18.18.26', 22);
  // ssh expands %% to % in ProxyCommand, then runs it with /bin/sh -c.
  const expanded = value.replace(/%%/g, '%');
  const words = execFileSync('/bin/sh', ['-c', `set -- ${expanded}; for w in "$@"; do printf '%s\\0' "$w"; done`], { encoding: 'utf8' }).split('\0').slice(0, -1);
  assert.deepEqual(words, ['ssh', ...jumpArgs, '172.20.11.211', relayCommand('shms-vpn-axepa-celery_worker_vpn-1', '172.18.18.26', 22)]);
});

test('the relay copies bytes both ways (needs python3)', async (t) => {
  try { execFileSync('python3', ['--version']); } catch { t.skip('python3 not available'); return; }
  const server = createServer((sock) => sock.on('data', (d) => sock.write(Buffer.concat([Buffer.from('echo:'), d]))));
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const { port } = server.address();
  const remote = relayCommand('worker', '127.0.0.1', port).replace(/^docker exec -i worker /, '');
  const child = spawn('/bin/sh', ['-c', remote]);
  let out = '';
  child.stdout.on('data', (d) => { out += d; });
  child.stdin.write('hello');
  await new Promise((r) => setTimeout(r, 800));
  child.stdin.end();
  await new Promise((r) => child.on('exit', r));
  server.close();
  assert.equal(out, 'echo:hello');
});

test('customer ssh options log in with a password only, through the proxy', () => {
  const opts = customerSshOptions({ username: 'admin' }, 22, 'PROXY');
  assert.ok(opts.includes('User=admin'));
  assert.ok(opts.includes('PubkeyAuthentication=no'));
  assert.ok(opts.includes('PreferredAuthentications=keyboard-interactive,password'));
  assert.ok(opts.includes('ProxyCommand=PROXY'));
  assert.ok(!opts.some((o) => o.includes('secret')));
  const env = askpassEnv('s3cr3t');
  assert.equal(env.SSH_ASKPASS_REQUIRE, 'force');
  assert.equal(env.MCP_SSH_SECRET, 's3cr3t');
});

test('askpass.sh answers with the secret from its environment', () => {
  const script = fileURLToPath(new URL('../askpass.sh', import.meta.url));
  assert.equal(execFileSync('/bin/sh', [script, 'Password:'], { env: { MCP_SSH_SECRET: 'p@ss w0rd' }, encoding: 'utf8' }), 'p@ss w0rd\n');
});

test('Nautobot lookup by name and by IP, cached', async () => {
  const calls = [];
  const fetchImpl = async (url, init) => {
    const body = JSON.parse(init.body);
    calls.push({ url, auth: init.headers.Authorization, vars: body.variables });
    const data = body.variables.ip
      ? { ip_addresses: body.variables.ip[0] === '172.16.31.10'
        ? [{ host: '172.16.31.10', tenant: { name: 'AXEPA' }, primary_ip4_for: [] }]
        : [] }
      : { devices: [{ name: 'Ahepa_9800w', primary_ip4: { host: '172.18.18.26' }, tenant: { name: 'AXEPA' }, platform: { network_driver: 'cisco_xe' } }], virtual_machines: [] };
    return { ok: true, status: 200, json: async () => ({ data }) };
  };
  const client = new NautobotClient({ url: 'https://nb.example/', token: async () => 'tkn', fetchImpl });
  assert.deepEqual(await client.lookup('ahepa_9800w'), { name: 'Ahepa_9800w', hostname: '172.18.18.26', tenant: 'AXEPA', platform: 'cisco_xe' });
  assert.deepEqual(await client.lookup('172.16.31.10'), { name: '172.16.31.10', hostname: '172.16.31.10', tenant: 'AXEPA', platform: null });
  assert.equal(await client.lookup('10.9.9.9'), null);
  await client.lookup('AHEPA_9800W');
  assert.equal(calls.length, 3, 'case-insensitive cache hit');
  assert.equal(calls[0].url, 'https://nb.example/api/graphql/');
  assert.equal(calls[0].auth, 'Token tkn');

  const down = new NautobotClient({ url: 'https://nb.example', token: async () => 't', fetchImpl: async () => { throw new Error('x'); } });
  await assert.rejects(down.lookup('a'), { kind: 'nautobot_unavailable' });
});

test('slot directory caches and refreshes on demand', async () => {
  let n = 0;
  const dir = new SlotDirectory({ discover: async () => { n += 1; return SLOTS; } });
  await dir.slots();
  await dir.slots();
  assert.equal(n, 1);
  await dir.slots({ fresh: true });
  assert.equal(n, 2);
});
