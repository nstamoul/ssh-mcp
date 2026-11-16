#!/usr/bin/env node

/**
 * MCP SSH Agent - HTTP Server with SSE Support
 *
 * This is an HTTP-based MCP server that uses Server-Sent Events (SSE) for streaming.
 * It provides the same SSH operations as the STDIO version but over HTTP.
 */

import express from 'express';
import cors from 'cors';
import { homedir } from 'os';
import { readFile } from 'fs/promises';
import { join } from 'path';
import { createRequire } from 'module';
import { assertSafeTarget, classifySshFailure, ensureKnownHosts, replaceHostKey, sshOptions } from './ssh-exec.mjs';
import { RealmCredentials, findRealmHost, loadRealms, realmSshOptions } from './realm.mjs';

// Use createRequire to work around ESM import issues
const require = createRequire(import.meta.url);

// Required libraries
const { execFile } = require('child_process');
const { promisify } = require('util');
const sshConfig = require('ssh-config');

const execFileAsync = promisify(execFile);

// Import MCP components
const { Server } = require('@modelcontextprotocol/sdk/server/index.js');
// Use the Streamable HTTP transport (supports unified POST/GET, SSE fallback, stateless/stateful)
const { StreamableHTTPServerTransport } = require('@modelcontextprotocol/sdk/server/streamableHttp.js');
const { CallToolRequestSchema, ListToolsRequestSchema } = require('@modelcontextprotocol/sdk/types.js');

// OAuth/OpenID configuration
const OAUTH_ISSUER = process.env.OAUTH_ISSUER || 'https://authelia.nstam.eu';
const OAUTH_AUTHORIZATION_ENDPOINT = process.env.OAUTH_AUTHORIZATION_ENDPOINT || `${OAUTH_ISSUER}/api/oidc/authorization`;
const OAUTH_TOKEN_ENDPOINT = process.env.OAUTH_TOKEN_ENDPOINT || process.env.OAUTH_TOKEN_URL || `${OAUTH_ISSUER}/api/oidc/token`;
const OAUTH_JWKS_URI = process.env.OAUTH_JWKS_URI || `${OAUTH_ISSUER}/jwks.json`;
const OAUTH_USERINFO_ENDPOINT = process.env.OAUTH_USERINFO_ENDPOINT || `${OAUTH_ISSUER}/api/oidc/userinfo`;
const OAUTH_INTROSPECTION_ENDPOINT = process.env.OAUTH_INTROSPECTION_ENDPOINT || `${OAUTH_ISSUER}/api/oidc/introspection`;
const OAUTH_DEVICE_AUTHORIZATION_ENDPOINT = process.env.OAUTH_DEVICE_AUTHORIZATION_ENDPOINT || `${OAUTH_ISSUER}/api/oidc/device-authorization`;
const OAUTH_SCOPES = (process.env.OAUTH_SCOPE || process.env.OAUTH_SCOPES || '')
  .split(/[\s,]+/)
  .map(scope => scope.trim())
  .filter(scope => scope.length > 0);
const OAUTH_RESOURCE = process.env.OAUTH_RESOURCE || process.env.MCP_RESOURCE || 'https://mcp.nstam.eu/ssh';
const OAUTH_CLIENT_ID = process.env.OAUTH_CLIENT_ID || 'mcp';

const oauthProtectedResourceMetadata = sanitizeMetadata({
  resource: OAUTH_RESOURCE,
  authorization_servers: [OAUTH_ISSUER],
  token_endpoint: OAUTH_TOKEN_ENDPOINT,
  scopes_supported: OAUTH_SCOPES.length ? OAUTH_SCOPES : undefined,
  bearer_methods_supported: ['authorization_header'],
});

const oauthAuthorizationServerMetadata = sanitizeMetadata({
  issuer: OAUTH_ISSUER,
  authorization_endpoint: OAUTH_AUTHORIZATION_ENDPOINT,
  token_endpoint: OAUTH_TOKEN_ENDPOINT,
  jwks_uri: OAUTH_JWKS_URI,
  response_types_supported: ['code'],
  grant_types_supported: ['authorization_code', 'client_credentials'],
  code_challenge_methods_supported: ['S256'],
  token_endpoint_auth_methods_supported: ['client_secret_basic', 'client_secret_post'],
  scopes_supported: OAUTH_SCOPES.length ? OAUTH_SCOPES : ['openid', 'profile', 'email'],
  claims_supported: ['aud', 'iss', 'sub', 'exp', 'iat'],
  introspection_endpoint: OAUTH_INTROSPECTION_ENDPOINT,
  device_authorization_endpoint: OAUTH_DEVICE_AUTHORIZATION_ENDPOINT,
});

const openIdConfiguration = sanitizeMetadata({
  ...oauthAuthorizationServerMetadata,
  userinfo_endpoint: OAUTH_USERINFO_ENDPOINT,
  subject_types_supported: ['public', 'pairwise'],
  id_token_signing_alg_values_supported: ['RS256'],
  request_parameter_supported: true,
  token_endpoint_auth_methods_supported: oauthAuthorizationServerMetadata.token_endpoint_auth_methods_supported,
  grant_types_supported: oauthAuthorizationServerMetadata.grant_types_supported,
  response_types_supported: oauthAuthorizationServerMetadata.response_types_supported,
  scopes_supported: oauthAuthorizationServerMetadata.scopes_supported,
});

function sanitizeMetadata(metadata) {
  return Object.fromEntries(
    Object.entries(metadata).filter(([, value]) => {
      if (value === undefined || value === null) {
        return false;
      }
      if (Array.isArray(value)) {
        return value.length > 0;
      }
      return true;
    }),
  );
}

// Configuration from environment variables
const PORT = process.env.PORT || 3009;
const HOST = process.env.HOST || '0.0.0.0';
const DEBUG = process.env.DEBUG === 'true';

// Debug logging function
function debugLog(message) {
  if (DEBUG) {
    console.error(`[DEBUG] ${message}`);
  }
}

// SSH Configuration Parser
class SSHConfigParser {
  constructor() {
    const homeDir = homedir();
    this.configPath = join(homeDir, '.ssh', 'config');
    this.knownHostsPath = join(homeDir, '.ssh', 'known_hosts');
  }

  async parseConfig() {
    try {
      const content = await readFile(this.configPath, 'utf-8');
      const config = sshConfig.parse(content);
      return this.extractHostsFromConfig(config, this.configPath);
    } catch (error) {
      debugLog(`Error reading SSH config: ${error.message}`);
      return [];
    }
  }

  async processIncludeDirectives(configPath) {
    try {
      const content = await readFile(configPath, 'utf-8');
      const config = sshConfig.parse(content);
      const hosts = [];

      for (const section of config) {
        if (section.param === 'Include' && section.value) {
          const includePaths = this.expandIncludePath(section.value, configPath);

          for (const includePath of includePaths) {
            try {
              const includeHosts = await this.processIncludeDirectives(includePath);
              hosts.push(...includeHosts);
            } catch (error) {
              debugLog(`Error processing include file ${includePath}: ${error.message}`);
            }
          }
        }
      }

      // Add hosts from the current config file
      const currentHosts = this.extractHostsFromConfig(config, configPath);
      hosts.push(...currentHosts);

      return hosts;
    } catch (error) {
      debugLog(`Error processing config file ${configPath}: ${error.message}`);
      return [];
    }
  }

  expandIncludePath(includePath, baseConfigPath) {
    const { dirname, resolve } = require('path');
    const { glob } = require('glob');
    const { existsSync } = require('fs');

    // Handle tilde expansion
    if (includePath.startsWith('~/')) {
      includePath = includePath.replace('~', homedir());
    }

    // Handle relative paths
    if (!includePath.startsWith('/')) {
      const baseDir = dirname(baseConfigPath);
      includePath = resolve(baseDir, includePath);
    }

    try {
      // Handle glob patterns
      if (includePath.includes('*') || includePath.includes('?')) {
        return glob.sync(includePath).filter(path => existsSync(path));
      } else {
        return existsSync(includePath) ? [includePath] : [];
      }
    } catch (error) {
      debugLog(`Error expanding include path ${includePath}: ${error.message}`);
      return [];
    }
  }

  extractHostsFromConfig(config, configPath) {
    const hosts = [];

    for (const section of config) {
      // Skip Include directives as they are processed separately
      if (section.param === 'Include') {
        continue;
      }

      if (section.param === 'Host' && section.value !== '*') {
        const hostInfo = {
          hostname: '',
          alias: section.value,
          configFile: configPath
        };

        // Search all entries for this host
        for (const param of section.config) {
          // Safety check for undefined param
          if (!param || !param.param) {
            continue;
          }

          switch (param.param.toLowerCase()) {
            case 'hostname':
              hostInfo.hostname = param.value;
              break;
            case 'user':
              hostInfo.user = param.value;
              break;
            case 'port':
              hostInfo.port = parseInt(param.value, 10);
              break;
            case 'identityfile':
              hostInfo.identityFile = param.value;
              break;
            default:
              // Store other parameters
              hostInfo[param.param.toLowerCase()] = param.value;
          }
        }

        // Only add hosts with complete information
        if (hostInfo.hostname) {
          hosts.push(hostInfo);
        }
      }
    }

    return hosts;
  }

  async parseKnownHosts() {
    try {
      const content = await readFile(this.knownHostsPath, 'utf-8');
      const knownHosts = content
        .split('\n')
        .filter(line => line.trim() !== '')
        .map(line => {
          // Format: hostname[,hostname2...] key-type public-key
          const parts = line.split(' ')[0];
          return parts.split(',')[0];
        });

      return knownHosts;
    } catch (error) {
      debugLog(`Error reading known_hosts file: ${error.message}`);
      return [];
    }
  }

  async getAllKnownHosts() {
    // First: Get all hosts from ~/.ssh/config including Include directives (these are prioritized)
    const configHosts = await this.processIncludeDirectives(this.configPath);

    // Second: Get hostnames from ~/.ssh/known_hosts
    const knownHostnames = await this.parseKnownHosts();

    // Create a comprehensive list starting with config hosts
    const allHosts = [...configHosts];

    // Add hosts from known_hosts that aren't already in the config
    // These will appear after the config hosts
    for (const hostname of knownHostnames) {
      if (!configHosts.some(host =>
          host.hostname === hostname ||
          host.alias === hostname)) {
        allHosts.push({
          hostname: hostname,
          source: 'known_hosts'
        });
      }
    }

    // Mark config hosts for clarity
    configHosts.forEach(host => {
      host.source = 'ssh_config';
    });

    return allHosts;
  }
}

// SSH Client Implementation
class SSHClient {
  constructor() {
    this.configParser = new SSHConfigParser();
    this.realms = loadRealms();
    this.credentials = new Map(this.realms.map((realm) => [realm.name, new RealmCredentials(realm)]));
    debugLog(`Realms: ${this.realms.map((r) => `${r.name} (${r.hosts.length} hosts)`).join(', ') || 'none'}`);
  }

  realmHostList() {
    return this.realms.flatMap((realm) => realm.hosts.map((host) => ({
      alias: host.alias,
      hostname: host.hostname,
      user: host.user,
      port: host.port,
      realm: realm.name,
      auth: `certificate from ${realm.vault} (principal ${realm.principal})`,
      source: 'realm',
    })));
  }

  async listKnownHosts() {
    const realmHosts = this.realmHostList();
    const taken = new Set(realmHosts.flatMap((h) => [h.alias, h.hostname]));
    const others = await this.configParser.getAllKnownHosts();
    return [...realmHosts, ...others.filter((h) => !taken.has(h.alias) && !taken.has(h.hostname))];
  }

  // How to reach a host: realm hosts get the MCP's own key and a Vault
  // certificate; everything else goes through the mounted ~/.ssh config.
  // If Vault cannot issue a certificate the mounted config is tried instead,
  // and `realm.error` says why.
  async connection(hostAlias) {
    assertSafeTarget(hostAlias);
    const match = findRealmHost(this.realms, hostAlias);
    if (!match) return { opts: [], target: hostAlias };
    try {
      const credentials = await this.credentials.get(match.realm.name).ensureCertificate();
      return {
        opts: realmSshOptions(match.host, credentials),
        target: match.host.hostname,
        realm: { name: match.realm.name, auth: 'certificate', validUntil: new Date(credentials.validUntil).toISOString() },
      };
    } catch (error) {
      debugLog(`Realm ${match.realm.name}: ${error.message}`);
      return {
        opts: [],
        target: hostAlias,
        realm: {
          name: match.realm.name,
          auth: 'mounted-config',
          error: { kind: error.kind || 'vault_unavailable', message: error.message },
        },
      };
    }
  }

  async accessStatus(renew) {
    const out = [];
    for (const credentials of this.credentials.values()) {
      let renewal;
      if (renew) {
        try {
          const result = await credentials.ensureCertificate({ force: true });
          renewal = { ok: true, validUntil: new Date(result.validUntil).toISOString() };
        } catch (error) {
          renewal = { ok: false, kind: error.kind, message: error.message };
        }
      }
      out.push({ ...(await credentials.status()), ...(renewal ? { renewal } : {}) });
    }
    return { realms: out };
  }

  // Runs ssh or scp without ever prompting. A failure of ssh itself (as
  // opposed to a non-zero remote exit) comes back as `error` with a `kind`.
  async exec(binary, args, timeout) {
    ensureKnownHosts();
    try {
      const { stdout, stderr } = await execFileAsync(binary, [...sshOptions(), ...args], {
        timeout,
        maxBuffer: 1024 * 1024 * 10 // 10MB buffer
      });
      return { stdout: stdout || '', stderr: stderr || '', code: 0 };
    } catch (error) {
      const stderr = typeof error.stderr === 'string' ? error.stderr : error.message;
      const result = {
        stdout: error.stdout || '',
        stderr,
        code: typeof error.code === 'number' ? error.code : 255
      };
      const failure = classifySshFailure(error, stderr);
      if (failure) result.error = failure;
      debugLog(`${binary} failed (${failure ? failure.kind : 'remote exit ' + result.code})`);
      return result;
    }
  }

  async runRemoteCommand(hostAlias, command) {
    const route = await this.connection(hostAlias);
    debugLog(`Executing: ssh ${route.target} ${command}`);
    const result = await this.exec('ssh', [...route.opts, '--', route.target, command], 30000);
    if (route.realm) result.realm = route.realm;
    return result;
  }

  async getHostInfo(hostAlias) {
    const realmHost = this.realmHostList().find((h) => h.alias === hostAlias || h.hostname === hostAlias);
    if (realmHost) return realmHost;
    const hosts = await this.configParser.processIncludeDirectives(this.configParser.configPath);
    return hosts.find(host => host.alias === hostAlias || host.hostname === hostAlias) || null;
  }

  async checkConnectivity(hostAlias) {
    try {
      const result = await this.runRemoteCommand(hostAlias, 'echo connected');
      const connected = result.code === 0 && result.stdout.trim() === 'connected';
      const realm = result.realm ? { realm: result.realm } : {};
      if (connected) return { connected, message: 'Connection successful', ...realm };
      return {
        connected,
        message: result.error ? result.error.message : 'Connection failed',
        error: result.error,
        stderr: result.stderr,
        ...realm
      };
    } catch (error) {
      return { connected: false, message: error instanceof Error ? error.message : String(error) };
    }
  }

  async transfer(route, args) {
    const result = await this.exec('scp', [...route.opts, ...args], 60000);
    const realm = route.realm ? { realm: route.realm } : {};
    if (result.code === 0) return { success: true, ...realm };
    return { success: false, error: result.error, stderr: result.stderr, ...realm };
  }

  async uploadFile(hostAlias, localPath, remotePath) {
    const route = await this.connection(hostAlias);
    debugLog(`Executing: scp ${localPath} ${route.target}:${remotePath}`);
    return await this.transfer(route, ['--', localPath, `${route.target}:${remotePath}`]);
  }

  async downloadFile(hostAlias, remotePath, localPath) {
    const route = await this.connection(hostAlias);
    debugLog(`Executing: scp ${route.target}:${remotePath} ${localPath}`);
    return await this.transfer(route, ['--', `${route.target}:${remotePath}`, localPath]);
  }

  async replaceHostKey(hostAlias, fingerprint) {
    assertSafeTarget(hostAlias);
    const match = findRealmHost(this.realms, hostAlias);
    if (!match) return await replaceHostKey(hostAlias, fingerprint);
    // Scan over the realm route; no credentials are needed to read a host key.
    return await replaceHostKey(hostAlias, fingerprint, {
      target: match.host.hostname,
      opts: realmSshOptions(match.host, null),
    });
  }

  async runCommandBatch(hostAlias, commands) {
    try {
      const results = [];
      let success = true;

      for (const command of commands) {
        const result = await this.runRemoteCommand(hostAlias, command);
        results.push(result);

        if (result.code !== 0) {
          success = false;
          // Continue executing remaining commands
        }
      }

      return {
        results,
        success
      };
    } catch (error) {
      debugLog(`Error during batch execution on ${hostAlias}: ${error.message}`);
      return {
        results: [{
          stdout: '',
          stderr: error instanceof Error ? error.message : String(error),
          code: 1
        }],
        success: false
      };
    }
  }
}

// Create MCP Server instance
function createMCPServer(sshClient) {
  const server = new Server(
    { name: "mcp-ssh-http", version: "1.1.0" },
    { capabilities: { tools: {} } }
  );

  // Handler for listing available tools
  server.setRequestHandler(ListToolsRequestSchema, async () => {
    debugLog("Received listTools request");
    return {
      tools: [
        {
          name: "listKnownHosts",
          description: "Returns a consolidated list of all known SSH hosts, prioritizing ~/.ssh/config entries first, then additional hosts from ~/.ssh/known_hosts",
          inputSchema: {
            type: "object",
            properties: {},
            required: [],
          },
        },
        {
          name: "runRemoteCommand",
          description: "Executes a shell command on an SSH host. Never prompts: a host seen for the first time is trusted and recorded; a host whose key CHANGED is refused with error.kind 'host_key_changed' and the fingerprint it presented (see replaceHostKey). error.kind explains any other ssh failure (auth_failed, no_route, timeout, client_setup). Hosts in a realm are reached with the MCP's own Vault-issued certificate; the result's realm field says which credential was used and, if Vault failed, why (vault_denied, vault_unavailable, vault_setup).",
          inputSchema: {
            type: "object",
            properties: {
              hostAlias: {
                type: "string",
                description: "Alias or hostname of the SSH host",
              },
              command: {
                type: "string",
                description: "The shell command to execute",
              },
            },
            required: ["hostAlias", "command"],
          },
        },
        {
          name: "getHostInfo",
          description: "Returns all configuration details for an SSH host",
          inputSchema: {
            type: "object",
            properties: {
              hostAlias: {
                type: "string",
                description: "Alias or hostname of the SSH host",
              },
            },
            required: ["hostAlias"],
          },
        },
        {
          name: "checkConnectivity",
          description: "Checks if an SSH connection to the host is possible",
          inputSchema: {
            type: "object",
            properties: {
              hostAlias: {
                type: "string",
                description: "Alias or hostname of the SSH host",
              },
            },
            required: ["hostAlias"],
          },
        },
        {
          name: "uploadFile",
          description: "Uploads a local file to an SSH host",
          inputSchema: {
            type: "object",
            properties: {
              hostAlias: {
                type: "string",
                description: "Alias or hostname of the SSH host",
              },
              localPath: {
                type: "string",
                description: "Path to the local file",
              },
              remotePath: {
                type: "string",
                description: "Path on the remote host",
              },
            },
            required: ["hostAlias", "localPath", "remotePath"],
          },
        },
        {
          name: "downloadFile",
          description: "Downloads a file from an SSH host",
          inputSchema: {
            type: "object",
            properties: {
              hostAlias: {
                type: "string",
                description: "Alias or hostname of the SSH host",
              },
              remotePath: {
                type: "string",
                description: "Path on the remote host",
              },
              localPath: {
                type: "string",
                description: "Path to the local destination",
              },
            },
            required: ["hostAlias", "remotePath", "localPath"],
          },
        },
        {
          name: "accessStatus",
          description: "Shows, per realm (a group of hosts reached with a Vault-issued SSH certificate), whether Vault credentials are configured and until when the MCP's certificate is valid. With renew=true it asks Vault for a fresh certificate now and reports why that failed, if it did. Use it when a realm host fails with a vault_* error kind.",
          inputSchema: {
            type: "object",
            properties: {
              renew: {
                type: "boolean",
                description: "Request a new certificate from Vault now",
              },
            },
            required: [],
          },
        },
        {
          name: "replaceHostKey",
          description: "Replaces the recorded SSH host key of a host after an error.kind 'host_key_changed'. Use ONLY after telling the user the presented fingerprint and getting their explicit confirmation that the change is expected (for example the host was reinstalled). The fingerprint argument must be the one the host presents; if it does not match, nothing changes and the current fingerprints are returned.",
          inputSchema: {
            type: "object",
            properties: {
              hostAlias: {
                type: "string",
                description: "Alias or hostname of the SSH host",
              },
              fingerprint: {
                type: "string",
                description: "The SHA256:... fingerprint the user confirmed",
              },
            },
            required: ["hostAlias", "fingerprint"],
          },
        },
        {
          name: "runCommandBatch",
          description: "Executes multiple shell commands sequentially on an SSH host",
          inputSchema: {
            type: "object",
            properties: {
              hostAlias: {
                type: "string",
                description: "Alias or hostname of the SSH host",
              },
              commands: {
                type: "array",
                items: { type: "string" },
                description: "List of shell commands to execute",
              },
            },
            required: ["hostAlias", "commands"],
          },
        },
      ],
    };
  });

  // Handler for tool calls
  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    const { name, arguments: args } = request.params;
    debugLog(`Received callTool request for tool: ${name}`);

    if (!args && name !== "listKnownHosts" && name !== "accessStatus") {
      throw new Error(`No arguments provided for tool: ${name}`);
    }

    try {
      switch (name) {
        case "listKnownHosts": {
          const hosts = await sshClient.listKnownHosts();
          return {
            content: [{ type: "text", text: JSON.stringify(hosts, null, 2) }],
          };
        }

        case "runRemoteCommand": {
          const result = await sshClient.runRemoteCommand(
            args.hostAlias,
            args.command
          );
          return {
            content: [{ type: "text", text: JSON.stringify(result, null, 2) }],
          };
        }

        case "getHostInfo": {
          const hostInfo = await sshClient.getHostInfo(args.hostAlias);
          return {
            content: [{ type: "text", text: JSON.stringify(hostInfo, null, 2) }],
          };
        }

        case "checkConnectivity": {
          const status = await sshClient.checkConnectivity(args.hostAlias);
          return {
            content: [{ type: "text", text: JSON.stringify(status, null, 2) }],
          };
        }

        case "uploadFile": {
          const result = await sshClient.uploadFile(
            args.hostAlias,
            args.localPath,
            args.remotePath
          );
          return {
            content: [{ type: "text", text: JSON.stringify(result, null, 2) }],
          };
        }

        case "downloadFile": {
          const result = await sshClient.downloadFile(
            args.hostAlias,
            args.remotePath,
            args.localPath
          );
          return {
            content: [{ type: "text", text: JSON.stringify(result, null, 2) }],
          };
        }

        case "accessStatus": {
          const result = await sshClient.accessStatus(Boolean(args?.renew));
          return {
            content: [{ type: "text", text: JSON.stringify(result, null, 2) }],
          };
        }

        case "replaceHostKey": {
          const result = await sshClient.replaceHostKey(args.hostAlias, args.fingerprint);
          return {
            content: [{ type: "text", text: JSON.stringify(result, null, 2) }],
          };
        }

        case "runCommandBatch": {
          const result = await sshClient.runCommandBatch(
            args.hostAlias,
            args.commands
          );
          return {
            content: [{ type: "text", text: JSON.stringify(result, null, 2) }],
          };
        }

        default:
          throw new Error(`Unknown tool: ${name}`);
      }
    } catch (error) {
      debugLog(`Error executing tool ${name}: ${error.message}`);
      return {
        content: [
          {
            type: "text",
            text: JSON.stringify({
              error: error instanceof Error ? error.message : String(error),
            }),
          },
        ],
      };
    }
  });

  return server;
}

// Main function to start the HTTP server
async function main() {
  try {
    const app = express();

    // Enable CORS
    app.use(cors({
      origin: '*',
      methods: ['GET', 'POST', 'OPTIONS'],
      allowedHeaders: ['Content-Type', 'Authorization'],
    }));

    app.use(express.json());

    const sendAuthorizationServerMetadata = (_req, res) => {
      res.json(oauthAuthorizationServerMetadata);
    };

    const sendOpenIdConfiguration = (_req, res) => {
      res.json(openIdConfiguration);
    };

    const sendProtectedResourceMetadata = (_req, res) => {
      res.json(oauthProtectedResourceMetadata);
    };

    [
      '/.well-known/oauth-authorization-server',
      '/.well-known/oauth-authorization-server/:resourceId(*)',
    ].forEach(path => {
      app.get(path, sendAuthorizationServerMetadata);
    });

    [
      '/.well-known/openid-configuration',
      '/.well-known/openid-configuration/:resourceId(*)',
    ].forEach(path => {
      app.get(path, sendOpenIdConfiguration);
    });

    [
      '/.well-known/oauth-protected-resource',
      '/.well-known/oauth-protected-resource/:resourceId(*)',
    ].forEach(path => {
      app.get(path, sendProtectedResourceMetadata);
    });

    // Create SSH client instance
    debugLog("Initializing SSH client...");
    const sshClient = new SSHClient();

    debugLog("Creating MCP server...");
    const mcpServer = createMCPServer(sshClient);

    // Health check endpoints (primary: /healthz)
    app.get('/healthz', (req, res) => {
      res.json({ status: 'ok', server: 'mcp-ssh-http', version: '1.1.0' });
    });
    // Back-compat: /health
    app.get('/health', (req, res) => {
      res.json({ status: 'ok', server: 'mcp-ssh-http', version: '1.1.0' });
    });

    // Single unified endpoint implementing Streamable HTTP transport.
    // - POST /    : JSON-RPC over HTTP with streaming responses (chunked)
    // - GET  /    : SSE stream when client sends Accept: text/event-stream
    // - DELETE /  : Close stream/session (when applicable)
    const transport = new StreamableHTTPServerTransport({
      // Stateless mode fits proxy/load-balancer friendly patterns; set to undefined.
      // For stateful sessions with resumability, provide a generator, e.g., () => crypto.randomUUID()
      sessionIdGenerator: undefined,
      enableJsonResponse: true,
    });

    await mcpServer.connect(transport);

    app.all('/', async (req, res) => {
      try {
        await transport.handleRequest(req, res, req.body);
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        debugLog(`Transport error handling ${req.method} ${req.url}: ${msg}`);
        res.status(500).json({ jsonrpc: '2.0', error: { code: -32000, message: msg }, id: null });
      }
    });

    // Start the server
    const server = app.listen(PORT, HOST, () => {
      console.log(`MCP SSH HTTP Server running on http://${HOST}:${PORT}`);
      console.log(`Streamable HTTP endpoint (unified): http://${HOST}:${PORT}/`);
      console.log(`Health check: http://${HOST}:${PORT}/healthz`);
      console.log(`Debug mode: ${DEBUG}`);
    });

    // Graceful shutdown
    process.on('SIGTERM', () => {
      console.log('SIGTERM received, shutting down gracefully...');
      server.close(() => {
        console.log('Server closed');
        process.exit(0);
      });
    });

    process.on('SIGINT', () => {
      console.log('SIGINT received, shutting down gracefully...');
      server.close(() => {
        console.log('Server closed');
        process.exit(0);
      });
    });

  } catch (error) {
    console.error(`Error starting MCP SSH HTTP Server: ${error.message}`);
    process.exit(1);
  }
}

// Start the server
main().catch(error => {
  console.error(`Unhandled error: ${error.message}`);
  process.exit(1);
});
