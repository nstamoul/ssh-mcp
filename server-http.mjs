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
import { randomBytes, createHash } from 'crypto';

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
const OAUTH_RESOURCE = process.env.OAUTH_RESOURCE || process.env.MCP_RESOURCE || 'https://mcp.nstam.eu/ssh';
const PUBLIC_BASE_URL = (process.env.OAUTH_BASE_URL || process.env.PUBLIC_BASE_URL || OAUTH_RESOURCE).replace(/\/$/, '');
const OAUTH_ISSUER = process.env.OAUTH_ISSUER || PUBLIC_BASE_URL;
const OAUTH_AUTHORIZATION_ENDPOINT = process.env.OAUTH_AUTHORIZATION_ENDPOINT || `${PUBLIC_BASE_URL}/oauth/authorize`;
const OAUTH_TOKEN_ENDPOINT =
  process.env.OAUTH_TOKEN_ENDPOINT || process.env.OAUTH_TOKEN_URL || `${PUBLIC_BASE_URL}/oauth/token`;
const OAUTH_REGISTRATION_ENDPOINT = process.env.OAUTH_REGISTRATION_ENDPOINT || `${PUBLIC_BASE_URL}/oauth/register`;
const OAUTH_JWKS_URI = process.env.OAUTH_JWKS_URI || `${PUBLIC_BASE_URL}/oauth/jwks.json`;
const OAUTH_USERINFO_ENDPOINT = process.env.OAUTH_USERINFO_ENDPOINT || `${PUBLIC_BASE_URL}/oauth/userinfo`;
const OAUTH_INTROSPECTION_ENDPOINT = process.env.OAUTH_INTROSPECTION_ENDPOINT || `${PUBLIC_BASE_URL}/oauth/introspect`;
const OAUTH_DEVICE_AUTHORIZATION_ENDPOINT =
  process.env.OAUTH_DEVICE_AUTHORIZATION_ENDPOINT || `${PUBLIC_BASE_URL}/oauth/device`;
const OAUTH_SCOPES = (process.env.OAUTH_SCOPE || process.env.OAUTH_SCOPES || '')
  .split(/[\s,]+/)
  .map(scope => scope.trim())
  .filter(scope => scope.length > 0);
const OAUTH_CLIENT_ID = process.env.OAUTH_CLIENT_ID || 'mcp';
const OAUTH_CLIENT_SECRET = process.env.OAUTH_CLIENT_SECRET || process.env.CLIENT_SECRET;

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
  registration_endpoint: OAUTH_REGISTRATION_ENDPOINT,
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

const CLAUDE_CLIENT_ID = process.env.CLAUDE_CLIENT_ID || 'mcp';
const CLAUDE_REDIRECT_URIS = (process.env.CLAUDE_REDIRECT_URIS || 'https://claude.ai/api/mcp/auth_callback')
  .split(',')
  .map(uri => uri.trim())
  .filter(uri => uri.length > 0);
const CLAUDE_SCOPES = process.env.CLAUDE_SCOPES || 'claudeai';
const CLAUDE_CLIENT_SECRET = process.env.CLAUDE_CLIENT_SECRET || undefined;
const CLAUDE_TOKEN_AUTH_METHOD = CLAUDE_CLIENT_SECRET ? 'client_secret_basic' : 'none';

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

function seedStaticClients() {
  if (CLAUDE_CLIENT_ID && CLAUDE_REDIRECT_URIS.length) {
    registeredClients.set(CLAUDE_CLIENT_ID, {
      client_id: CLAUDE_CLIENT_ID,
      client_secret: CLAUDE_CLIENT_SECRET,
      redirect_uris: CLAUDE_REDIRECT_URIS,
      grant_types: ['authorization_code'],
      response_types: ['code'],
      scope: CLAUDE_SCOPES,
      token_endpoint_auth_method: CLAUDE_TOKEN_AUTH_METHOD,
    });
  }
}

// Simple in-memory stores for OAuth entities
const registeredClients = new Map();
const authorizationCodes = new Map();
const accessTokens = new Map();

seedStaticClients();

const AUTH_CODE_TTL_MS = Number(process.env.OAUTH_AUTH_CODE_TTL || 5 * 60 * 1000);
const ACCESS_TOKEN_TTL_SECONDS = Number(process.env.OAUTH_ACCESS_TOKEN_TTL || 3600);
const ACCESS_TOKEN_TTL_MS = ACCESS_TOKEN_TTL_SECONDS * 1000;

const STATIC_TOKENS = [
  process.env.MCP_SSH_TOKEN,
  process.env.MCP_API_KEY,
  process.env.MCP_ACCESS_TOKEN,
  process.env.MCP_STATIC_TOKEN,
].filter(Boolean);

const baseScopeString = OAUTH_SCOPES.length ? OAUTH_SCOPES.join(' ') : undefined;

function base64UrlEncode(buffer) {
  return buffer
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/g, '');
}

function generateRandomString(bytes = 32) {
  return base64UrlEncode(randomBytes(bytes));
}

function resolveAuthenticatedUser(req) {
  const pickHeader = value => (Array.isArray(value) ? value[0] : value);
  return (
    pickHeader(req.headers['remote-user']) ||
    pickHeader(req.headers['remote_user']) ||
    pickHeader(req.headers['x-remote-user']) ||
    pickHeader(req.headers['x-remote_user'])
  );
}

function validateBearerToken(token) {
  if (!token) {
    return null;
  }

  if (STATIC_TOKENS.includes(token)) {
    return {
      clientId: 'static-token',
      user: 'static',
      scope: baseScopeString,
      issuedAt: 0,
      expiresAt: Infinity,
    };
  }

  const record = accessTokens.get(token);
  if (!record) {
    return null;
  }

  if (record.expiresAt < Date.now()) {
    accessTokens.delete(token);
    return null;
  }

  return record;
}

function requireAccessToken(req, res, next) {
  if (req.method === 'OPTIONS') {
    return next();
  }

  const authHeader = req.headers['authorization'];
  let token;
  if (authHeader && /^Bearer\s+/i.test(authHeader)) {
    token = authHeader.replace(/^Bearer\s+/i, '').trim();
  } else if (req.query && typeof req.query.access_token === 'string') {
    token = req.query.access_token;
  }

  const tokenRecord = validateBearerToken(token);
  if (!tokenRecord) {
    return res.status(401).json({ error: 'invalid_token', error_description: 'Missing or invalid access token' });
  }

  req.oauth = tokenRecord;
  return next();
}

function verifyPkce(codeChallenge, codeVerifier, method = 'S256') {
  if (!codeChallenge) {
    return false;
  }

  if (!codeVerifier) {
    return false;
  }

  if (method && method !== 'S256') {
    return false;
  }

  const digest = createHash('sha256').update(codeVerifier).digest();
  const expected = base64UrlEncode(digest);
  return expected === codeChallenge;
}

function authenticateClient(req, suppliedClientId, suppliedClientSecret) {
  let clientId = suppliedClientId;
  let clientSecret = suppliedClientSecret;

  const authHeader = req.headers['authorization'];
  if ((!clientId || !clientSecret) && authHeader && authHeader.startsWith('Basic ')) {
    const decoded = Buffer.from(authHeader.slice('Basic '.length), 'base64').toString('utf8');
    const separatorIndex = decoded.indexOf(':');
    if (separatorIndex >= 0) {
      const authId = decoded.slice(0, separatorIndex);
      const authSecret = decoded.slice(separatorIndex + 1);
      if (!clientId) {
        clientId = authId;
      }
      if (!clientSecret) {
        clientSecret = authSecret;
      }
    }
  }

  if (!clientId) {
    return null;
  }

  const client = registeredClients.get(clientId);
  if (!client) {
    return null;
  }

  if (client.token_endpoint_auth_method !== 'none') {
    if (!clientSecret || client.client_secret !== clientSecret) {
      return null;
    }
  }

  return client;
}

function getClientScopes(client) {
  if (!client || !client.scope) {
    return OAUTH_SCOPES;
  }

  return client.scope.split(/\s+/).filter(Boolean);
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
  }

  async listKnownHosts() {
    return await this.configParser.getAllKnownHosts();
  }

  async runRemoteCommand(hostAlias, command) {
    try {
      // Use execFile for security - prevents command injection
      debugLog(`Executing: ssh ${hostAlias} ${command}`);

      const { stdout, stderr } = await execFileAsync('ssh', [hostAlias, command], {
        timeout: 30000, // 30 second timeout
        maxBuffer: 1024 * 1024 * 10 // 10MB buffer
      });

      return {
        stdout: stdout || '',
        stderr: stderr || '',
        code: 0
      };
    } catch (error) {
      debugLog(`Error executing command on ${hostAlias}: ${error.message}`);
      return {
        stdout: error.stdout || '',
        stderr: error.stderr || error.message,
        code: error.code || 1
      };
    }
  }

  async getHostInfo(hostAlias) {
    const hosts = await this.configParser.processIncludeDirectives(this.configParser.configPath);
    return hosts.find(host => host.alias === hostAlias || host.hostname === hostAlias) || null;
  }

  async checkConnectivity(hostAlias) {
    try {
      // Simple connectivity test using ssh
      const result = await this.runRemoteCommand(hostAlias, 'echo connected');
      const connected = result.code === 0 && result.stdout.trim() === 'connected';

      return {
        connected,
        message: connected ? 'Connection successful' : 'Connection failed'
      };
    } catch (error) {
      debugLog(`Connectivity error with ${hostAlias}: ${error.message}`);
      return {
        connected: false,
        message: error instanceof Error ? error.message : String(error)
      };
    }
  }

  async uploadFile(hostAlias, localPath, remotePath) {
    try {
      debugLog(`Executing: scp ${localPath} ${hostAlias}:${remotePath}`);

      await execFileAsync('scp', [localPath, `${hostAlias}:${remotePath}`], {
        timeout: 60000 // 60 second timeout for file transfer
      });
      return true;
    } catch (error) {
      debugLog(`Error uploading file to ${hostAlias}: ${error.message}`);
      return false;
    }
  }

  async downloadFile(hostAlias, remotePath, localPath) {
    try {
      debugLog(`Executing: scp ${hostAlias}:${remotePath} ${localPath}`);

      await execFileAsync('scp', [`${hostAlias}:${remotePath}`, localPath], {
        timeout: 60000 // 60 second timeout for file transfer
      });
      return true;
    } catch (error) {
      debugLog(`Error downloading file from ${hostAlias}: ${error.message}`);
      return false;
    }
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
          description: "Executes a shell command on an SSH host",
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

    if (!args && name !== "listKnownHosts") {
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
          const success = await sshClient.uploadFile(
            args.hostAlias,
            args.localPath,
            args.remotePath
          );
          return {
            content: [{ type: "text", text: JSON.stringify({ success }, null, 2) }],
          };
        }

        case "downloadFile": {
          const success = await sshClient.downloadFile(
            args.hostAlias,
            args.remotePath,
            args.localPath
          );
          return {
            content: [{ type: "text", text: JSON.stringify({ success }, null, 2) }],
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
    app.use(express.urlencoded({ extended: false }));

    const sendAuthorizationServerMetadata = (_req, res) => {
      res.json(oauthAuthorizationServerMetadata);
    };

    const sendOpenIdConfiguration = (_req, res) => {
      res.json(openIdConfiguration);
    };

    const sendProtectedResourceMetadata = (_req, res) => {
      res.json(oauthProtectedResourceMetadata);
    };

    const registerGetRoutes = (paths, ...handlers) => {
      paths.forEach(path => app.get(path, ...handlers));
    };

    const registerPostRoutes = (paths, ...handlers) => {
      paths.forEach(path => app.post(path, ...handlers));
    };

    registerGetRoutes(
      [
        '/.well-known/oauth-authorization-server',
        '/.well-known/oauth-authorization-server/:resourceId(*)',
        '/ssh/.well-known/oauth-authorization-server',
        '/ssh/.well-known/oauth-authorization-server/:resourceId(*)',
      ],
      sendAuthorizationServerMetadata,
    );

    registerGetRoutes(
      [
        '/.well-known/openid-configuration',
        '/.well-known/openid-configuration/:resourceId(*)',
        '/ssh/.well-known/openid-configuration',
        '/ssh/.well-known/openid-configuration/:resourceId(*)',
      ],
      sendOpenIdConfiguration,
    );

    registerGetRoutes(
      [
        '/.well-known/oauth-protected-resource',
        '/.well-known/oauth-protected-resource/:resourceId(*)',
        '/ssh/.well-known/oauth-protected-resource',
        '/ssh/.well-known/oauth-protected-resource/:resourceId(*)',
      ],
      sendProtectedResourceMetadata,
    );

    registerPostRoutes(['/oauth/register', '/register', '/ssh/oauth/register'], (req, res) => {
      const body = typeof req.body === 'object' && req.body !== null ? req.body : {};
      const redirectUris = Array.isArray(body.redirect_uris) ? body.redirect_uris.filter(uri => typeof uri === 'string') : [];

      if (!redirectUris.length) {
        return res.status(400).json({
          error: 'invalid_client_metadata',
          error_description: "The 'redirect_uris' parameter is required",
        });
      }

      const grantTypes =
        Array.isArray(body.grant_types) && body.grant_types.length ? body.grant_types : ['authorization_code'];
      const responseTypes =
        Array.isArray(body.response_types) && body.response_types.length ? body.response_types : ['code'];
      const scopeString = body.scope || baseScopeString;
      const tokenEndpointAuthMethod = body.token_endpoint_auth_method || 'client_secret_basic';
      const clientId = generateRandomString(24);
      const clientSecret = tokenEndpointAuthMethod === 'none' ? undefined : generateRandomString(32);
      const issuedAt = Math.floor(Date.now() / 1000);

      const clientRecord = {
        client_id: clientId,
        client_secret: clientSecret,
        client_name: body.client_name,
        redirect_uris: redirectUris,
        grant_types: grantTypes,
        response_types: responseTypes,
        scope: scopeString,
        token_endpoint_auth_method: tokenEndpointAuthMethod,
      };

      registeredClients.set(clientId, clientRecord);

      const responsePayload = sanitizeMetadata({
        ...clientRecord,
        client_id_issued_at: issuedAt,
        client_secret_expires_at: 0,
        registration_client_uri: `${PUBLIC_BASE_URL}/oauth/clients/${clientId}`,
      });

      res.status(201).json(responsePayload);
    });

    registerGetRoutes(['/oauth/authorize', '/authorize', '/ssh/oauth/authorize'], (req, res) => {
      const pickFirst = value => (Array.isArray(value) ? value[0] : value);
      const responseType = pickFirst(req.query.response_type);
      const clientId = pickFirst(req.query.client_id);
      const redirectUri = pickFirst(req.query.redirect_uri);
      const state = pickFirst(req.query.state);
      const codeChallenge = pickFirst(req.query.code_challenge);
      const codeChallengeMethod = pickFirst(req.query.code_challenge_method) || 'S256';
      const scope = pickFirst(req.query.scope);

      const sendOAuthError = (error, description) => {
        if (redirectUri && typeof redirectUri === 'string') {
          try {
            const url = new URL(redirectUri);
            url.searchParams.set('error', error);
            if (description) {
              url.searchParams.set('error_description', description);
            }
            if (state) {
              url.searchParams.set('state', state);
            }
            return res.redirect(url.toString());
          } catch {
            // fall through to JSON response
          }
        }
        return res.status(400).json({ error, error_description: description });
      };

      if (responseType !== 'code') {
        return sendOAuthError('unsupported_response_type', 'Only response_type=code is supported');
      }

      const client = clientId ? registeredClients.get(clientId) : null;
      if (!client) {
        return sendOAuthError('unauthorized_client', 'Unknown client_id');
      }

      const clientRedirectUris = Array.isArray(client.redirect_uris) ? client.redirect_uris : [];
      if (typeof redirectUri !== 'string' || !clientRedirectUris.includes(redirectUri)) {
        return sendOAuthError('invalid_request', 'The redirect_uri is not registered for this client');
      }

      if (!codeChallenge) {
        return sendOAuthError('invalid_request', 'Missing PKCE code_challenge');
      }

      if (codeChallengeMethod !== 'S256') {
        return sendOAuthError('invalid_request', 'Only S256 code_challenge_method is supported');
      }

      const user = resolveAuthenticatedUser(req);
      if (!user) {
        return res.status(401).send('User authentication required');
      }

      const requestedScopes =
        typeof scope === 'string' && scope.length ? scope.split(/\s+/).filter(Boolean) : getClientScopes(client);
      const allowedScopes = new Set(getClientScopes(client));
      const invalidScope = requestedScopes.find(sc => !allowedScopes.has(sc));
      if (invalidScope) {
        return sendOAuthError('invalid_scope', `Scope '${invalidScope}' is not permitted for this client`);
      }

      const code = generateRandomString(48);
      authorizationCodes.set(code, {
        clientId,
        redirectUri,
        codeChallenge,
        codeChallengeMethod,
        scope: requestedScopes,
        user,
        expiresAt: Date.now() + AUTH_CODE_TTL_MS,
      });

      const redirectUrl = new URL(redirectUri);
      redirectUrl.searchParams.set('code', code);
      if (state) {
        redirectUrl.searchParams.set('state', state);
      }

      return res.redirect(redirectUrl.toString());
    });

    registerPostRoutes(['/oauth/token', '/token', '/ssh/oauth/token'], (req, res) => {
      const grantType = req.body?.grant_type;

      if (grantType !== 'authorization_code') {
        return res
          .status(400)
          .json({ error: 'unsupported_grant_type', error_description: 'Only authorization_code is supported' });
      }

      const client = authenticateClient(req, req.body.client_id, req.body.client_secret);
      if (!client) {
        return res.status(401).json({ error: 'invalid_client', error_description: 'Client authentication failed' });
      }

      const { code, redirect_uri: redirectUri, code_verifier: codeVerifier } = req.body;
      if (!code) {
        return res.status(400).json({ error: 'invalid_request', error_description: 'Missing authorization code' });
      }

      const storedCode = authorizationCodes.get(code);
      if (!storedCode || storedCode.clientId !== client.client_id) {
        return res.status(400).json({ error: 'invalid_grant', error_description: 'Authorization code is invalid' });
      }

      if (storedCode.expiresAt < Date.now()) {
        authorizationCodes.delete(code);
        return res.status(400).json({ error: 'invalid_grant', error_description: 'Authorization code expired' });
      }

      if (storedCode.redirectUri !== redirectUri) {
        return res
          .status(400)
          .json({ error: 'invalid_grant', error_description: 'redirect_uri does not match original request' });
      }

      if (!verifyPkce(storedCode.codeChallenge, codeVerifier, storedCode.codeChallengeMethod)) {
        return res.status(400).json({ error: 'invalid_grant', error_description: 'PKCE verification failed' });
      }

      authorizationCodes.delete(code);

      const accessToken = generateRandomString(48);
      const expiresAt = Date.now() + ACCESS_TOKEN_TTL_MS;
      const scope = storedCode.scope?.join(' ') || baseScopeString;
      const tokenRecord = {
        accessToken,
        clientId: client.client_id,
        user: storedCode.user,
        scope,
        issuedAt: Date.now(),
        expiresAt,
      };

      accessTokens.set(accessToken, tokenRecord);

      return res.json({
        access_token: accessToken,
        token_type: 'Bearer',
        expires_in: ACCESS_TOKEN_TTL_SECONDS,
        scope,
      });
    });

    registerGetRoutes(['/oauth/jwks.json', '/jwks.json', '/ssh/oauth/jwks.json'], (_req, res) => {
      res.json({ keys: [] });
    });

    registerPostRoutes(['/oauth/introspect', '/introspect', '/ssh/oauth/introspect'], (req, res) => {
      const token = req.body?.token;
      const record = validateBearerToken(token);
      if (!record) {
        return res.json({ active: false });
      }

      return res.json({
        active: true,
        client_id: record.clientId,
        username: record.user,
        scope: record.scope,
        exp: Math.floor(record.expiresAt / 1000),
        iat: Math.floor(record.issuedAt / 1000),
        token_type: 'access_token',
      });
    });

    registerGetRoutes(['/oauth/userinfo', '/userinfo', '/ssh/oauth/userinfo'], requireAccessToken, (req, res) => {
      res.json({
        sub: req.oauth.user || req.oauth.clientId,
        name: req.oauth.user,
        preferred_username: req.oauth.user,
      });
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

    app.all('/', requireAccessToken, async (req, res) => {
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
