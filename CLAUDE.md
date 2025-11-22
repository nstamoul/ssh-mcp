# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is MCP SSH Agent (@aiondadotcom/mcp-ssh) - a Model Context Protocol (MCP) server that provides SSH operations for AI assistants like Claude Desktop. The project supports both STDIO and HTTP/SSE transports and uses native SSH commands (`ssh`, `scp`) rather than JavaScript SSH libraries for maximum reliability and compatibility.

## Development Commands

### Basic Operations (STDIO Mode)
- `npm start` - Start the MCP server (same as `npm run dev`)
- `npm run dev` - Start the MCP server with debug output
- `npm run build` - Currently a no-op (echo "Build skipped")
- `npm test` - Currently a no-op (echo "No tests specified")

### HTTP Server Operations
- `npm run start:http` - Start the HTTP server (production mode)
- `npm run dev:http` - Start the HTTP server with debug output
- `./start-http.sh` - Start the HTTP server with debug output
- `./start-http-silent.sh` - Start the HTTP server in silent mode
- `node server-http.mjs` - Direct HTTP server execution

### Development Scripts (STDIO Mode)
- `./start.sh` - Start the STDIO server with debug output
- `./start-silent.sh` - Start the STDIO server in silent mode
- `node server-simple.mjs` - Direct STDIO server execution

### Publishing
- `npm version patch|minor|major` - Bump version and create git tag
- `npm publish` - Publish to npm (see PUBLISHING.md for details)
- `npm pack` - Create tarball for testing

### DXT Package Building
- `npm run build:dxt` - Build Desktop Extension (.dxt) package
- `./scripts/build-dxt.sh` - Direct build script execution

## Architecture

### Main Entry Points
- `server-simple.mjs` - STDIO-based MCP server (default, for local use with Claude Desktop)
- `server-http.mjs` - HTTP-based MCP server with SSE streaming (for remote/network access)

### Source Structure (Development)
- `src/` - TypeScript source files (currently not compiled/used in production)
  - `ssh-client.ts` - SSH operations using node-ssh library (development version)
  - `ssh-config-parser.ts` - SSH config parsing utilities
  - `types.ts` - TypeScript type definitions
- `bin/mcp-ssh.js` - Binary wrapper for STDIO server (npx compatibility)
- `bin/mcp-ssh-http.js` - Binary wrapper for HTTP server (npx compatibility)

### Key Design Decisions
1. **Native SSH Tools**: Uses system `ssh` and `scp` commands rather than JavaScript SSH libraries for reliability
2. **Self-contained**: Both server implementations include all code inline to avoid ESM import issues
3. **Dual Transport**: Supports both STDIO (local) and HTTP/SSE (network) transports
4. **Dual Implementation**: TypeScript source in `src/` for development, JavaScript implementations in `server-*.mjs` for production
5. **Silent Mode**: STDIO server uses `MCP_SILENT` environment variable; HTTP server uses `DEBUG` environment variable

## SSH Configuration Integration

The agent automatically discovers SSH hosts from:
- `~/.ssh/config` - Primary source for host configurations
- `~/.ssh/known_hosts` - Additional hosts not in config

Host discovery prioritizes SSH config entries first, then adds additional hosts from known_hosts.

## MCP Tools Provided

1. **listKnownHosts()** - Lists all discovered SSH hosts
2. **runRemoteCommand(hostAlias, command)** - Execute commands via SSH
3. **getHostInfo(hostAlias)** - Get host configuration details
4. **checkConnectivity(hostAlias)** - Test SSH connectivity
5. **uploadFile(hostAlias, localPath, remotePath)** - Upload files via SCP
6. **downloadFile(hostAlias, remotePath, localPath)** - Download files via SCP
7. **runCommandBatch(hostAlias, commands)** - Execute multiple commands sequentially

## Testing and Debugging

### Manual Testing
```bash
# Test as MCP server
npx @aiondadotcom/mcp-ssh

# Test with debug output
MCP_SILENT=false npx @aiondadotcom/mcp-ssh

# Test installation
npm pack
npm install -g ./aiondadotcom-mcp-ssh-*.tgz
mcp-ssh
```

### Integration Testing
Configure in Claude Desktop's `claude_desktop_config.json`:
```json
{
  "mcpServers": {
    "mcp-ssh": {
      "command": "npx",
      "args": ["@aiondadotcom/mcp-ssh"]
    }
  }
}
```

## Dependencies

### Production Dependencies
- `@modelcontextprotocol/sdk` - MCP protocol implementation (STDIO and SSE transports)
- `ssh-config` - SSH configuration file parsing
- `express` - HTTP server framework (for HTTP mode)
- `cors` - Cross-Origin Resource Sharing middleware (for HTTP mode)
- `glob` - File pattern matching for SSH config includes
- Node.js built-ins: `child_process`, `fs/promises`, `os`, `path`

### Development Dependencies
- `@anthropic-ai/dxt` - Desktop Extension packaging tools
- TypeScript and type definitions

## Desktop Extension Support

The project supports Desktop Extensions (.dxt) for easy installation in Claude Desktop:

- `manifest.json` - DXT package manifest with server configuration
- `scripts/build-dxt.sh` - Build script that creates .dxt packages in `build/` directory
- `.dxt` files are ZIP archives containing the manifest and server files
- Built packages are excluded from git via `.gitignore` but can be uploaded to GitHub releases

## Important Notes

- The project is ESM-only (`"type": "module"` in package.json)
- Production code is in `server-simple.mjs` (STDIO) and `server-http.mjs` (HTTP), not compiled from TypeScript
- SSH operations require properly configured SSH keys and host access
- The agent can run in two modes:
  - **STDIO mode**: For local use with Claude Desktop (default)
  - **HTTP mode**: For remote/network access via HTTP with SSE streaming
- DXT packages provide one-click installation alternative to manual JSON configuration
- For detailed HTTP server documentation, see `HTTP-SERVER.md`
- Configuration files:
  - `.env.example` - Environment variable examples for HTTP server
  - `HTTP-SERVER.md` - Complete HTTP server documentation