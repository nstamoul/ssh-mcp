# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.2.0] - 2025-11-08

### Added
- **NEW FEATURE**: HTTP Server with Server-Sent Events (SSE) streaming support
- Added `server-http.mjs` - HTTP-based MCP server for network access
- Added `bin/mcp-ssh-http.js` - Binary wrapper for HTTP server
- Added HTTP server startup scripts (`start-http.sh`, `start-http-silent.sh`)
- Added `.env.example` - Environment variable configuration examples
- Added `HTTP-SERVER.md` - Comprehensive HTTP server documentation
- New npm scripts: `npm run start:http` and `npm run dev:http`

### Enhanced
- Dual transport support: STDIO (local) and HTTP/SSE (network)
- Environment-based configuration for HTTP mode (PORT, HOST, DEBUG)
- CORS support for web clients
- Health check endpoint (`/health`)
- Graceful shutdown handling for HTTP server
- Updated documentation with HTTP mode examples

### Dependencies
- Added `express` (^4.21.2) for HTTP server
- Added `cors` (^2.8.5) for Cross-Origin Resource Sharing

### Documentation
- Comprehensive HTTP server guide with deployment examples
- Docker and systemd deployment configurations
- Security best practices for network deployments
- Updated README with HTTP mode instructions
- Updated CLAUDE.md with HTTP server commands

## [1.1.0] - 2025-08-17

### Added
- **NEW FEATURE**: SSH config Include directive support
- Added recursive processing of Include directives in SSH configuration files
- Support for glob patterns in Include paths (e.g., `Include ~/.ssh/configs/*`)
- Enhanced SSH host discovery from included configuration files
- Added `glob` dependency for Include path pattern matching

### Enhanced
- Improved SSH configuration parsing to handle complex Include hierarchies
- Enhanced host discovery to recursively process all included config files
- Better error handling for malformed or inaccessible Include files

## [1.0.4] - 2025-08-17

### Security
- **SECURITY FIX**: Fixed command injection vulnerability in SSH operations (commit 5b9b9c5)
- **SECURITY FIX**: Upgraded `tmp` dependency to version 0.2.5 to address CVE vulnerability
- Fixed arbitrary temporary file/directory write via symbolic link in `tmp` package (GHSA-52f5-9888-hmc6)
- Added dependency overrides to ensure all transitive dependencies use secure `tmp` version
- Enhanced input validation and sanitization for SSH commands and file paths

### Technical
- Added `tmp: ">=0.2.4"` to devDependencies to force secure version
- Added npm overrides configuration to enforce secure tmp version across entire dependency tree
- Updated package-lock.json to reflect security fixes

## [1.0.3] - 2025-06-06

### Added
- Binary wrapper script (`bin/mcp-ssh.js`) for proper npx compatibility
- Fixed npx execution issues by implementing wrapper pattern

### Fixed
- NPX executable resolution using wrapper script approach
- Package binary configuration now points to proper wrapper

### Technical
- Added `bin/mcp-ssh.js` wrapper to handle npx execution
- Updated package.json bin configuration to use wrapper script

## [1.0.2] - 2025-06-06

### Fixed
- Build script temporary fix
- File permissions for executable

## [1.0.1] - 2025-06-06

### Fixed
- Initial package configuration
- File permissions

## [1.0.0] - 2025-06-06

### Added
- Initial release of MCP SSH Agent
- Support for all SSH operations via native ssh/scp commands
- Automatic SSH host discovery from ~/.ssh/config and ~/.ssh/known_hosts
- Functions: listKnownHosts, runRemoteCommand, getHostInfo, checkConnectivity, uploadFile, downloadFile, runCommandBatch
- Claude Desktop integration support
- NPM package distribution via @aiondadotcom/mcp-ssh
- npx compatibility for easy installation and usage

### Features
- Native SSH command execution for maximum compatibility
- Silent mode for MCP clients (MCP_SILENT=true)
- Comprehensive error handling with timeouts
- Batch command execution support
- File upload/download via scp
- SSH connectivity testing

### Documentation
- Complete README with Claude Desktop setup instructions
- Usage examples and troubleshooting guide
- Professional npm package configuration
