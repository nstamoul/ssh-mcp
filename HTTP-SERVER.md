# MCP SSH HTTP Server

This document describes how to run and use the MCP SSH server as an HTTP streamable server using Server-Sent Events (SSE).

## Overview

The HTTP server provides the same SSH operations as the STDIO version but over HTTP with SSE streaming support. This allows the MCP SSH server to be accessed remotely over a network and integrated with web-based applications.

## Features

- **HTTP/SSE Transport**: Uses Server-Sent Events for real-time streaming
- **CORS Enabled**: Cross-Origin Resource Sharing enabled for web clients
- **Health Check**: Built-in health check endpoint
- **Same Tools**: All SSH tools available in STDIO mode work in HTTP mode
- **Configurable**: Environment variables for port, host, and debug settings

## Installation

Install the package and dependencies:

```bash
npm install @aiondadotcom/mcp-ssh
```

## Running the HTTP Server

### Recommended: Docker Deployment

For production deployment, we recommend using Docker:

```bash
# Build and start
make build && make up

# View logs
make logs

# Check status
make health
```

See [DOCKER.md](DOCKER.md) and [DEPLOYMENT.md](DEPLOYMENT.md) for complete Docker deployment instructions.

### Alternative: Using npm scripts

```bash
# Start HTTP server (production)
npm run start:http

# Start HTTP server with debug logging
npm run dev:http
```

### Using the binary

```bash
# After npm install -g
mcp-ssh-http

# Or via npx
npx @aiondadotcom/mcp-ssh-http
```

### Direct execution

```bash
node server-http.mjs
```

## Configuration

Configure the server using environment variables. You can create a `.env` file or set them in your shell:

```bash
# Port to listen on (default: 3009)
export PORT=3009

# Host to bind to (default: 0.0.0.0)
export HOST=0.0.0.0

# Enable debug logging (default: false)
export DEBUG=true

# Run the server
npm run start:http
```

### Configuration Options

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | `3009` | TCP port to listen on |
| `HOST` | `0.0.0.0` | IP address to bind to (use `127.0.0.1` for localhost only) |
| `DEBUG` | `false` | Enable detailed debug logging |

## API Endpoints

The HTTP server exposes the following endpoints:

### Health Check

```
GET /health
```

Returns the server status and version.

**Response:**
```json
{
  "status": "ok",
  "server": "mcp-ssh-http",
  "version": "1.1.0"
}
```

### SSE Endpoint

```
GET /sse
```

Establishes a Server-Sent Events connection for MCP protocol communication. This is the main endpoint for MCP clients.

### Message Endpoint

```
POST /message
```

Accepts MCP protocol messages from clients. Used in conjunction with the SSE endpoint.

## Usage Examples

### Using with MCP Client

```javascript
// Example: Connect to MCP SSH HTTP server
const mcpClient = new MCPClient({
  transport: {
    type: 'http',
    url: 'http://localhost:3009'
  }
});

// List all SSH hosts
const hosts = await mcpClient.callTool('listKnownHosts', {});
console.log(hosts);

// Run a remote command
const result = await mcpClient.callTool('runRemoteCommand', {
  hostAlias: 'myserver',
  command: 'uptime'
});
console.log(result);
```

### Using with curl

Test the health endpoint:

```bash
curl http://localhost:3009/health
```

### Using with Claude Desktop

Configure Claude Desktop to use the HTTP server by adding to `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "mcp-ssh-http": {
      "url": "http://localhost:3009/sse"
    }
  }
}
```

## Available Tools

The HTTP server provides the same MCP tools as the STDIO version:

1. **listKnownHosts()** - Lists all discovered SSH hosts
2. **runRemoteCommand(hostAlias, command)** - Execute commands via SSH
3. **getHostInfo(hostAlias)** - Get host configuration details
4. **checkConnectivity(hostAlias)** - Test SSH connectivity
5. **uploadFile(hostAlias, localPath, remotePath)** - Upload files via SCP
6. **downloadFile(hostAlias, remotePath, localPath)** - Download files via SCP
7. **runCommandBatch(hostAlias, commands)** - Execute multiple commands sequentially

See the main README for detailed tool documentation.

## Security Considerations

### Network Security

- **Localhost Only**: For local use, bind to `127.0.0.1` instead of `0.0.0.0`
- **Firewall**: Use firewall rules to restrict access to the port
- **Reverse Proxy**: Consider using nginx or Apache as a reverse proxy with TLS
- **Authentication**: Add authentication layer (JWT, OAuth) for production use

### SSH Security

- The server uses native SSH commands (`ssh`, `scp`) with proper key authentication
- Command injection is prevented by using `execFile` with argument arrays
- SSH operations require properly configured SSH keys and host access
- No passwords are handled or stored by the server

### Recommended Production Setup

For production deployments:

1. **Use HTTPS**: Deploy behind a reverse proxy with TLS/SSL
2. **Add Authentication**: Implement token-based authentication
3. **Rate Limiting**: Add rate limiting to prevent abuse
4. **Monitoring**: Monitor server logs and metrics
5. **Network Isolation**: Deploy in a private network or VPN

Example nginx reverse proxy configuration:

```nginx
server {
    listen 443 ssl;
    server_name mcp-ssh.example.com;

    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;

    location / {
        proxy_pass http://localhost:3009;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_cache_bypass $http_upgrade;

        # SSE specific settings
        proxy_buffering off;
        proxy_cache off;
    }
}
```

## Deployment

### Docker

Example Dockerfile:

```dockerfile
FROM node:20-alpine

WORKDIR /app

COPY package*.json ./
RUN npm ci --production

COPY . .

EXPOSE 3009

ENV HOST=0.0.0.0
ENV PORT=3009

CMD ["npm", "run", "start:http"]
```

Build and run:

```bash
docker build -t mcp-ssh-http .
docker run -p 3009:3009 -v ~/.ssh:/root/.ssh:ro mcp-ssh-http
```

**For production deployment, see [DOCKER.md](DOCKER.md) and [DEPLOYMENT.md](DEPLOYMENT.md) for the complete Docker setup with docker-compose.**

### systemd Service

Example service file (`/etc/systemd/system/mcp-ssh-http.service`):

```ini
[Unit]
Description=MCP SSH HTTP Server
After=network.target

[Service]
Type=simple
User=mcp
WorkingDirectory=/opt/mcp-ssh
Environment="PORT=3009"
Environment="HOST=127.0.0.1"
ExecStart=/usr/bin/node /opt/mcp-ssh/server-http.mjs
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

Enable and start:

```bash
sudo systemctl enable mcp-ssh-http
sudo systemctl start mcp-ssh-http
```

## Troubleshooting

### Server won't start

- Check if the port is already in use: `lsof -i :3009`
- Verify Node.js version: `node --version` (requires Node.js 18+)
- Check permissions for SSH config access

### Connection issues

- Verify the server is running: `curl http://localhost:3009/health`
- Check firewall rules
- Ensure CORS settings allow your client origin

### SSH operations fail

- Verify SSH keys are properly configured
- Test SSH connectivity manually: `ssh hostAlias`
- Check SSH config file permissions: `~/.ssh/config` should be readable

### Debug logging

Enable debug mode to see detailed operation logs:

```bash
DEBUG=true npm run start:http
```

## Differences from STDIO Mode

| Feature | STDIO Mode | HTTP Mode |
|---------|-----------|-----------|
| Transport | Standard I/O | HTTP with SSE |
| Network Access | Local only | Network accessible |
| Multiple Clients | Single process | Multiple concurrent |
| Configuration | Command args | Environment vars |
| Security | Process isolation | Network security needed |

## Performance

The HTTP server uses:
- Non-blocking I/O for all operations
- Streaming responses via SSE
- Connection pooling (handled by Express)
- Automatic resource cleanup

For high-volume deployments, consider:
- Using a process manager (PM2, systemd)
- Load balancing across multiple instances
- Monitoring memory and connection usage

## License

MIT - See LICENSE file for details

## Support

- GitHub Issues: https://github.com/aiondadotcom/mcp-ssh/issues
- Documentation: https://github.com/aiondadotcom/mcp-ssh
