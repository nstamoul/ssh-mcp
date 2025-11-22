# MCP SSH Server - Docker Deployment Guide

This guide covers deploying the MCP SSH HTTP server in Docker, designed to integrate with the MCP Gateway (Caddy reverse proxy).

## Quick Start

### 1. Build and Start the Container

```bash
# Build the Docker image
docker compose build

# Start the service
docker compose up -d

# View logs
docker compose logs -f ssh-mcp

# Check health
docker compose ps
```

### 2. Verify the Service

```bash
# Check health endpoint directly
curl http://localhost:3009/health

# Expected response:
# {"status":"ok","server":"mcp-ssh-http","version":"1.2.0"}
```

## Integration with MCP Gateway

### Add to Caddy Gateway Configuration

Add this block to your MCP Gateway's `Caddyfile`:

```caddyfile
# SSH MCP - SSH operations and automation
handle_path /ssh* {
    reverse_proxy ssh-mcp:3009 {
        header_up Host {upstream_hostport}
        header_up X-Forwarded-Host {host}
        header_up X-Forwarded-Proto {scheme}
    }
}
```

**Complete example with all services:**

```caddyfile
mcp.orb.local {
    # TLS configuration using wildcard cert
    tls /certs/_.orb.local.crt /certs/orb.local_wildcard_key.pem

    # Gateway health check endpoint
    handle /healthz {
        header Content-Type "application/json"
        respond `{"status":"ok","service":"mcp-gateway"}` 200
    }

    # Nornir MCP - Network automation
    handle_path /nornir* {
        reverse_proxy nornir-mcp-server:8009 {
            header_up Host {upstream_hostport}
            header_up X-Forwarded-Host {host}
            header_up X-Forwarded-Proto {scheme}
        }
    }

    # Orchestrator MCP - Central orchestration
    handle_path /orchestrator* {
        reverse_proxy orchestrator-mcp:3000 {
            header_up Host {upstream_hostport}
            header_up X-Forwarded-Host {host}
            header_up X-Forwarded-Proto {scheme}
        }
    }

    # Nautobot MCP - Device inventory
    handle_path /nautobot* {
        reverse_proxy nautobot-mcp:3005 {
            header_up Host {upstream_hostport}
            header_up X-Forwarded-Host {host}
            header_up X-Forwarded-Proto {scheme}
        }
    }

    # SSH MCP - SSH operations and automation
    handle_path /ssh* {
        reverse_proxy ssh-mcp:3009 {
            header_up Host {upstream_hostport}
            header_up X-Forwarded-Host {host}
            header_up X-Forwarded-Proto {scheme}
        }
    }

    # Default response for unknown paths
    handle {
        respond "MCP Gateway - Available endpoints: /nornir, /orchestrator, /nautobot, /ssh" 200
    }

    # Logging
    log {
        output file /var/log/caddy/access.log
        format json
    }
}
```

### Reload Caddy Gateway

After updating the Caddyfile:

```bash
# Reload Caddy configuration
cd /opt/_tools/_automation/mcp-gateway
docker compose exec mcp-gateway caddy reload --config /etc/caddy/Caddyfile

# Or restart the gateway
docker compose restart mcp-gateway
```

### Test Gateway Integration

```bash
# Test through the gateway
curl https://mcp.orb.local/ssh/health

# Expected response:
# {"status":"ok","server":"mcp-ssh-http","version":"1.2.0"}
```

## SSH Configuration

### Mounting SSH Keys

The `docker-compose.yml` file mounts your SSH configuration and keys as read-only volumes. By default, it mounts:

- `~/.ssh/config` - SSH client configuration
- `~/.ssh/known_hosts` - Known host keys
- `~/.ssh/id_ed25519` - Ed25519 private key
- `~/.ssh/id_rsa` - RSA private key

**To add additional SSH keys**, edit `docker-compose.yml`:

```yaml
volumes:
  # Add your custom keys here
  - ${HOME}/.ssh/id_production:/home/mcp/.ssh/id_production:ro
  - ${HOME}/.ssh/id_staging:/home/mcp/.ssh/id_staging:ro
```

### SSH Key Requirements

- **No Passphrases**: SSH keys must NOT have passphrases (the container runs non-interactively)
- **Read-Only**: All SSH files are mounted read-only (`:ro`) for security
- **Permissions**: The container automatically sets correct permissions internally

### Example SSH Config

The container will read your `~/.ssh/config` file:

```ssh-config
# Include directives at the beginning
Include ~/.ssh/config.d/*

# Global settings
ServerAliveInterval 55

Host production
    Hostname prod.example.com
    Port 22
    User deploy
    IdentityFile ~/.ssh/id_production
    IdentitiesOnly yes

Host staging
    Hostname staging.example.com
    Port 22
    User deploy
    IdentityFile ~/.ssh/id_staging
    IdentitiesOnly yes
```

## Environment Configuration

### Default Configuration

```yaml
environment:
  - NODE_ENV=production
  - PORT=3009
  - HOST=0.0.0.0
  - DEBUG=false
```

### Debug Mode

To enable debug logging, edit `docker-compose.yml`:

```yaml
environment:
  - DEBUG=true
```

Then restart:

```bash
docker compose restart ssh-mcp
docker compose logs -f ssh-mcp
```

## Network Architecture

```
┌─────────────────────────────────────────┐
│ MCP Gateway (Caddy)                     │
│ https://mcp.orb.local                   │
│ Port: 443                               │
└──────────────┬──────────────────────────┘
               │
               │ mcp_gateway network
               │
    ┌──────────┼──────────┬──────────┬─────────┐
    │          │          │          │         │
┌───▼────┐ ┌──▼─────┐ ┌──▼─────┐ ┌──▼─────┐ ┌──▼─────┐
│ Nornir │ │ Orch   │ │ Nauto  │ │ SSH    │ │ Other  │
│  :8009 │ │ :3000  │ │ :3005  │ │ :3009  │ │   MCP  │
└────────┘ └────────┘ └────────┘ └────────┘ └────────┘
```

## MCP Client Configuration

### Using with Claude Desktop

Configure Claude Desktop to use the gateway endpoint:

```json
{
  "mcpServers": {
    "ssh-mcp": {
      "url": "https://mcp.orb.local/ssh/sse"
    }
  }
}
```

### Using with Custom MCP Client

```javascript
const mcpClient = new MCPClient({
  transport: {
    type: 'http',
    url: 'https://mcp.orb.local/ssh'
  }
});

// List SSH hosts
const hosts = await mcpClient.callTool('listKnownHosts', {});

// Run a command
const result = await mcpClient.callTool('runRemoteCommand', {
  hostAlias: 'production',
  command: 'uptime'
});
```

## Operations

### View Logs

```bash
# Follow logs
docker compose logs -f ssh-mcp

# Last 100 lines
docker compose logs --tail 100 ssh-mcp

# With timestamps
docker compose logs -f -t ssh-mcp
```

### Restart Service

```bash
# Graceful restart
docker compose restart ssh-mcp

# Stop and start
docker compose stop ssh-mcp
docker compose start ssh-mcp

# Full rebuild and restart
docker compose up -d --build
```

### Update Service

```bash
# Pull latest changes
git pull

# Rebuild and restart
docker compose up -d --build

# Clean rebuild (removes old images)
docker compose build --no-cache
docker compose up -d
```

### Stop Service

```bash
# Stop container
docker compose stop ssh-mcp

# Stop and remove container
docker compose down

# Stop and remove everything (including volumes)
docker compose down -v
```

## Troubleshooting

### Check Container Status

```bash
# Container status
docker compose ps

# Detailed container info
docker inspect ssh-mcp

# Container resource usage
docker stats ssh-mcp
```

### Test SSH Connectivity

```bash
# Exec into container
docker compose exec ssh-mcp sh

# Test SSH from inside container
ssh -T production

# Check SSH config
cat /home/mcp/.ssh/config

# Check mounted keys
ls -la /home/mcp/.ssh/
```

### Common Issues

#### Container won't start

```bash
# Check logs for errors
docker compose logs ssh-mcp

# Verify network exists
docker network ls | grep mcp_gateway

# Create network if missing
docker network create mcp_gateway
```

#### SSH keys not working

```bash
# Verify keys are mounted
docker compose exec ssh-mcp ls -la /home/mcp/.ssh/

# Check key permissions inside container
docker compose exec ssh-mcp stat /home/mcp/.ssh/id_ed25519

# Test SSH connection manually
docker compose exec ssh-mcp ssh -vvv production
```

#### Can't reach through gateway

```bash
# Check gateway status
cd /opt/_tools/_automation/mcp-gateway
docker compose ps

# Verify ssh-mcp is on correct network
docker inspect ssh-mcp | grep -A 10 Networks

# Test direct connection (bypass gateway)
curl http://localhost:3009/health

# Test through gateway
curl https://mcp.orb.local/ssh/health
```

### Health Check Failures

```bash
# Check health status
docker compose ps

# Manually test health endpoint
curl http://localhost:3009/health

# Check container logs
docker compose logs --tail 50 ssh-mcp
```

## Security Considerations

### Container Security

- ✅ Runs as non-root user (`mcp` UID 1001)
- ✅ SSH keys mounted read-only
- ✅ Minimal Alpine-based image
- ✅ Production-only dependencies
- ✅ No sensitive data in environment variables

### Network Security

- ✅ Internal network only (mcp_gateway)
- ✅ TLS termination at gateway
- ✅ No direct public exposure
- ✅ Path-based routing through Caddy

### SSH Key Security

- ⚠️ **Use separate keys for container**: Don't reuse your personal SSH keys
- ⚠️ **Key rotation**: Regularly rotate SSH keys
- ⚠️ **Least privilege**: Only mount keys that are actually needed
- ⚠️ **Monitor access**: Review SSH logs regularly

### Best Practices

1. **Separate Keys**: Create dedicated SSH keys for the MCP container
2. **Read-Only Mounts**: Keep all volume mounts read-only (`:ro`)
3. **Network Isolation**: Use the mcp_gateway network exclusively
4. **Regular Updates**: Keep base image and dependencies updated
5. **Log Monitoring**: Monitor container logs for suspicious activity

## Production Deployment Checklist

- [ ] SSH keys created and configured (no passphrases)
- [ ] SSH config file updated with hosts
- [ ] Docker image built successfully
- [ ] Container starts without errors
- [ ] Health check passes
- [ ] Connected to mcp_gateway network
- [ ] Caddy gateway configuration updated
- [ ] Gateway routing works correctly
- [ ] MCP client can connect through gateway
- [ ] SSH operations work as expected
- [ ] Logs are clean, no errors
- [ ] Container auto-restarts on failure

## Maintenance

### Backup Configuration

```bash
# Backup SSH configuration
tar czf ssh-mcp-backup-$(date +%Y%m%d).tar.gz \
    ~/.ssh/config \
    ~/.ssh/known_hosts \
    docker-compose.yml

# Backup with keys (SECURE THIS FILE!)
tar czf ssh-mcp-full-backup-$(date +%Y%m%d).tar.gz \
    ~/.ssh/ \
    docker-compose.yml
```

### Monitoring

Set up monitoring for:
- Container health status
- API endpoint availability
- SSH operation success/failure rates
- Container resource usage
- Gateway access logs

## Support

For issues and questions:
- GitHub Issues: https://github.com/aiondadotcom/mcp-ssh/issues
- Documentation: See README.md and HTTP-SERVER.md
