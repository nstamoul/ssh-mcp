# Docker Deployment Guide

The MCP SSH Server is designed for production deployment via Docker, integrating seamlessly with the MCP Gateway (Caddy reverse proxy).

## Quick Start

```bash
# Build and start
make build
make up

# View logs
make logs

# Check status
make status

# Test health
make health
```

## Prerequisites

- Docker and Docker Compose installed
- MCP Gateway network created: `docker network create mcp_gateway`
- SSH keys configured (without passphrases)
- Access to your `~/.ssh/config` and SSH keys

## Deployment Steps

### 1. Clone and Build

```bash
git clone https://github.com/aiondadotcom/mcp-ssh.git
cd mcp-ssh

# Build the image
make build
# or: docker compose build
```

### 2. Configure SSH Keys

The container mounts your SSH configuration from `~/.ssh/`. Ensure:

- SSH keys exist and have no passphrases
- `~/.ssh/config` is properly configured
- Keys have correct permissions (600 for private keys)

**Edit `docker-compose.yml` if you need to mount additional keys:**

```yaml
volumes:
  # Add your custom keys here
  - ${HOME}/.ssh/id_custom:/home/mcp/.ssh/id_custom:ro
```

### 3. Start the Service

```bash
make up
# or: docker compose up -d
```

### 4. Verify Deployment

```bash
# Check container is running
make status

# Check health endpoint
make health

# View logs
make logs
```

## Integration with MCP Gateway

### Update Caddy Configuration

Add to your MCP Gateway's `Caddyfile`:

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

### Reload Caddy

```bash
cd /opt/_tools/_automation/mcp-gateway
docker compose exec mcp-gateway caddy reload --config /etc/caddy/Caddyfile
```

### Test Gateway Integration

```bash
# Direct access (should work)
curl http://localhost:3009/health

# Through gateway (should also work)
curl https://mcp.orb.local/ssh/health
```

## Configuration

### Environment Variables

Edit `docker-compose.yml` to configure:

```yaml
environment:
  - PORT=3009          # Server port (default: 3009)
  - HOST=0.0.0.0       # Bind address (default: 0.0.0.0)
  - DEBUG=false        # Debug logging (default: false)
```

### Debug Mode

To enable debug logging:

```yaml
environment:
  - DEBUG=true
```

Then restart:

```bash
make restart
make logs
```

## Operations

### Common Commands

```bash
make build          # Build Docker image
make up             # Start service
make down           # Stop service
make logs           # View logs (follow mode)
make restart        # Restart service
make status         # Show status
make health         # Check health
make clean          # Stop and remove everything
make rebuild        # Rebuild and restart
make exec           # Open shell in container
```

### Manual Docker Commands

```bash
# Build
docker compose build

# Start in foreground (see output)
docker compose up

# Start in background (daemon)
docker compose up -d

# View logs
docker compose logs -f ssh-mcp

# Stop
docker compose down

# Restart
docker compose restart ssh-mcp

# Execute command in container
docker compose exec ssh-mcp sh
```

## Troubleshooting

### Container Won't Start

```bash
# View logs
make logs

# Check for port conflicts
lsof -i :3009

# Verify network exists
docker network ls | grep mcp_gateway
docker network create mcp_gateway  # if missing
```

### SSH Keys Not Working

```bash
# Check mounted files
make exec
ls -la /home/mcp/.ssh/

# Test SSH manually
make exec
ssh -vvv production
```

### Health Check Failing

```bash
# Check if service is responding
make health

# View recent logs
make logs-tail

# Check container status
make status
```

### Gateway Integration Issues

```bash
# Test direct access (bypass gateway)
curl http://localhost:3009/health

# Test through gateway
curl https://mcp.orb.local/ssh/health

# Check if container is on correct network
docker inspect ssh-mcp | grep -A 10 Networks

# Verify gateway is running
cd /opt/_tools/_automation/mcp-gateway
docker compose ps
```

## Security

### Container Security Features

- ✅ **Non-root user**: Runs as `mcp` (UID 1001)
- ✅ **Read-only mounts**: SSH keys mounted as read-only
- ✅ **Minimal image**: Alpine-based, production dependencies only
- ✅ **Network isolation**: Internal `mcp_gateway` network only
- ✅ **Health checks**: Automatic container health monitoring

### Best Practices

1. **Dedicated SSH Keys**
   ```bash
   # Create dedicated key for MCP container
   ssh-keygen -t ed25519 -f ~/.ssh/id_mcp -C "mcp-ssh-container"
   # DO NOT set a passphrase (press Enter twice)
   ```

2. **Minimal Key Access**
   ```yaml
   # Only mount keys you need
   volumes:
     - ${HOME}/.ssh/id_mcp:/home/mcp/.ssh/id_mcp:ro
   ```

3. **Regular Updates**
   ```bash
   make update  # Pull latest code and rebuild
   ```

4. **Monitor Logs**
   ```bash
   make logs  # Regular log review
   ```

## Production Checklist

Before deploying to production:

- [ ] SSH keys created (no passphrases)
- [ ] SSH config tested manually
- [ ] `docker-compose.yml` reviewed and customized
- [ ] Image builds successfully
- [ ] Container starts without errors
- [ ] Health check passes
- [ ] Connected to `mcp_gateway` network
- [ ] Caddy gateway configured
- [ ] Gateway routing verified
- [ ] SSH operations tested
- [ ] Logging configured
- [ ] Monitoring set up
- [ ] Backup strategy defined

## Advanced Configuration

### Custom Network

If not using `mcp_gateway`:

```yaml
# docker-compose.yml
networks:
  custom_network:
    external: true
    name: your_network_name
```

### Multiple SSH Configs

Mount different config files:

```yaml
volumes:
  - ./custom-ssh-config:/home/mcp/.ssh/config:ro
  - ${HOME}/.ssh/known_hosts:/home/mcp/.ssh/known_hosts:ro
```

### Resource Limits

Add resource constraints:

```yaml
# docker-compose.yml
services:
  ssh-mcp:
    deploy:
      resources:
        limits:
          cpus: '0.5'
          memory: 256M
        reservations:
          cpus: '0.25'
          memory: 128M
```

### Persistent Logs

Add volume for logs:

```yaml
volumes:
  - ./logs:/app/logs
```

## Updating

### Pull Latest Changes

```bash
make update
# or manually:
git pull
docker compose up -d --build
```

### Rebuild from Scratch

```bash
make dev-build  # No cache rebuild
make up
```

## Monitoring

### Health Monitoring

Set up automated health checks:

```bash
# Add to cron
*/5 * * * * curl -sf http://localhost:3009/health || /path/to/alert.sh
```

### Log Aggregation

Ship logs to your logging system:

```yaml
# docker-compose.yml
services:
  ssh-mcp:
    logging:
      driver: "json-file"
      options:
        max-size: "10m"
        max-file: "3"
```

### Metrics

Monitor with Docker stats:

```bash
docker stats ssh-mcp
```

## Backup

### Backup Configuration

```bash
# Backup essential files
tar czf mcp-ssh-backup-$(date +%Y%m%d).tar.gz \
    docker-compose.yml \
    .env \
    ~/.ssh/config
```

### Restore

```bash
# Restore from backup
tar xzf mcp-ssh-backup-20250108.tar.gz
make rebuild
```

## Multi-Host Deployment

For deploying across multiple hosts:

### Docker Swarm

```yaml
# docker-stack.yml
version: '3.8'
services:
  ssh-mcp:
    image: mcp-ssh:latest
    deploy:
      replicas: 2
      restart_policy:
        condition: on-failure
    # ... rest of config
```

Deploy:

```bash
docker stack deploy -c docker-stack.yml mcp-ssh
```

### Kubernetes

See `kubernetes/` directory for Kubernetes manifests (if available).

## Support

- GitHub Issues: https://github.com/aiondadotcom/mcp-ssh/issues
- Full Documentation: README.md
- HTTP Server Guide: HTTP-SERVER.md
- Deployment Guide: DEPLOYMENT.md
