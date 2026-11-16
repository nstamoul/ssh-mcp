# Production Dockerfile for MCP SSH HTTP Server
# Multi-stage build for optimal image size

# Stage 1: Dependencies
FROM node:20-alpine AS deps

WORKDIR /app

# Install openssh-client for SSH operations
RUN apk add --no-cache openssh-client

# Copy package files
COPY package.json package-lock.json ./

# Install production dependencies only
RUN npm ci --production --ignore-scripts

# Stage 2: Production
FROM node:20-alpine

# openssh-client for SSH operations; python3 for the ShellHub 443 route of
# homelab-connect (tls-pipe.py)
RUN apk add --no-cache openssh-client python3

WORKDIR /app

# Create non-root user for security
RUN addgroup -g 1001 -S mcp && \
    adduser -S mcp -u 1001 -G mcp && \
    mkdir -p /home/mcp/.ssh /home/mcp/.ssh-mcp && \
    chown -R mcp:mcp /home/mcp/.ssh /home/mcp/.ssh-mcp && \
    chmod 700 /home/mcp/.ssh /home/mcp/.ssh-mcp

# Copy dependencies from deps stage
COPY --from=deps /app/node_modules ./node_modules

# Copy application files
COPY --chown=mcp:mcp server-http.mjs ssh-exec.mjs realm.mjs ./
COPY --chown=mcp:mcp package.json ./

# Switch to non-root user
USER mcp

# Environment variables
ENV NODE_ENV=production \
    PORT=3009 \
    HOST=0.0.0.0 \
    DEBUG=false

# Expose port
EXPOSE 3009

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD node -e "fetch('http://localhost:3009/health').then(r => r.ok ? process.exit(0) : process.exit(1)).catch(() => process.exit(1))"

# Start the server
CMD ["node", "server-http.mjs"]
