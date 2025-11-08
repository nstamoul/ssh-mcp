# Makefile for MCP SSH Server
# Simplifies common Docker operations

.PHONY: help build up down logs restart status test clean rebuild

help: ## Show this help message
	@echo 'Usage: make [target]'
	@echo ''
	@echo 'Available targets:'
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  %-15s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

build: ## Build the Docker image
	docker compose build

up: ## Start the service
	docker compose up -d

down: ## Stop the service
	docker compose down

logs: ## View logs (follow mode)
	docker compose logs -f ssh-mcp

logs-tail: ## View last 100 log lines
	docker compose logs --tail 100 ssh-mcp

restart: ## Restart the service
	docker compose restart ssh-mcp

status: ## Show service status
	docker compose ps

health: ## Check health endpoint
	@curl -s http://localhost:3009/health | jq . || curl -s http://localhost:3009/health

test: ## Run integration tests
	@echo "Testing health endpoint..."
	@curl -sf http://localhost:3009/health > /dev/null && echo "✓ Health check passed" || echo "✗ Health check failed"

clean: ## Stop and remove containers, networks
	docker compose down -v

rebuild: ## Rebuild and restart the service
	docker compose up -d --build

exec: ## Execute shell in container
	docker compose exec ssh-mcp sh

inspect: ## Show detailed container information
	docker inspect ssh-mcp

network: ## Show network configuration
	docker network inspect mcp_gateway

deploy: build up ## Build and deploy (build + up)
	@echo "Deployment complete. Run 'make logs' to view output."

update: ## Update service (pull, rebuild, restart)
	git pull
	docker compose up -d --build
	@echo "Update complete. Run 'make logs' to view output."

# Development targets
dev-build: ## Build without cache
	docker compose build --no-cache

dev-logs: ## View logs with timestamps
	docker compose logs -f -t ssh-mcp

dev-shell: exec ## Alias for exec
