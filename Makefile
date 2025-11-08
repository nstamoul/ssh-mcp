# Makefile for MCP SSH Server
#
# Supports two deployment profiles via Compose file sets:
# - local (default on Mac): docker-compose.yml + docker-compose.local.yaml
# - wyse:                    docker-compose.yml + docker-compose.wyse.yaml
#
# Use either ENV=local|wyse or convenience targets:
# - make up                 # uses ENV=local by default
# - make wyse-up            # forces ENV=wyse

.PHONY: help build up down logs restart status test clean rebuild exec \
        inspect network deploy update dev-build dev-logs dev-shell \
        wyse-% local-%

# Select environment (local|wyse). Default to local.
ENV ?= local

# Compose invocation and files
COMPOSE ?= docker compose
COMPOSE_FILES = -f docker-compose.yml -f docker-compose.$(ENV).yaml
DC = $(COMPOSE) $(COMPOSE_FILES)

help: ## Show this help message
	@echo 'Usage: make [target] [ENV=local|wyse]'
	@echo ''
	@echo 'ENV currently:' $(ENV)
	@echo ''
	@echo 'Common targets:'
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  %-18s %s\n", $$1, $$2}' $(MAKEFILE_LIST)
	@echo ''
	@echo 'Convenience aliases:'
	@echo '  wyse-<target>   -> run <target> with ENV=wyse'
	@echo '  local-<target>  -> run <target> with ENV=local'

build: ## Build the Docker image
	$(DC) build

up: ## Start the service
	$(DC) up -d

down: ## Stop the service
	$(DC) down

logs: ## View logs (follow mode)
	$(DC) logs -f ssh-mcp-server

logs-tail: ## View last 100 log lines
	$(DC) logs --tail 100 ssh-mcp-server

restart: ## Restart the service
	$(DC) restart ssh-mcp-server

status: ## Show service status
	$(DC) ps

health: ## Check health endpoint
	@curl -s http://localhost:3009/health | jq . || curl -s http://localhost:3009/health

test: ## Run integration tests
	@echo "Testing health endpoint..."
	@curl -sf http://localhost:3009/health > /dev/null && echo "✓ Health check passed" || echo "✗ Health check failed"

clean: ## Stop and remove containers, networks
	$(DC) down -v

rebuild: ## Rebuild and restart the service
	$(DC) up -d --build

exec: ## Execute shell in container
	$(DC) exec ssh-mcp-server sh

inspect: ## Show detailed container information
	docker inspect ssh-mcp-server

network: ## Show network configuration
	docker network inspect mcp_gateway

deploy: build up ## Build and deploy (build + up)
	@echo "Deployment complete. Run 'make logs' to view output."

update: ## Update service (pull, rebuild, restart)
	git pull
	$(DC) up -d --build
	@echo "Update complete. Run 'make logs' to view output."

# Development targets
dev-build: ## Build without cache
	$(DC) build --no-cache

dev-logs: ## View logs with timestamps
	$(DC) logs -f -t ssh-mcp-server

dev-shell: exec ## Alias for exec

# Convenience wrappers: wyse-<t> or local-<t>
wyse-%:
	@$(MAKE) ENV=wyse $*

local-%:
	@$(MAKE) ENV=local $*
