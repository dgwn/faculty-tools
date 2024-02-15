COMPOSE_FILE=docker-compose.yml
DOCKER_COMPOSE=docker compose -f $(COMPOSE_FILE)

BLACK        := $(shell tput -Txterm setaf 0)
RED          := $(shell tput -Txterm setaf 1)
GREEN        := $(shell tput -Txterm setaf 2)
YELLOW       := $(shell tput -Txterm setaf 3)
LIGHTPURPLE  := $(shell tput -Txterm setaf 4)
PURPLE       := $(shell tput -Txterm setaf 5)
BLUE         := $(shell tput -Txterm setaf 6)
WHITE        := $(shell tput -Txterm setaf 7)
RESET := $(shell tput -Txterm sgr0)

default: build

#==============================================
# Building and cleaning the Docker environment
#==============================================
build: ## Build all Docker images
	@echo "Building Faculty Tools' Docker images"
	@$(DOCKER_COMPOSE) build

build-no-cache: ## Build all Docker images
	@echo "Building Faculty Tools' Docker images"
	@$(DOCKER_COMPOSE) build --no-cache

clean: stop-lti remove-lti-volumes build-no-cache ## Stops and removes existing existing containers before rebuilding images

nuke:  ## Stops and removes existing existing containers and volumes, including the database
	@echo "${YELLOW}Stopping running containers and purging existing volumes${RESET}"
	$(DOCKER_COMPOSE) down -v

#================================================================================
# Managing the Docker environment (e.g. starting, stopping, deleting containers)
#================================================================================
start: start-daemon ## Start Faculty Tools (default: daemon mode)

start-attached: ## Start Faculty Tools in attached mode
	@echo "${GREEN}Starting Faculty Tools in attached mode${RESET}"
	$(DOCKER_COMPOSE) up

start-daemon: ## Start Faculty Tools in daemon mode
	@echo "${GREEN}Starting Faculty Tools in daemon mode${RESET}"
	@echo "Run \`make start-attached\` to run in attached mode, or view container logs with \`make logs\`"
	$(DOCKER_COMPOSE) up -d

stop: ## Stop Faculty Tools
	@echo "${YELLOW}Stopping Faculty Tools${RESET}"
	$(DOCKER_COMPOSE) down

logs: ## View container logs (optionally specifying a service name, like `lti`)
	$(DOCKER_COMPOSE) logs -f

#=================================
# Application management commands
#=================================
create-db:
	@echo "Initializing the database"
	docker-compose up -d lti
	docker-compose exec lti python -c "from lti import app, db; app.app_context().push(); db.create_all()"
