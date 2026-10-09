# Pitangus · common commands. `make help` for the list.
# Only needs make and Docker; the development targets also need Python 3.12 and Node 22.

SHELL := /bin/sh
COMPOSE ?= docker compose
VERSION := $(shell sed -n 's/^VERSION = "\(.*\)"/\1/p' pitangus/version.py)
PORT := $(shell sed -n 's/^PITANGUS_HOST_PORT=//p' .env 2>/dev/null | tail -n1)
PUBLIC_URL := $(shell sed -n 's/^PITANGUS_PUBLIC_URL=//p' .env 2>/dev/null | tail -n1)
HOST_PORT := $(if $(PORT),$(PORT),8766)
URL := $(if $(PUBLIC_URL),$(PUBLIC_URL),http://127.0.0.1:$(HOST_PORT))
PYTHON ?= python3
DIR ?=
ARGS ?=
# make setup [DOMAIN=…] [PREBUILT=1] [SOCKET=1]: server mode, published images, engines through the Docker socket
# (see scripts/init-env.sh). make restore FROM=backups/<date>.
DOMAIN ?=
PREBUILT ?=
SOCKET ?=
FROM ?=
SERVICE ?= api
# Who signs the published images (cosign keyless, GitHub OIDC): the repository whose release workflow built them.
SIGNER ?= Pitangus-Dev/pitangus
OPENGREP_VERSION := $(shell sed -n 's/^ARG OPENGREP_VERSION=//p' docker/engines/opengrep/Dockerfile)
VENV := .venv
export PITANGUS_VERSION := $(VERSION)
# Docker socket group on Linux and WSL with native Docker (on macOS, Docker Desktop uses 0).
# A value in the environment or in .env overrides detection.
DOCKER_SOCKET_GID ?= $(shell sed -n 's/^DOCKER_SOCKET_GID=//p' .env 2>/dev/null | tail -n1)
ifeq ($(strip $(DOCKER_SOCKET_GID)),)
DOCKER_SOCKET_GID := $(shell [ "$$(uname -s)" = Linux ] && stat -Lc %g /var/run/docker.sock 2>/dev/null)
endif
# 0 is always in compose already; repeating it is an error.
ifeq ($(strip $(DOCKER_SOCKET_GID)),0)
DOCKER_SOCKET_GID :=
endif
export DOCKER_SOCKET_GID
# Published engine images, pinned by digest, read from the code (no Python or app image needed).
# `make engines` pulls them from the host: progress is visible, there is no time limit and it doesn't depend
# on the socket permissions inside the container.
# The worker runs the engines inside its image (compose.no-socket.yaml): nothing to pull, one more image to check.
NO_SOCKET := $(shell sed -n 's/^COMPOSE_FILE=//p' .env 2>/dev/null | tail -n1 | grep -o 'compose\.no-socket\.yaml')
ENGINE_IMAGES := sed -n 's/.*"image": "\([^"]*@sha256:[0-9a-f]\{64\}\)".*/\1/p' pitangus/modules/scanning/engines.py

.DEFAULT_GOAL := help
.PHONY: arch openapi standalone help doctor setup build up down restart status logs ps setup-code engines scan demo update backup restore \
        verify-images shell cli clean purge dev-setup lock dev test lint lint-py test-web web check

## —— Usage —————————————————————————————————————————————————————————————

help: ## Show this help
	@printf 'Pitangus %s · usage: make <target>\n\n' "$(VERSION)"
	@awk 'BEGIN {FS = ":.*## "} /^## ——/ {sub(/^## /, ""); printf "\n\033[1m%s\033[0m\n", $$0} /^[a-z-]+:.*## / {printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)
	@printf '\nFirst time:  make up\n'

doctor: ## Check requirements (Docker, Compose, disk, port, permissions)
	@sh scripts/doctor.sh

setup: ## Create .env and the folders. PREBUILT=1: published images. On a server: make setup DOMAIN=pitangus.example.com [PREBUILT=1]
	@DOMAIN="$(DOMAIN)" PREBUILT="$(PREBUILT)" SOCKET="$(SOCKET)" sh scripts/init-env.sh

build: setup ## Build the images (app and verified Opengrep engine)
	$(COMPOSE) build

up: setup ## Build if needed (or check and pull the published images), start, pull missing engines and show the URL
	@if grep -q '^PITANGUS_IMAGE=.' .env 2>/dev/null; then \
	  if command -v cosign >/dev/null; then $(MAKE) --no-print-directory verify-images || exit 1; \
	  else echo 'Signatures of the published images not checked: install cosign (https://docs.sigstore.dev/cosign/system_config/installation/) and make up checks them.'; \
	    for var in PITANGUS_IMAGE_TAG PITANGUS_WORKER_IMAGE_TAG; do tag=$$(sed -n "s/^$$var=//p" .env | tail -n1); \
	      if printf '%s' "$$tag" | grep -Eq '^[0-9]+\.[0-9]+@sha256:' && { [ -n "$(REPIN)" ] || [ "$${tag%%@*}" != "$(VERSION)" ]; }; then \
	        sed -i.bak "/^$$var=/d" .env && rm -f .env.bak; fi; done; \
	  fi; \
	fi
	$(COMPOSE) up --build -d
	@printf 'Waiting for the panel to respond'
	@i=0; until [ "$$(docker inspect -f '{{.State.Health.Status}}' "$$($(COMPOSE) ps -q api)" 2>/dev/null)" = healthy ]; do \
	  i=$$((i + 1)); if [ $$i -gt 60 ]; then echo; echo 'It did not start within 2 minutes: make logs'; exit 1; fi; printf '.'; sleep 2; done; echo
	@$(MAKE) --no-print-directory engines || echo 'Warning: some engines are missing; the panel works, retry with make engines.'
	@echo "Panel: $(URL)"
	@$(MAKE) --no-print-directory setup-code

down: ## Stop and remove the containers (keeps data/ and config/)
	$(COMPOSE) down

restart: ## Restart the app (marks running scans as failed)
	$(COMPOSE) restart api worker

status: ## Status of the containers and the engines
	@$(COMPOSE) ps
	@echo
	@$(COMPOSE) exec -T worker python -m pitangus engines 2>/dev/null || echo "The app is not running: make up"

ps: status

logs: ## Follow the app logs (Ctrl+C to exit). Another service: make logs SERVICE=caddy
	$(COMPOSE) logs -f --tail 100 $(SERVICE)

setup-code: ## Show the code to create the first administrator
	@sh scripts/setup-code.sh "$(URL)"

engines: ## Pull the missing engine images (Trivy, OSV-Scanner, Gitleaks, Grype, Checkov, zizmor), with progress
	@if [ "$(NO_SOCKET)" ]; then echo 'Engines: inside the worker image (no Docker socket).'; exit 0; fi; \
	images=$$($(ENGINE_IMAGES)); \
	missing=0; for image in $$images; do docker image inspect "$$image" >/dev/null 2>&1 || missing=$$((missing + 1)); done; \
	if [ $$missing -eq 0 ]; then echo 'Engines: all images are ready.'; exit 0; fi; \
	echo "Engines: $$missing images missing; the first time can take a while depending on your connection."; \
	for image in $$images; do \
	  docker image inspect "$$image" >/dev/null 2>&1 && continue; \
	  echo "→ $${image%%@*}"; \
	  docker pull "$$image" || { echo "Pulling $${image%%@*} failed: check your connection and run make engines again."; exit 1; }; \
	done; echo 'Engines: ready.'

scan: ## Scan a local folder: make scan DIR=../my-repo ARGS="--base main --fail-on high"
	@[ -d "$(DIR)" ] || { echo 'Give the folder: make scan DIR=../my-repo (and options in ARGS="--base main")'; exit 2; }
	@$(COMPOSE) run --rm --no-deps -T -v "$(abspath $(DIR))":/src:ro worker python -m pitangus scan /src --name "$(notdir $(abspath $(DIR)))" $(ARGS)

demo: ## Demo data: scans the vulnerable examples and imports a threat model (IMAGE=nginx:1.21 adds an image)
	@$(COMPOSE) run --rm -T -v "$(abspath fixtures)":/demo/fixtures:ro -v "$(abspath web/src/examples/threat-models)":/demo/models:ro \
		worker python -m pitangus --data-dir /data demo --fixtures /demo/fixtures --models /demo/models $(if $(IMAGE),--image "$(IMAGE)",)

update: ## Back up, update the code (git pull), pull or rebuild the images and restart (migrates on start)
	@if git symbolic-ref -q HEAD >/dev/null; then git pull --ff-only; \
	else echo "On $$(git describe --tags --always) (a fixed version): not pulling. Check out the version you want first."; fi
	@sh scripts/backup.sh
	$(COMPOSE) pull --ignore-buildable --policy always --quiet
	$(MAKE) --no-print-directory up REPIN=1

backup: ## Database and data/ to backups/<date>/, age-encrypted with the master key if PITANGUS_BACKUP_AGE_RECIPIENT (FORCE=1 if scans run)
	@sh scripts/backup.sh

restore: ## Restore a backup: make restore FROM=backups/<date> CONFIRM=restore (saves the current state first)
	@CONFIRM="$(CONFIRM)" sh scripts/restore.sh "$(FROM)"

# The app image is checked by digest and PITANGUS_IMAGE_TAG pinned to it (<version>@sha256:…), so every later start
# runs exactly what was checked; without the socket, the worker image too (PITANGUS_WORKER_IMAGE_TAG). A pin of another
# version (after a git pull) or REPIN=1 (make update) checks the tag again.
verify-images: ## Check the cosign signatures of the published images and pin .env to the checked digest (needs cosign)
	@image=$$(sed -n 's/^PITANGUS_IMAGE=//p' .env 2>/dev/null | tail -n1); \
	[ -n "$$image" ] || { echo 'There is no PITANGUS_IMAGE in .env: this server builds its own images.'; exit 2; }; \
	command -v cosign >/dev/null || { echo 'Install cosign first: https://docs.sigstore.dev/cosign/system_config/installation/'; exit 2; }; \
	verify() { out=$$(cosign verify --certificate-oidc-issuer https://token.actions.githubusercontent.com \
	  --certificate-identity-regexp '^https://github\.com/$(SIGNER)/\.github/workflows/release\.yml@refs/tags/v[0-9]+\.[0-9]+(\.[0-9]+)?$$' \
	  "$$1" 2>&1) || { echo "NOT verified: $$1"; printf '%s\n' "$$out" | tail -n1; exit 1; }; }; \
	check() { name=$$1; var=$$2; tag=$$(sed -n "s/^$$var=//p" .env | tail -n1); pin=; \
	  if [ -n "$$tag" ] && ! printf '%s' "$$tag" | grep -Eq '^[0-9]+\.[0-9]+@sha256:[0-9a-f]{64}$$'; then ref="$$name:$$tag"; \
	  elif [ "$${tag%%@*}" = "$(VERSION)" ] && [ -z "$(REPIN)" ]; then ref="$$name@$${tag#*@}"; \
	  else ref="$$name:$(VERSION)"; pin=1; fi; \
	  verify "$$ref"; \
	  digest=$$(printf '%s\n' "$$out" | sed -n 's/.*"docker-manifest-digest":"\(sha256:[0-9a-f]\{64\}\)".*/\1/p' | sort -u); \
	  [ "$$(printf '%s\n' "$$digest" | grep -c .)" -eq 1 ] || { echo "NOT verified: no single digest for $$ref"; exit 1; }; \
	  echo "Signature verified: $$name@$$digest"; \
	  [ -n "$$pin" ] || return 0; \
	  if grep -q "^$$var=" .env; then sed -i.bak "s|^$$var=.*|$$var=$(VERSION)@$$digest|" .env && rm -f .env.bak; \
	  else printf '%s=%s\n' "$$var" "$(VERSION)@$$digest" >> .env; fi; \
	  echo "Pinned in .env: $$var=$(VERSION)@$$digest"; }; \
	check "$$image" PITANGUS_IMAGE_TAG; \
	if [ "$(NO_SOCKET)" ]; then check "$$image-worker" PITANGUS_WORKER_IMAGE_TAG; \
	else verify "$$image-opengrep:$(OPENGREP_VERSION)"; echo "Signature verified: $$image-opengrep:$(OPENGREP_VERSION)"; fi

shell: ## Open a shell inside the container
	$(COMPOSE) exec api sh

cli: ## App CLI: make cli ARGS="user list"
	$(COMPOSE) exec api python -m pitangus --data-dir /data $(ARGS)

clean: ## Stop everything and remove the local images (keeps data/ and config/)
	$(COMPOSE) down --rmi all

purge: ## DELETES data/ and config/. Requires CONFIRM=delete
	@if [ "$(CONFIRM)" != "delete" ] && [ "$(CONFIRM)" != "borrar" ]; then echo 'This deletes runs, users and secrets. Run again with: make purge CONFIRM=delete'; exit 1; fi
	$(COMPOSE) down --rmi all
	rm -rf data config

## —— Development ———————————————————————————————————————————————————————

dev-setup: ## Create .venv and install the Python and panel dependencies
	$(PYTHON) -m venv $(VENV)
	$(VENV)/bin/pip install -q --disable-pip-version-check --require-hashes --only-binary :all: -r requirements-dev.txt
	cd web && pnpm install --frozen-lockfile

# In the image's own Python (3.12, pinned by digest) so the lock resolves like the release build.
lock: ## Regenerate requirements.txt and requirements-dev.txt from the .in files (hashes). Upgrade: ARGS="--upgrade-package fastapi"
	@image=$$(sed -n 's/^FROM \(python:3\.12-slim-bookworm@sha256:[0-9a-f]\{64\}\) AS app$$/\1/p' docker/app/Dockerfile); \
	[ -n "$$image" ] || { echo 'The Python base image was not found in docker/app/Dockerfile.'; exit 1; }; \
	docker run --rm --user "$$(id -u):$$(id -g)" -e HOME=/tmp -e PIP_DISABLE_PIP_VERSION_CHECK=1 \
	  -e CUSTOM_COMPILE_COMMAND="make lock  # pip-compile --generate-hashes --allow-unsafe --strip-extras" -v "$(CURDIR)":/work -w /work "$$image" sh -c \
	  'pip install -q --user --no-warn-script-location pip-tools==7.5.1 && for name in requirements requirements-dev; do \
	     python -m piptools compile -q --generate-hashes --allow-unsafe --strip-extras $(ARGS) --output-file $$name.txt $$name.in || exit 1; done'

dev: ## Local server without a container on 127.0.0.1:8767 (engines through your Docker)
	PITANGUS_PUBLIC_URL=http://127.0.0.1:8767 PITANGUS_ALLOWED_ORIGINS=http://127.0.0.1:8767,http://localhost:8767 \
	PITANGUS_CONFIG_DIR=$(CURDIR)/.dev/config $(VENV)/bin/python -m pitangus --data-dir .dev/data serve --port 8767

web: ## Build the panel into pitangus/app/static/
	cd web && pnpm run build

test: ## Backend tests (starts a throwaway test Postgres if needed)
	@url=$$(sh scripts/test-db.sh) && config=$$(mktemp -d) && trap 'rm -rf "$$config"; sh scripts/test-db.sh drop "$$url"' EXIT && \
	PITANGUS_DATABASE_URL="$$url" PITANGUS_DB_ISOLATE=data-dir PITANGUS_CONFIG_DIR="$$config" PITANGUS_DEFAULT_LOCALE=es \
	DOCKER_HOST=unix:///nonexistent/docker.sock $(VENV)/bin/python -m unittest discover -s tests

standalone: ## Regenerate deploy/compose.yaml (one file, published images, no Docker socket)
	python3 scripts/standalone-compose.py

openapi: ## API OpenAPI schema and the panel's TypeScript types (web/src/shared/api/)
	@mkdir -p web/src/shared/api
	$(VENV)/bin/python -c "from pitangus.app.api import openapi_document; print(openapi_document(), end='')" > web/src/shared/api/openapi.json
	cd web && pnpm exec openapi-typescript src/shared/api/openapi.json -o src/shared/api/schema.d.ts

arch: ## Architecture contracts (import-linter, see pyproject.toml)
	$(VENV)/bin/lint-imports --cache-dir .cache/import-linter

lint-py: ## Backend lint (ruff) and types (mypy), see pyproject.toml
	$(VENV)/bin/ruff check pitangus tests scripts api
	$(VENV)/bin/mypy

lint: ## Panel lint and types
	cd web && pnpm exec tsc -b && pnpm run lint

test-web: ## Panel tests (vitest: sign-in, triage, launching an analysis)
	cd web && pnpm test

check: test arch lint-py lint test-web ## Tests, architecture contracts and lint (required before a PR)
