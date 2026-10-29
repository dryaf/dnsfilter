# Check if .env file exists and then export variables from it
ifneq (,$(wildcard ./.env))
    include .env
    export
endif

# Extract User and Host from SSH_HOST (format: user@host) for Ansible
SSH_USER := $(shell echo $(SSH_HOST) | cut -d@ -f1)
SSH_HOSTNAME := $(shell echo $(SSH_HOST) | cut -d@ -f2)

# Default to "no" for WireGuard requirement. Use 'make deploy WG=yes' to enable.
WG ?= no

LEFTHOOK_VERSION := v2.2.2
GOVULNCHECK_VERSION := v1.9.0
GOLANGCI_LINT_VERSION := v2.15.0

CONTAINER_ENGINE ?= podman
CONTAINER_IMAGE ?= localhost/dnsfilter:local
CONTAINER_ARCH ?= $(shell go env GOHOSTARCH)

.PHONY: deps help lint format test test-deploy build container-binary container-build logs deploy deploy-config

help:
	@echo "Available commands:"
	@echo "  deps          - Install development dependencies"
	@echo "  lint          - Run linters"
	@echo "  test          - Run tests"
	@echo "  test-deploy   - Test deployment recovery locally (requires Ansible)"
	@echo "  build         - Build binary locally (for verification)"
	@echo "  container-build - Build a local Podman/Docker image"
	@echo "  deploy        - Full deploy (binary + config)"
	@echo "  deploy-config - Fast deploy (config only + reload)"
	@echo "  logs          - Stream remote service logs"

deps:
	go install github.com/evilmartians/lefthook/v2@$(LEFTHOOK_VERSION)
	go install golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION)
	go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION)

lint:
	golangci-lint run ./...

format:
	golangci-lint fmt ./...

test:
	go test -race -covermode=atomic -coverprofile=coverage.out ./...
	go tool cover -func=coverage.out

test-deploy:
	python3 tests/deployment_test.py

# Build the Linux binary (Local Verification)
build:
	cd service && GOOS=linux CGO_ENABLED=0 GOARCH=amd64 go build -a -installsuffix cgo -o dns_filter_linux

# Match the binary-mode build context assembled remotely by dryaf/deploy.
container-binary:
	mkdir -p build/container
	CGO_ENABLED=0 GOOS=linux GOARCH="$(CONTAINER_ARCH)" go build -trimpath -ldflags="-s -w" -o build/container/dns-filter ./service

container-build: container-binary
	cp Containerfile .dockerignore build/container/
	$(CONTAINER_ENGINE) build --platform "linux/$(CONTAINER_ARCH)" -f build/container/Containerfile -t "$(CONTAINER_IMAGE)" build/container

# Stream the service logs
logs:
	@echo "Streaming service logs from $(SSH_HOST)..."
	ssh -p $(SSH_PORT) $(SSH_HOST) "journalctl -f -u dns-filter"

# Deploy everything
deploy:
	@echo "Deploying to $(SSH_HOSTNAME) with user $(SSH_USER)..."
	ansible-playbook build_and_deploy.yml \
		-i "$(SSH_HOSTNAME)," \
		-u "$(SSH_USER)" \
		-e "ansible_port=$(SSH_PORT)" \
		-e "wg_required=$(WG)"

# Deploy config only (Fast)
deploy-config:
	@echo "Updating configuration on $(SSH_HOSTNAME)..."
	ansible-playbook build_and_deploy.yml \
		-i "$(SSH_HOSTNAME)," \
		-u "$(SSH_USER)" \
		-e "ansible_port=$(SSH_PORT)" \
		-e "wg_required=$(WG)" \
		--tags "config,dns"
