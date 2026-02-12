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

.PHONY: deps help lint format test build logs deploy deploy-config

help:
	@echo "Available commands:"
	@echo "  deps          - Install development dependencies"
	@echo "  lint          - Run linters"
	@echo "  test          - Run tests"
	@echo "  build         - Build binary locally (for verification)"
	@echo "  deploy        - Full deploy (binary + config)"
	@echo "  deploy-config - Fast deploy (config only + reload)"
	@echo "  logs          - Stream remote service logs"

deps:
	go install github.com/evilmartians/lefthook@latest
	go install golang.org/x/vuln/cmd/govulncheck@latest
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest

lint:
	golangci-lint run ./...

format:
	go fmt ./...

test:
	go test -race -covermode=atomic -coverprofile=coverage.out ./...
	go tool cover -func=coverage.out

# Build the Linux binary (Local Verification)
build:
	cd service && GOOS=linux CGO_ENABLED=0 GOARCH=amd64 go build -a -installsuffix cgo -o dns_filter_linux

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