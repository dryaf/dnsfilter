# Check if .env file exists and then export variables from it
ifneq (,$(wildcard ./.env))
    include .env
    export
endif

# Configurable parameters
TARGET_BIN := /usr/local/bin/dns_proxy
TARGET_CONFIG := /etc/dnsproxy.yml

deps:
	go install github.com/evilmartians/lefthook@latest
	go install golang.org/x/vuln/cmd/govulncheck@latest

help:
	echo "what?"

# Build the Linux binary
build: 
	cd service && GOOS=linux CGO_ENABLED=0 GOARCH=amd64 go build -a -installsuffix cgo -o dns_proxy_linux

# Stream the service logs
logs:
	@echo "Streaming service logs..."
	ssh -p $(SSH_PORT) $(SSH_HOST) "journalctl -f -u dns-proxy"

# Remove the old binary
clean: 
	@echo "Removing old binary..."
	ssh -p $(SSH_PORT) $(SSH_HOST) "service dns-proxy stop || true && \
	$(TARGET_BIN) -service uninstall || true && \
	rm -f $(TARGET_BIN)"

# Upload the new binary and configuration
upload: build
	@echo "Uploading binary and configuration..."
	scp  -P $(SSH_PORT) service/dns_proxy_linux $(SSH_HOST):$(TARGET_BIN)
	scp  -P $(SSH_PORT) config.yml $(SSH_HOST):$(TARGET_CONFIG)

# Setup the service on the server
setup: upload
	@echo "Setting up service..."
	ssh -p $(SSH_PORT) $(SSH_HOST) "[ -f $(TARGET_BIN) ] && \
	groupadd dnsproxy || true && \
	useradd -G dnsproxy -r -M -N -s /bin/false dnsproxy || true && \
	chown -R dnsproxy:dnsproxy $(TARGET_BIN) $(TARGET_CONFIG) && \
	ufw allow in on wg0 to any port 53 proto udp && \
	chmod 755 $(TARGET_BIN) $(TARGET_CONFIG) && \
	setcap cap_net_bind_service=+ep $(TARGET_BIN) && \
	systemctl stop systemd-resolved || true && \
	systemctl disable systemd-resolved || true && \
	rm -f /etc/resolv.conf && echo \"nameserver 1.1.1.2\" | tee /etc/resolv.conf && \
	$(TARGET_BIN) -service install && \
	service dns-proxy start"

# Full deployment process
deploy: clean build upload setup
	@echo "Removal of old binary, upload and setup finished."
	rm -f service/dns_proxy_linux
