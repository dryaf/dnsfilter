# DNS Filter & Proxy

A high-performance, production-ready DNS proxy written in Go. This service acts as a middleware that filters traffic based on categories (Malware, Porn, Ads), caches responses for performance, and forwards legitimate requests to specific upstream resolvers (supporting DNS-over-HTTPS).

It is designed to be deployed as a system service on Linux servers, specifically protecting VPN gateways (WireGuard) or local networks.

## Features

*   **Category Blocking:** Toggleable filters for Malware, Adult Content, and Advertisements.
*   **Split-Horizon Resolution:** Routes traffic to different upstream resolvers based on the type of content being filtered.
*   **Protocol Support:**
    *   **Downstream:** Listens on both **UDP** and **TCP** (RFC compliant).
    *   **Upstream:** Supports standard DNS and **DNS-over-HTTPS (DoH)** for privacy.
*   **Performance:**
    *   In-memory **TTL Cache** to reduce latency and upstream load.
    *   Concurrent resolution strategies.
*   **Observability:** Built-in HTTP server for **Prometheus Metrics** (`/metrics`) and Health Checks (`/health`).
*   **Resilience:**
    *   Panic recovery middleware.
    *   Self-healing deployment (bootstraps DNS if broken).
    *   Atomic binary upgrades (zero downtime restart).

## Prerequisites

### Local Development
*   **Go:** Version 1.25 or higher.
*   **Make:** For build automation.
*   **GolangCI-Lint:** For code quality checks (installed via `make deps`).

### Deployment Target
*   **OS:** Ubuntu/Debian (systemd based).
*   **Access:** SSH with sudo privileges.
*   **Ansible:** Installed locally to run the playbooks.

## Configuration

### 1. Environment Variables (`.env`)
Create a `.env` file in the root directory to define your deployment target:

```bash
cp .env-sample .env
```

**Content:**
```ini
SSH_HOST=root@your-server-ip
SSH_PORT=22
```

### 2. Service Configuration (`config.yml`)
The behavior is controlled by `config.yml`.

```yaml
listen_addr: 0.0.0.0:53
metrics_addr: 0.0.0.0:8080  # Prometheus metrics
request_timeout: 4s
cache_size: 10000           # In-memory cache capacity

filter_malware: true
filter_porn: true
filter_ads: true

whitelist:
  - trusted-site.com

# Upstream Resolvers
resolver_unfiltered:
  name: cloudflare
  addr: 1.1.1.1:443
  url: https://1.1.1.1/dns-query # Uses DoH
```

## Development

The project uses a `Makefile` to standardize development tasks.

```bash
# Install linter and tools
make deps

# Run tests with race detection and coverage
make test

# Lint the code
make lint

# Build binary locally (to verify compilation)
make build
```

## Deployment

Deployment is handled via **Ansible**, wrapped by Make commands for convenience. The playbook handles dependencies (`ufw`, `libcap`), firewall rules, and systemd configuration.

### Full Deployment
Builds the binary, uploads it, installs system dependencies, and restarts the service.

```bash
make deploy
```

### WireGuard Support
If you are running this on a WireGuard VPN server, enable the `WG` flag to automatically configure UFW firewall rules for the `wg0` interface.

```bash
make deploy WG=yes
```

### Fast Config Update
If you only changed `config.yml` (e.g., added a whitelist domain), use this to upload the config and reload the service without rebuilding the binary.

```bash
make deploy-config
```

## Observability

Once deployed, the service exposes an HTTP server (default port 8080):

*   **Health Check:** `GET /health` -> `200 OK`
*   **Metrics:** `GET /metrics` -> JSON stats:
    ```json
    {
      "requests_total": 150,
      "blocked_total": 12,
      "errors_total": 0,
      "cache_hits": 45
    }
    ```

## Project Structure

*   `lib/`: Core logic (Filtering, Caching, DoH client, Metrics).
*   `service/`: Service wrapper (kardianos/service) and CLI entry point.
*   `build_and_deploy.yml`: Ansible playbook.
*   `config.yml`: Runtime configuration.