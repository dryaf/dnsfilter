# DNS Filter & Proxy

A high-performance, production-ready DNS proxy written in Go. This service acts as a middleware that filters traffic based on categories (Malware, Porn, Ads), caches responses for performance, and forwards legitimate requests to specific upstream resolvers (supporting DNS-over-HTTPS).

It runs as a system service or a rootless Podman container on Linux servers, protecting VPN gateways (WireGuard) or local networks.

## Features

*   **Category Blocking:** Toggleable filters for Malware, Adult Content, and Advertisements.
*   **Split-Horizon Resolution:** Routes traffic to different upstream resolvers based on the type of content being filtered.
*   **Protocol Support:**
    *   **Downstream:** Listens on both **UDP** and **TCP** (RFC compliant).
    *   **Upstream:** Supports UDP DNS with TCP fallback, TCP DNS, **DNS-over-TLS (DoT)** and **DNS-over-HTTPS (DoH)**.
*   **Client Access:** Loopback plus explicitly allowed client networks; unauthorized requests receive REFUSED before any cache or upstream access.
*   **Performance:**
    *   In-memory **TTL Cache** to reduce latency and upstream load.
    *   Concurrent resolution strategies.
    *   DNS TTLs account for both local cache time and HTTP `Age` on DoH responses.
    *   Combined filter decisions expire with the shortest resolver lifetime, including time spent waiting for another resolver. The same limit is sent to clients.
    *   NXDOMAIN and NODATA responses with a SOA use the smaller of its TTL and MINIMUM for negative caching; responses without a usable lifetime are not cached.
*   **Observability:** Built-in HTTP server for **JSON metrics** (`/metrics`) and Health Checks (`/health`).
*   **Resilience:**
    *   Panic recovery middleware.
    *   Self-healing deployment (bootstraps DNS if broken).
    *   Staged configuration validation, atomic binary replacement, UDP/TCP readiness checks, and rollback of the previous deployment on failure.
    *   Startup errors terminate the service; SIGINT/SIGTERM stop DNS and HTTP listeners together.

## Prerequisites

### Local Development
*   **Go:** Version 1.27.3 or higher, including the `crypto/x509` security fix for GO-2026-6809. The version requirement in `go.mod` also applies to deployment builds.
*   **Make:** For build automation.
*   **Development tools:** `make deps` installs the versions pinned in the Makefile: golangci-lint v2.15.0, lefthook v2.2.2 and govulncheck v1.9.0. The linter configuration uses the v2 schema.

### Ansible Deployment Target
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
metrics_addr: 127.0.0.1:8080 # JSON metrics and health check
request_timeout: 4s
cache_size: 10000           # In-memory cache capacity

# Restrict these examples to the actual VPN/LAN networks you serve.
allowed_clients:
  - 10.0.0.0/8
  - 172.16.0.0/12
  - 192.168.0.0/16
  - fc00::/7

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

resolver_anti_malware:
  name: cloudflare-malware
  addr: 1.1.1.2:443
  url: https://1.1.1.2/dns-query

resolver_anti_porn:
  name: cloudflare-family
  addr: 1.1.1.3:443
  url: https://1.1.1.3/dns-query

resolver_anti_ads:
  name: adguard
  addr: 94.140.14.14:443
  url: https://dns.adguard-dns.com/dns-query
```

Loopback clients are always allowed. Omitting `allowed_clients`, or setting it to an empty list, permits only loopback. This restriction applies to UDP and TCP independently of the host firewall. The supplied configuration allows private IPv4 and IPv6 ULA networks; use narrower CIDRs for your deployment. Metrics bind to loopback by default.

Startup rejects missing required resolvers, null resolver entries, invalid addresses or client networks, negative timeouts/cache sizes, and non-HTTPS DoH URLs. The selected primary resolver is `resolver_anti_porn` when `filter_porn` is enabled, otherwise `resolver_anti_malware` when `filter_malware` is enabled, otherwise `resolver_unfiltered`. Ads filtering additionally requires `resolver_anti_ads`; any whitelist requires `resolver_unfiltered`.

Filtering recognizes NXDOMAIN, unspecified IP addresses, and policy-related Extended DNS Errors, including AdGuard's `Filtered` response for TXT/MX/HTTPS records. Failed filter checks produce SERVFAIL instead of allowing or caching an unchecked positive answer. Confirmed blocks take precedence over another upstream's failure. Whitelist matching is case-insensitive and uses only the unfiltered resolver; an outage does not remove the exception.

The optional resolver `protocol` selects the upstream transport:

| `protocol` | Transport | Additional configuration |
| --- | --- | --- |
| `udp` | Plain DNS, with TCP retry for truncated responses | `addr` |
| `tcp` | Plain DNS over TCP | `addr` |
| `tls` | DNS over TLS | `addr`, optionally `tls_server_name` for the certificate hostname |
| `https` | DNS over HTTPS | `addr` and an absolute HTTPS `url` |

Without `protocol`, a resolver with `url` uses HTTPS; otherwise it keeps the existing TLS default. Plain DNS must be selected explicitly, for example:

```yaml
resolver_unfiltered:
  protocol: udp
  addr: 1.1.1.1:53
```

Upstream `addr` must contain a literal IP and a nonzero port. HTTPS connections use this address directly, avoiding a bootstrap dependency on the system resolver.

DNS server cookies are specific to an upstream. Each upstream exchange starts with the client-cookie portion only and can answer one `BADCOOKIE` challenge with that upstream's server cookie. Retries share the original request deadline. DoH response bodies are limited to 65,535 bytes, including streamed responses without a `Content-Length`.

## Development

The project uses a `Makefile` to standardize development tasks.

YAML parsing uses the maintained `go.yaml.in/yaml/v3` package; duplicate configuration keys are rejected. Logging uses Go's standard `log/slog` package. Dependency versions are recorded in `go.mod` and `go.sum`.

```bash
# Install linter and tools
make deps

# Run tests with race detection and coverage
make test

# Test deployment recovery using temporary files and simulated service management
make test-deploy

# Lint the code
make lint

# Format code and imports using the configured v2 formatter
make format

# Build binary locally (to verify compilation)
make build
```

## Deployment

Deployment is handled via **Ansible**, wrapped by Make commands for convenience. The playbook handles dependencies (`ufw`, `libcap`), optional WireGuard firewall rules, and systemd configuration. DNS client access is enforced by the service's `allowed_clients` setting even if UFW is inactive.

The candidate configuration is checked before changing the running service or system DNS. After activation, the playbook probes actual DNS responses over UDP and TCP. Selecting local system DNS additionally requires a successful probe of `127.0.0.1:53`. A failure restores the previous binary, configuration, unit, resolver file (including symlinks), and service state, and returns a deployment error. If rollback itself fails, the error reports the staging directory containing the recovery files; they are retained for manual recovery.

The checks are also available directly:

```bash
./service/dns_filter_linux -checkConfig -configFile config.yml
./service/dns_filter_linux -checkDNS 127.0.0.1:53
```

`-checkConfig` validates without opening listeners and prints the configured listen address as JSON. `-checkDNS` checks both transports by querying the root NS records. The local deployment tests simulate the service manager and readiness outcomes while exercising real Ansible file operations and the binary's configuration validator.

### Full Deployment
Builds the binary, uploads it, installs system dependencies, and restarts the service.

```bash
make deploy
```

### WireGuard Support
If you are running this on a WireGuard VPN server, enable the `WG` flag to automatically allow DNS over both UDP and TCP on port 53 of the `wg0` interface. TCP is required when an answer exceeds the client's UDP limit.

```bash
make deploy WG=yes
```

Full deployments update existing systemd units from `templates/dns-filter.service.j2`. `WG=yes` adds a dependency on `wg-quick@wg0.service`; a subsequent full deployment with `WG=no` removes it. Installation errors are reported normally.

### Fast Config Update
If you only changed `config.yml` (e.g., added a whitelist domain), use this to upload the config and reload the service without rebuilding the binary.

```bash
make deploy-config
```

Use a full deployment when upgrading the binary/configuration schema or changing the WireGuard service dependency. Config-only updates preserve the installed unit.

When upgrading an older installation, run `make deploy` once before `make deploy-config`: the installed binary must support `-checkConfig` and `-checkDNS` for config-only updates.

## Container Deployment with dryaf/deploy

[`dryaf/deploy`](https://github.com/dryaf/deploy) can manage dnsfilter as a rootless Podman Quadlet service. The supplied `deploy.yaml.example` uses its **binary** mode: Go builds `./service` locally, then the target builds `Containerfile` with the executable. The runtime image contains the static binary and CA certificates for HTTPS/TLS upstreams. Its Distroless base is pinned by digest, and it runs as UID/GID 65532 with a read-only root filesystem.

Copy and configure the deployment template:

```bash
cp deploy.yaml.example deploy.yaml
```

Set the SSH host/user, `target_dir`, and `build.arch` (`amd64` or `arm64`) in `deploy.yaml`. Configure the actual client networks and resolvers in `config.yml`. The local `deploy.yaml` is ignored by Git. `deploy` transfers `config.yml` as a separate artifact and mounts it read-only at `/etc/dnsfilter.yml`; `.dockerignore` excludes configuration from the image build context. The user namespace mapping lets the container read a configuration owned by the deployment user even with mode `0600`.

### Host Setup

Prepare rootless Podman, Quadlet, SSH access, and the systemd user manager with lingering according to the [deploy setup instructions](https://github.com/dryaf/deploy). The service uses **host networking**, preserving source IPs for `allowed_clients`. DNS binds directly to the configured host address over UDP and TCP; the template disables HTTP routing. With the default configuration, metrics are available on the host's `127.0.0.1:8080`.

Rootless processes can bind port 53 only if the host's `net.ipv4.ip_unprivileged_port_start` is at most 53. Check it first:

```bash
sysctl net.ipv4.ip_unprivileged_port_start
```

If its value is greater than 53, an administrator can persist the required setting on the target:

```bash
printf '%s\n' 'net.ipv4.ip_unprivileged_port_start=53' | sudo tee /etc/sysctl.d/90-dnsfilter-rootless.conf
sudo sysctl -p /etc/sysctl.d/90-dnsfilter-rootless.conf
```

This permits **all local unprivileged users** to bind ports 53 and above. Keep an existing lower value. Ensure the configured DNS and metrics ports are free and allow inbound UDP/TCP 53 only from the intended VPN/LAN networks in the host firewall. For testing without changing this setting, choose a high port such as `1053` in both `config.yml` and `quadlet.health_cmd`.

### Release and Operation

```bash
deploy validate production
deploy --dry-run release v0.1.0 production
deploy release v0.1.0 production
deploy status production
deploy logs production
```

Replace `v0.1.0` with a release tag at the current commit and use a clean, committed checkout. The dry run validates and prints the plan; the actual release may push the Git tag and changes the remote service. The Quadlet health command uses Podman's explicit `CMD` prefix to run `/dns-filter -checkDNS` without a shell and check both DNS transports. Keep its address aligned with `listen_addr` when changing the DNS binding. Process failures trigger a systemd restart; failed releases use deploy's rollback handling.

When replacing an existing Ansible installation, prepare the host first and pull the exact `FROM` image from `Containerfile` on the target as the deployment user while the old DNS service is still running. Stop the old **system** service (`sudo systemctl stop dns-filter`) for the cutover, then release the container. If the release fails, restart that old service. After a successful release, disable the old system service to avoid port conflicts after reboot. Container deployments manage their own user service; they do not perform the Ansible playbook's firewall or `/etc/resolv.conf` setup.

### Local Image

```bash
make container-build
# Optional: CONTAINER_ENGINE=docker or CONTAINER_ARCH=arm64

podman run -d --name dns-filter --network host --read-only \
  --userns=keep-id:uid=65532,gid=65532 \
  --cap-drop=all --security-opt=no-new-privileges \
  -v "$PWD/config.yml:/etc/dnsfilter.yml:ro,Z" \
  --health-cmd='CMD /dns-filter -checkDNS 0.0.0.0:53' \
  --health-interval=60s --health-timeout=5s --health-retries=3 \
  localhost/dnsfilter:local

podman healthcheck run dns-filter
podman logs dns-filter
podman stop dns-filter
```

These commands use the same host-network and port requirements as the deployment template. `make container-build` assembles a minimal context under `build/container`; `CONTAINER_IMAGE` overrides the image tag.

The base version is **Debian 13** (`static-debian13`); `nonroot` selects the variant, and the SHA-256 digest fixes its exact multi-architecture image index. A changed tag cannot silently replace the pinned image. For a base update, resolve the new digest, verify the [official Distroless signing identity](https://github.com/GoogleContainerTools/distroless#how-do-i-verify-distroless-images), review the change, then rebuild and test. With Cosign installed, verify the reference currently in `Containerfile` using:

```bash
base_image=$(awk '$1 == "FROM" { print $2 }' Containerfile)
cosign verify "$base_image" \
  --certificate-oidc-issuer https://accounts.google.com \
  --certificate-identity keyless@distroless.iam.gserviceaccount.com
```

Digest pinning fixes the selected content; signature verification checks its publisher. Neither guarantees that the publisher or the application dependencies are uncompromised.

## Observability

Once deployed, the service exposes an HTTP server on `127.0.0.1:8080` by default:

*   **Health Check:** `GET /health` -> `200 OK` after DNS listeners start; this is a liveness check, not an upstream connectivity probe.
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
*   `templates/dns-filter.service.j2`: Managed systemd unit.
*   `config.yml`: Runtime configuration.
*   `Containerfile`: Runtime image for the static Linux executable.
*   `deploy.yaml.example`: Podman/Quadlet deployment template for dryaf/deploy.
