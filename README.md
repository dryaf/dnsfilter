# DNS Filter & Proxy

A high-performance, custom DNS proxy written in Go. This service acts as a DNS middleware that filters traffic based on categories (Malware, Porn, Ads) and forwards legitimate requests to specific upstream resolvers (Cloudflare, AdGuard, etc.).

## Features

- **Category Blocking:** Toggleable filters for Malware, Adult Content, and Advertisements.
- **Split-Horizon Resolution:** Routes traffic to different upstream resolvers based on the type of content being filtered (e.g., using Cloudflare's specific filter endpoints).
- **DNS-over-HTTPS (DoH) Support:** Can communicate with upstream resolvers via DoH for privacy.
- **Allowlisting:** Bypass filters for specific domains.
- **Systemd Integration:** Runs as a native Linux service.

## Prerequisites

### Local Development
- **Go:** Version 1.25 or higher.
- **Make:** For build automation.

### Deployment
- **Ansible:** For provisioning the remote server.
- **SSH Access:** Root or sudo access to the target Linux server.

## Configuration

### 1. Environment Variables (`.env`)
Copy the sample file and configure your deployment target:

```bash
cp .env-sample .env
```

Edit `.env`:
```ini
SSH_HOST=user@your-server-ip
SSH_PORT=22
```

### 2. DNS Configuration (`config.yml`)
The service behavior is controlled by `config.yml`.

```yaml
listen_addr: 0.0.0.0:53
filter_malware: true
filter_porn: true
filter_ads: true

whitelist:
  - trusted-site.com

# Resolvers definition...
```

## Build and Run

### Local Build
To compile the binary for Linux (AMD64):

```bash
make build
```

### Local Testing
To run tests:

```bash
go test ./...
```

## Deployment

The project uses **Ansible** for reliable deployment.

### 1. Update Inventory
Ensure your `build_and_deploy.yml` hosts match your target, or configure an Ansible inventory file.

### 2. Deploy
You can run the playbook directly:

```bash
ansible-playbook build_and_deploy.yml -i "your-server-ip," --user root --ask-pass
```

*Note: You may be prompted to enable WireGuard support (`wg_required`).*

## Project Structure

- `lib/`: Core DNS logic, filtering engine, and resolver implementation.
- `service/`: System service wrapper (kardianos/service) and CLI entry point.
- `config.yml`: Runtime configuration.
- `build_and_deploy.yml`: Ansible playbook for provisioning.

## License

Private / Proprietary.