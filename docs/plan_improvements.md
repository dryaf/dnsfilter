# Improvement Plan: Code Quality & Deployment Standardization

## Goal
To professionalize the `dnsfilter` project by establishing clear documentation, unifying the deployment strategy (favoring Ansible over fragile Make/SSH scripts), and enforcing code quality standards via linting and idiomatic Go practices.

## Phase 1: Documentation & Requirements (Completed)
- [x] Create `README.md` with:
    - Project Overview.
    - Prerequisites (Go, Ansible).
    - Configuration Guide (`config.yml` & `.env`).
    - Build & Run instructions.

## Phase 2: Tooling & Code Quality (Completed)
- [x] Create `.golangci.yml` configuration.
- [x] Update `Makefile`:
    - Add `lint` target.
    - Add `test` target with coverage.
    - Ensure `deps` installs necessary tooling.

## Phase 3: Deployment Consolidation (Completed)
- [x] Refactor `Makefile`:
    - Removed raw `ssh` and `scp` targets (`upload`, `setup`, `clean`).
    - Created `deploy` target that wraps the Ansible playbook.
    - Logic added to parse `.env` variables for Ansible inventory.
- [x] Refine `build_and_deploy.yml`:
    - Changed `hosts` to `all` for flexibility.
    - Removed interactive prompt (`vars_prompt`) in favor of `wg_required` variable.
    - Cleaned up task idempotency and binary permissions.

## Phase 4: Go Code Refactoring (Completed)
- [x] **Context Propagation:** The `Resolve` method now creates a context with a configurable timeout and passes it down.
- [x] **Logging:** Implemented structured logging (`slog`) with request IDs, client IPs, and domain context attached to all log entries during resolution.
- [x] **Refactoring:** Decomposed the `ResolveDomain` "God function" into smaller, single-purpose methods (`checkWhitelist`, `resolveConcurrently`).
- [x] **Configuration Safety:** Added timeouts to the `dns.Server` and configuration validation.