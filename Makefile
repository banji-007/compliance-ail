# AIL Integration Test Makefile
#
# Requires:
#   - Docker Compose v2  (docker compose, not legacy docker-compose)
#   - Python 3.11+ with project venv activated, or pytest on PATH
#   - openssl on PATH (for keygen)
#
# Optional env overrides:
#   IMMUDB_USER      (default: immudb)
#   IMMUDB_PASSWORD  (default: immudb)

.PHONY: keygen test-integration test-integration-down

## Generate the ECDSA P-256 signing key pair used by ImmuDB and the verifier.
## Skips generation if keys/signing.key already exists (idempotent).
## To rotate keys: delete keys/ and re-run, then also delete the verifier
## state volume (docker compose down -v) so the new root is accepted.
keygen:
	@mkdir -p keys
	@if [ -f keys/signing.key ]; then \
	  echo "keygen: keys/signing.key already exists — reusing existing keys."; \
	else \
	  openssl ecparam -genkey -name prime256v1 -noout -out keys/signing.key && \
	  openssl ec -in keys/signing.key -pubout -out keys/signing.pub && \
	  echo "keygen: keys written to keys/signing.key and keys/signing.pub"; \
	fi

## Boot CI infrastructure, run the full pytest suite, then tear down.
## Starts with "down -v" to ensure a hermetic run: any previous stack and
## its volumes (verifier state, control-plane DB) are removed before the
## new stack starts. This prevents stale verifier state from a prior keygen
## rotation from causing opaque proof failures.
##
## OPA bundle timing: opa-config.yaml sets min_delay_seconds=10 for bundle
## polling. "docker compose up --wait" blocks until health checks pass (OPA
## binary alive), but the first bundle poll may not have completed yet.
## The 15-second sleep ensures OPA has loaded the policy before pytest runs.
test-integration:
	docker compose -f docker-compose.test.yml down -v
	$(MAKE) keygen
	docker compose -f docker-compose.test.yml up -d --wait
	@echo "Waiting 15s for OPA to complete its first bundle poll..."
	sleep 15
	SPIRE_DISABLED=true \
	  OPA_URL=http://localhost:8181/v1/data/ail/main/allow \
	  CONTROL_PLANE_URL=http://localhost:8002 \
	  IMMUDB_URL=http://localhost:8080 \
	  IMMUDB_USER=$${IMMUDB_USER:-immudb} \
	  IMMUDB_PASSWORD=$${IMMUDB_PASSWORD:-immudb} \
	  VERIFIER_URL=http://localhost:8003 \
	  CONTROL_PLANE_API_KEY=$${CONTROL_PLANE_API_KEY:-test-api-key} \
	  python -m pytest tests/ -v
	docker compose -f docker-compose.test.yml down -v

## Tear down CI infrastructure without running tests (cleanup after failure).
test-integration-down:
	docker compose -f docker-compose.test.yml down -v
