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
## Run once before "docker compose up". The private key is mounted into the
## ImmuDB container; the public key is mounted into the verifier container.
## Both files are gitignored. Re-running rotates keys; restart both services
## afterward and delete the verifier state volume so the new root is accepted.
keygen:
	@mkdir -p keys
	openssl ecparam -genkey -name prime256v1 -noout -out keys/signing.key
	openssl ec -in keys/signing.key -pubout -out keys/signing.pub
	@echo "Keys written to keys/signing.key and keys/signing.pub"
	@echo "Run 'docker compose up -d --build' (or restart immudb + verifier) to apply."

## Boot CI infrastructure, run the full pytest suite, then tear down.
##
## OPA bundle timing: opa-config.yaml sets min_delay_seconds=10 for bundle
## polling. "docker compose up --wait" blocks until health checks pass (OPA
## binary alive), but the first bundle poll may not have completed yet.
## The 15-second sleep ensures OPA has loaded the policy before pytest runs.
test-integration:
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
