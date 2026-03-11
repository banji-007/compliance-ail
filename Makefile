# AIL Integration Test Makefile
#
# Requires:
#   - Docker Compose v2  (docker compose, not legacy docker-compose)
#   - Python 3.11+ with project venv activated, or pytest on PATH
#
# Optional env overrides:
#   IMMUDB_USER      (default: immudb)
#   IMMUDB_PASSWORD  (default: immudb)

.PHONY: test-integration test-integration-down

## Boot CI infrastructure, run the full pytest suite, then tear down.
##
## OPA bundle timing: opa-config.yaml sets min_delay_seconds=10 for bundle
## polling. "docker compose up --wait" blocks until health checks pass (OPA
## binary alive), but the first bundle poll may not have completed yet.
## The 15-second sleep ensures OPA has loaded the policy before pytest runs.
test-integration:
	docker compose -f docker-compose.test.yml up -d --wait
	@echo "Waiting 15s for OPA to complete its first bundle poll..."
	sleep 15
	SPIRE_DISABLED=true \
	  OPA_URL=http://localhost:8181/v1/data/ail/main/allow \
	  CONTROL_PLANE_URL=http://localhost:8002 \
	  IMMUDB_URL=http://localhost:8080 \
	  IMMUDB_USER=$${IMMUDB_USER:-immudb} \
	  IMMUDB_PASSWORD=$${IMMUDB_PASSWORD:-immudb} \
	  python -m pytest tests/ -v
	docker compose -f docker-compose.test.yml down -v

## Tear down CI infrastructure without running tests (cleanup after failure).
test-integration-down:
	docker compose -f docker-compose.test.yml down -v
