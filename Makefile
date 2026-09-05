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
##
## Rotating a WRITER key (D22) is a different operation and needs no volume
## deleted: records already written stay verifiable against the old public
## key, which is why a bundle names its writer by fingerprint and a checker
## can be handed more than one --writer-key. Rotation after a suspected
## compromise additionally means adding the old fingerprint to the checker's
## deny-list, or every record that key ever signed still verifies - see
## docs/adr/0012-writer-signing-and-external-anchoring.md.
keygen:
	@mkdir -p keys
	@if [ -f keys/signing.key ]; then \
	  echo "keygen: keys/signing.key already exists — reusing existing keys."; \
	else \
	  openssl ecparam -genkey -name prime256v1 -noout -out keys/signing.key && \
	  openssl ec -in keys/signing.key -pubout -out keys/signing.pub && \
	  echo "keygen: keys written to keys/signing.key and keys/signing.pub"; \
	fi
	@chmod 644 keys/signing.key keys/signing.pub
	@# D22/D23 (Phase 3b): three more long-lived P-256 pairs, generated
	@# by the same openssl invocation as the ImmuDB key above, because
	@# they are the same kind of thing - a key whose custody is an
	@# operational matter, not a credential the platform mints.
	@#   writer-decision      decision-service signs decision + intent records
	@#   writer-control-plane the control plane signs erasure tombstones
	@#   writer-verifier      the verifier signs the fault record (D35)
	@#   anchor-signing       anchor-service signs Rekor submissions
	@# One writer key per writer, not one shared key, so a bundle's
	@# writer_key_fingerprint names which service wrote the record, and so one
	@# writer can be put on a checker's deny-list without revoking the others.
	@# Three writers since D35 (Phase 3c-3c) gave the verifier a record of its
	@# own. See docs/adr/0012-writer-signing-and-external-anchoring.md.
	@for name in writer-decision writer-control-plane writer-verifier anchor-signing; do \
	  if [ -f keys/$$name.key ]; then \
	    echo "keygen: keys/$$name.key already exists - reusing existing key."; \
	  else \
	    openssl ecparam -genkey -name prime256v1 -noout -out keys/$$name.key && \
	    openssl ec -in keys/$$name.key -pubout -out keys/$$name.pub && \
	    echo "keygen: keys written to keys/$$name.key and keys/$$name.pub"; \
	  fi; \
	  chmod 644 keys/$$name.key keys/$$name.pub; \
	done
	@mkdir -p decision_service/secrets
	@if [ -f decision_service/secrets/vault_api_token.txt ]; then \
	  echo "keygen: decision_service/secrets/vault_api_token.txt already exists — reusing."; \
	else \
	  openssl rand -hex 32 > decision_service/secrets/vault_api_token.txt && \
	  echo "keygen: vault token written to decision_service/secrets/vault_api_token.txt"; \
	fi
	@chmod 600 decision_service/secrets/vault_api_token.txt

## Boot CI infrastructure, run the full pytest suite, then tear down.
## Starts with "down -v" to ensure a hermetic run: any previous stack and
## its volumes (verifier state, control-plane DB) are removed before the
## new stack starts. This prevents stale verifier state from a prior keygen
## rotation from causing opaque proof failures.
##
## --build (P12-5, Phase 1.2): "up -d --wait" alone does not rebuild an
## image that already exists under this Compose project's tag, even when
## the source it was built from has changed - five separate sessions hit
## this as a wall of spurious failures against stale code (docs/reports/
## phase-1-1.md, section 1: "two full docker compose build <service>
## passes were needed this session"; a prior session hit 30 at once).
## --build forces a build (respecting Docker's own layer cache, so an
## unchanged service is still fast) before the containers start, every run.
##
## OPA bundle timing: opa-config.yaml sets min_delay_seconds=10 for bundle
## polling. "docker compose up --wait" blocks until health checks pass (OPA
## binary alive), but the first bundle poll may not have completed yet.
## The 15-second sleep ensures OPA has loaded the policy before pytest runs.
##
## docker compose auto-loads a root .env regardless of -f, so the control
## plane, dashboard, and immudb containers enforce whatever IMMUDB_USER,
## IMMUDB_PASSWORD, CONTROL_PLANE_READ_KEY/WRITE_KEY,
## VERIFIER_READ_KEY/WRITE_KEY (D21, Phase 3a completion), and
## DASHBOARD_READ/WRITE_USER/PASSWORD are in .env if one exists. pytest must
## authenticate with those same values, so each is read from .env in its own
## isolated subshell if present, falling back to the prior default otherwise.
## Isolated per-variable subshells, not a blanket ". .env", so an unrelated
## var in .env (OPENAI_API_KEY, say) can never shadow an already-correct
## value already exported in the caller's shell. Without this, a
## contributor's real .env silently breaks test_cross_process with a 403
## that has nothing to do with the code under test.
test-integration:
	docker compose -f docker-compose.test.yml down -v
	$(MAKE) keygen
	docker compose -f docker-compose.test.yml up -d --build --wait
	@echo "Waiting 15s for OPA to complete its first bundle poll..."
	sleep 15
	IMMUDB_USER_ENV=$$( [ -f .env ] && ( set -a; . ./.env; set +a; echo "$$IMMUDB_USER" ) ); \
	IMMUDB_PASSWORD_ENV=$$( [ -f .env ] && ( set -a; . ./.env; set +a; echo "$$IMMUDB_PASSWORD" ) ); \
	CONTROL_PLANE_READ_KEY_ENV=$$( [ -f .env ] && ( set -a; . ./.env; set +a; echo "$$CONTROL_PLANE_READ_KEY" ) ); \
	CONTROL_PLANE_WRITE_KEY_ENV=$$( [ -f .env ] && ( set -a; . ./.env; set +a; echo "$$CONTROL_PLANE_WRITE_KEY" ) ); \
	VERIFIER_READ_KEY_ENV=$$( [ -f .env ] && ( set -a; . ./.env; set +a; echo "$$VERIFIER_READ_KEY" ) ); \
	VERIFIER_WRITE_KEY_ENV=$$( [ -f .env ] && ( set -a; . ./.env; set +a; echo "$$VERIFIER_WRITE_KEY" ) ); \
	DASHBOARD_READ_USER_ENV=$$( [ -f .env ] && ( set -a; . ./.env; set +a; echo "$$DASHBOARD_READ_USER" ) ); \
	DASHBOARD_READ_PASSWORD_ENV=$$( [ -f .env ] && ( set -a; . ./.env; set +a; echo "$$DASHBOARD_READ_PASSWORD" ) ); \
	DASHBOARD_WRITE_USER_ENV=$$( [ -f .env ] && ( set -a; . ./.env; set +a; echo "$$DASHBOARD_WRITE_USER" ) ); \
	DASHBOARD_WRITE_PASSWORD_ENV=$$( [ -f .env ] && ( set -a; . ./.env; set +a; echo "$$DASHBOARD_WRITE_PASSWORD" ) ); \
	SPIRE_DISABLED=true \
	  OPA_URL=http://localhost:8181/v1/data/ail/main/evaluation \
	  DECISION_SERVICE_URL=http://localhost:8010/decide \
	  AIL_BUNDLE_NAME=$${AIL_BUNDLE_NAME:-ail-policies} \
	  CONTROL_PLANE_URL=http://localhost:8002 \
	  IMMUDB_URL=http://localhost:8080 \
	  IMMUDB_USER=$${IMMUDB_USER_ENV:-$${IMMUDB_USER:-immudb}} \
	  IMMUDB_PASSWORD=$${IMMUDB_PASSWORD_ENV:-$${IMMUDB_PASSWORD:-immudb}} \
	  VERIFIER_URL=http://localhost:8003 \
	  CONTROL_PLANE_READ_KEY=$${CONTROL_PLANE_READ_KEY_ENV:-$${CONTROL_PLANE_READ_KEY:-test-read-key}} \
	  CONTROL_PLANE_WRITE_KEY=$${CONTROL_PLANE_WRITE_KEY_ENV:-$${CONTROL_PLANE_WRITE_KEY:-test-write-key}} \
	  VERIFIER_READ_KEY=$${VERIFIER_READ_KEY_ENV:-$${VERIFIER_READ_KEY:-test-verifier-read-key}} \
	  VERIFIER_WRITE_KEY=$${VERIFIER_WRITE_KEY_ENV:-$${VERIFIER_WRITE_KEY:-test-verifier-write-key}} \
	  AIL_WRITER_SIGNING_KEY=$$(pwd)/keys/writer-decision.key \
	  AIL_ANCHOR_SIGNING_KEY=$$(pwd)/keys/anchor-signing.key \
	  DASHBOARD_URL=http://localhost:3001 \
	  DASHBOARD_READ_USER=$${DASHBOARD_READ_USER_ENV:-$${DASHBOARD_READ_USER:-test-dashboard-reader}} \
	  DASHBOARD_READ_PASSWORD=$${DASHBOARD_READ_PASSWORD_ENV:-$${DASHBOARD_READ_PASSWORD:-test-dashboard-read-pw}} \
	  DASHBOARD_WRITE_USER=$${DASHBOARD_WRITE_USER_ENV:-$${DASHBOARD_WRITE_USER:-test-dashboard-writer}} \
	  DASHBOARD_WRITE_PASSWORD=$${DASHBOARD_WRITE_PASSWORD_ENV:-$${DASHBOARD_WRITE_PASSWORD:-test-dashboard-write-pw}} \
	  python -m pytest tests/ -v
	docker compose -f docker-compose.test.yml down -v

## Tear down CI infrastructure without running tests (cleanup after failure).
test-integration-down:
	docker compose -f docker-compose.test.yml down -v
