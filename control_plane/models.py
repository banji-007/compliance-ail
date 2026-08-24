from sqlalchemy import Boolean, Column, DateTime, Integer, String, Text
from sqlalchemy.sql import func

from database import Base


class Tenant(Base):
    __tablename__ = "tenants"

    id = Column(String, primary_key=True, index=True)
    name = Column(String, nullable=False)

    # Compliance pack toggles
    enable_gdpr = Column(Boolean, default=True, nullable=False)
    enable_soc2 = Column(Boolean, default=True, nullable=False)
    enable_finops = Column(Boolean, default=True, nullable=False)
    enable_hipaa = Column(Boolean, default=False, nullable=False)

    # Tenant-specific policy variables injected into bundle data.json
    # Comma-separated lists; consumed by Rego packs via data.ail.config.*
    allowed_cost_centers = Column(
        Text,
        default="engineering,marketing,finance,operations",
        nullable=False,
    )
    # Consumed by gdpr.rego: data.ail.config.approved_regions
    approved_regions = Column(
        Text,
        default="eu-central-1,us-east-1",
        nullable=False,
    )
    # Consumed by gdpr.rego: data.ail.config.approved_purposes
    approved_purposes = Column(
        Text,
        default="customer_support,billing",
        nullable=False,
    )

    created_at = Column(DateTime, server_default=func.now(), nullable=False)
    updated_at = Column(DateTime, server_default=func.now(), onupdate=func.now(), nullable=False)


class CallContent(Base):
    """
    Erasable store for raw tool-call arguments (D5, Phase 1). The immutable
    ImmuDB ledger holds only input_sha256; the full arguments live here,
    keyed by call_id (D7, Phase 1.1 - minted by the interceptor at intercept
    time, independent of ImmuDB's own transaction numbering), so a GDPR
    Article 17 erasure request can delete this row without touching the
    ledger. Deleting a row does not invalidate the ledger's proof of what
    was decided or that the input hashed to the value the ledger recorded.
    """

    __tablename__ = "call_content"

    call_id = Column(String, primary_key=True)
    payload_json = Column(Text, nullable=False)

    created_at = Column(DateTime, server_default=func.now(), nullable=False)


class StateAnchor(Base):
    """
    D23 (Phase 3b): one externally anchored ImmuDB checkpoint.

    A row exists only for a state that was actually accepted by a public
    transparency log. anchor_service/ submits first and records second, so
    "there is a row" and "external corroboration exists" are the same
    statement - which is what lets GET /audit/bundle decide, from the store
    alone, whether a bundle may claim corroboration.

    checkpoint_* is the ImmuDB signed state: the database name, the
    transaction, its Merkle root, and the server's own ECDSA signature over
    them. entry_json is the TransparencyLogEntry the log returned verbatim,
    including its inclusion proof and witnessed checkpoint - stored as
    returned rather than reshaped, so an offline checker verifies the log's
    own bytes with the log client's own code rather than this project's
    interpretation of them.

    Nothing here is trusted on its own. The verifier re-checks the
    checkpoint's ImmuDB signature before using it as a proof source, and
    tools/ail_verify_bundle.py re-checks the whole Rekor chain offline
    against an independently held trust root. A forged row produces a bundle
    that fails offline verification, which is where a forgery should be
    caught rather than at the edge of the system that would be forging it.
    """

    __tablename__ = "state_anchors"

    checkpoint_tx_id = Column(Integer, primary_key=True)
    checkpoint_db = Column(String, nullable=False)
    checkpoint_tx_hash = Column(String, nullable=False)     # base64
    checkpoint_signature = Column(String, nullable=False)   # base64, DER ECDSA

    log_url = Column(String, nullable=False)
    log_url_source = Column(String, nullable=False)   # which TUF document answered
    log_index = Column(String, nullable=False)
    anchor_key_fingerprint = Column(String, nullable=False)
    anchor_payload_format = Column(String, nullable=False)
    entry_json = Column(Text, nullable=False)

    created_at = Column(DateTime, server_default=func.now(), nullable=False)
