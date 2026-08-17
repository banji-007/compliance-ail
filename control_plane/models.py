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
    keyed by the ImmuDB transaction id, so a GDPR Article 17 erasure request
    can delete this row without touching the ledger. Deleting a row does not
    invalidate the ledger's proof of what was decided or that the input
    hashed to the value the ledger recorded.
    """

    __tablename__ = "call_content"

    tx_id = Column(Integer, primary_key=True)
    payload_json = Column(Text, nullable=False)

    created_at = Column(DateTime, server_default=func.now(), nullable=False)
