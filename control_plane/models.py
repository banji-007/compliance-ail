from sqlalchemy import Boolean, Column, DateTime, String, Text
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
    # Comma-separated list; consumed by finops.rego via data.ail.config.allowed_cost_centers
    allowed_cost_centers = Column(
        Text,
        default="engineering,marketing,finance,operations",
        nullable=False,
    )

    created_at = Column(DateTime, server_default=func.now(), nullable=False)
    updated_at = Column(DateTime, server_default=func.now(), onupdate=func.now(), nullable=False)
