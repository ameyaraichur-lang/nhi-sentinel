"""Shared tenant guard for services that receive ORM objects."""
from ..core.repo import TenantViolation


def assert_tenant(obj, tenant_id: str) -> None:
    if obj is None or getattr(obj, "tenant_id", None) != tenant_id:
        raise TenantViolation(getattr(obj, "id", "?"))
