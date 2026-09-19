"""Request dependencies: session resolution, CSRF, capability checks, tenant 404 mapping."""
from __future__ import annotations

from fastapi import Depends, HTTPException, Request

from ..contracts import Role
from ..core.auth import can, check_csrf, require, resolve_request
from ..core.db import Session as DbSession
from ..core.db import User
from ..core.repo import TenantViolation

Principal = tuple[User, DbSession]


def get_principal(request: Request) -> Principal:
    return resolve_request(request)


def guard(capability: str):
    """AuthN + CSRF (mutations) + AuthZ. Order avoids leaking object existence (AT01)."""

    def dep(request: Request, principal: Principal = Depends(get_principal)) -> Principal:
        user, sess = principal
        check_csrf(request, sess)
        require(capability, user.role)
        return principal

    return dep


def tenant_or_404(exc: TenantViolation) -> HTTPException:
    return HTTPException(
        status_code=404,
        detail={"code": "NOT_FOUND", "message": "Object not found or not visible to this tenant.",
                "retryable": False})


def tenant_of(principal: Principal) -> str:
    return principal[0].tenant_id


def user_id(principal: Principal) -> str:
    return principal[0].id
