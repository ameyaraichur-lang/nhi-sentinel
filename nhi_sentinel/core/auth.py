"""Sessions, role capabilities and request authorization (SC03/SC04, API01, AT01/AT21).

Authorization is server-side only; the browser receives redacted view models (AR01).
Cross-tenant object access returns 404 with no metadata leakage (EX07/AT01).
"""
from __future__ import annotations

from datetime import timedelta

from fastapi import HTTPException, Request
from sqlalchemy import select

from ..contracts import Role
from ..contracts.models import Me
from .db import Session as DbSession
from .db import Tenant, User, get_settings, new_id, session_scope, utcnow
from .security import new_token, sha256_hex, verify_password

# SC04 capability matrix. Missing capability => 403 without object existence leakage.
CAPABILITIES: dict[Role, set[str]] = {
    Role.VIEWER: {"read:overview", "read:runs", "read:identities", "read:findings",
                  "read:agents", "read:reports", "read:connectors", "read:evidence",
                  "assistant:query"},
    Role.ANALYST: {"read:*", "run:create", "engagement:create", "scope:create",
                   "finding:update", "finding:retest", "finding:bulk_assign",
                   "owner:attest", "report:create", "report:submit", "assistant:query"},
    Role.OPERATOR: {"read:*", "run:create", "run:command", "run:stop", "connector:preflight",
                    "connector:update", "agent:command"},
    Role.APPROVER: {"read:*", "approval:decide"},
    Role.REVIEWER: {"read:*", "report:review", "report:release"},
    Role.AUDITOR: {"read:overview", "read:audit", "read:reports", "read:runs"},
    Role.TENANT_ADMIN: {"read:*", "settings:update", "membership:manage", "run:stop",
                        "connector:update", "agent:command", "read:audit"},
    # SC23/AT33: support can only REQUEST elevation; every tenant view needs an active
    # audited SupportGrant. No read:* by default - normal endpoints stay 403 (AT33).
    Role.SUPPORT: {"support:elevate"},
}

SESSION_COOKIE = "nhi_session"


def can(role: str, capability: str) -> bool:
    caps = CAPABILITIES.get(Role(role), set())
    return capability in caps or "read:*" in caps and capability.startswith("read:")


def require(capability: str, role: str) -> None:
    if not can(role, capability):
        raise HTTPException(status_code=403, detail={
            "code": "FORBIDDEN", "message": "Role lacks required capability.", "retryable": False})


def login(email: str, password: str) -> tuple[str, str, User]:
    """Returns (session_token, csrf_token, user). SC20: cookie set HttpOnly by route layer."""
    with session_scope() as s:
        user = s.execute(select(User).where(User.email == email)).scalars().first()
        if not user or not verify_password(password, user.password_hash):
            raise HTTPException(status_code=401, detail={
                "code": "INVALID_CREDENTIALS", "message": "Authentication failed.", "retryable": False})
        token = new_token()
        csrf = new_token()
        sess = DbSession(
            id=new_id("ses"), tenant_id=user.tenant_id, user_id=user.id,
            token_hash=sha256_hex(token), csrf_token=csrf,
            expires_at=utcnow() + timedelta(minutes=get_settings().bounds.session_ttl_min),
        )
        s.add(sess)
        return token, csrf, user


def logout(token_hash: str) -> None:
    with session_scope() as s:
        sess = s.execute(select(DbSession).where(DbSession.token_hash == token_hash)).scalars().first()
        if sess:
            sess.revoked_at = utcnow()


def resolve_request(request: Request) -> tuple[User, DbSession]:
    """Resolve session -> (user, session). Revoked/expired sessions are invisible (SC03)."""
    token = request.cookies.get(SESSION_COOKIE)
    if not token:
        raise HTTPException(status_code=401, detail={
            "code": "UNAUTHENTICATED", "message": "Authentication required.", "retryable": False})
    token_hash = sha256_hex(token)
    with session_scope() as s:
        sess = s.execute(select(DbSession).where(DbSession.token_hash == token_hash)).scalars().first()
        if not sess or sess.revoked_at is not None or sess.expires_at < utcnow():
            raise HTTPException(status_code=401, detail={
                "code": "SESSION_INVALID", "message": "Session expired or revoked.", "retryable": False})
        user = s.get(User, sess.user_id)
        if not user:
            raise HTTPException(status_code=401, detail={
                "code": "SESSION_INVALID", "message": "Session user missing.", "retryable": False})
        s.expunge(user)
        s.expunge(sess)
        return user, sess


def check_csrf(request: Request, sess: DbSession) -> None:
    """SC20: mutations require the session-bound CSRF header."""
    if request.method in ("GET", "HEAD", "OPTIONS"):
        return
    supplied = request.headers.get("X-CSRF-Token", "")
    import hmac
    if not supplied or not hmac.compare_digest(supplied, sess.csrf_token):
        raise HTTPException(status_code=403, detail={
            "code": "CSRF_INVALID", "message": "Missing or invalid CSRF token.", "retryable": False})


def me_view(user: User, sess: DbSession) -> Me:
    with session_scope() as s:
        tenant = s.get(Tenant, user.tenant_id)
    return Me(
        user_id=user.id, email=user.email, display_name=user.display_name, role=user.role,
        tenant_id=user.tenant_id, tenant_name=tenant.name if tenant else "unknown",
        csrf_token=sess.csrf_token,
        capabilities=sorted(CAPABILITIES.get(Role(user.role), set())),
    )
