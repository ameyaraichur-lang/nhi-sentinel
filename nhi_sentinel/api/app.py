"""FastAPI application factory (AR01/AR02): session auth, EX07 errors, tenant 404s,
rate limiting (SC22/AT25), engine lifespan, static control-room portal."""
from __future__ import annotations

import asyncio
import contextlib
import threading
import time
import uuid
from collections import deque

from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from starlette.exceptions import HTTPException as StarletteHTTPException
from fastapi.staticfiles import StaticFiles
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

from ..config import get_settings
from ..core.repo import TenantViolation
from ..worker import engine
from . import routes_core, routes_data, routes_gov, routes_integrations


async def _engine_loop(stop: asyncio.Event):
    interval = get_settings().bounds.engine_tick_ms / 1000.0
    while not stop.is_set():
        with contextlib.suppress(Exception):
            await asyncio.to_thread(engine.tick)
        with contextlib.suppress(TimeoutError):
            await asyncio.wait_for(stop.wait(), timeout=interval)


async def _governance_loop(stop: asyncio.Event):
    """S00 subscriptions + retention/expiry maintenance every 10s (OP01/OP08)."""
    while not stop.is_set():
        with contextlib.suppress(Exception):
            await asyncio.to_thread(_maintenance_pass)
        with contextlib.suppress(TimeoutError):
            await asyncio.wait_for(stop.wait(), timeout=10.0)


def _maintenance_pass() -> None:
    from ..scheduler import record_signatures, run_due_subscriptions
    from ..governance import expire_exceptions, purge_expired
    from .core.db import session_scope
    run_due_subscriptions()
    record_signatures()
    with session_scope() as s:
        expire_exceptions(s)
    with session_scope() as s:
        purge_expired(s)


def correlation_id(request: Request) -> str:
    return request.headers.get("X-Correlation-ID") or uuid.uuid4().hex[:12]


def error_payload(code: str, message: str, correlation: str, retryable: bool = False,
                  details: dict | None = None) -> dict:
    return {"error": {"code": code, "message": message, "correlation_id": correlation,
                      "retryable": retryable, **({"details": details} if details else {})}}


class CorrelationHeader(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        cid = correlation_id(request)
        request.state.correlation_id = cid
        response = await call_next(request)
        response.headers["X-Correlation-ID"] = cid
        return response


class SecurityHeaders(BaseHTTPMiddleware):
    """SC20/AT21: browser defenses apply to every response including the portal."""

    async def dispatch(self, request, call_next):
        response = await call_next(request)
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
            "connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'")
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        return response


class RateLimitMiddleware(BaseHTTPMiddleware):
    """SC22/AT25: in-process sliding-window limiter keyed per client IP (60s window).

    Limit comes from Settings.rate_limit_per_min (env NHI_RATE_LIMIT_PER_MIN; 0 disables).
    Exempt: /health and the /portal prefix. Over-limit requests get the EX07 envelope with
    code RATE_LIMITED plus a Retry-After header. Single-process only - multi-worker
    deployments would move the window into the shared store."""

    WINDOW_S = 60.0

    def __init__(self, app):
        super().__init__(app)
        # bind the limit at construction: per-request get_settings() would let one app's
        # test-scoped settings mutate another app instance's limiter
        self._limit = get_settings().rate_limit_per_min
        self._hits: dict[str, deque[float]] = {}
        self._lock = threading.Lock()

    async def dispatch(self, request, call_next):
        limit = self._limit
        path = request.url.path
        if limit <= 0 or path == "/health" or path.startswith("/portal"):
            return await call_next(request)
        client_ip = request.client.host if request.client else "unknown"
        now = time.monotonic()
        with self._lock:
            hits = self._hits.setdefault(client_ip, deque())
            cutoff = now - self.WINDOW_S
            while hits and hits[0] <= cutoff:
                hits.popleft()
            if len(hits) >= limit:
                retry_after = max(1, int(self.WINDOW_S - (now - hits[0])) + 1)
                cid = getattr(request.state, "correlation_id", None) or correlation_id(request)
                return JSONResponse(
                    status_code=429,
                    content=error_payload("RATE_LIMITED",
                                          "Too many requests for this client; slow down.",
                                          cid, True, {"retry_after_s": retry_after}),
                    headers={"Retry-After": str(retry_after)})
            hits.append(now)
        return await call_next(request)


def create_app() -> FastAPI:
    app = FastAPI(title=get_settings().app_name, version="0.1.0", docs_url="/api-docs")
    # add order = wrap order: the LAST add_middleware ends up outermost, so CorrelationHeader
    # wraps RateLimitMiddleware and a 429 body carries the same correlation id as the header.
    app.add_middleware(RateLimitMiddleware)
    app.add_middleware(CorrelationHeader)
    app.add_middleware(SecurityHeaders)
    app.include_router(routes_core.router)
    app.include_router(routes_data.router)
    app.include_router(routes_gov.router)
    app.include_router(routes_integrations.router)

    app.add_exception_handler(TenantViolation, tenant_violation_handler)
    app.add_exception_handler(StarletteHTTPException, starlette_http_handler)
    app.add_exception_handler(HTTPException, http_exc_handler)
    app.add_exception_handler(RequestValidationError, validation_handler)
    app.add_exception_handler(Exception, unhandled_handler)

    stop_event = asyncio.Event()

    @app.on_event("startup")
    async def _startup():
        from ..seed import ensure_seed
        ensure_seed()
        app.state.engine_stop = stop_event
        app.state.engine_task = asyncio.create_task(_engine_loop(stop_event))
        app.state.governance_task = asyncio.create_task(_governance_loop(stop_event))

    @app.on_event("shutdown")
    async def _shutdown():
        stop_event.set()

    web_dir = get_settings().web_dir
    if web_dir.exists():
        app.mount("/portal", StaticFiles(directory=str(web_dir), html=True), name="portal")

    @app.get("/health")
    async def health():
        return {"ok": True, "service": "nhi-sentinel", "synthetic": True}

    return app


async def tenant_violation_handler(request: Request, exc: TenantViolation):
    return JSONResponse(status_code=404, content=error_payload(
        "NOT_FOUND", "Object not found or not visible to this tenant.", correlation_id(request)))


async def starlette_http_handler(request: Request, exc: StarletteHTTPException):
    if isinstance(exc, HTTPException):
        return await http_exc_handler(request, exc)
    return JSONResponse(status_code=exc.status_code, content=error_payload(
        {404: "NOT_FOUND", 405: "METHOD_NOT_ALLOWED"}.get(exc.status_code, "ERROR"),
        exc.detail if isinstance(exc.detail, str) else "request failed",
        correlation_id(request)))


async def http_exc_handler(request: Request, exc: HTTPException):
    detail = exc.detail
    if isinstance(detail, dict) and "code" in detail:
        return JSONResponse(status_code=exc.status_code, content=error_payload(
            detail.get("code", "ERROR"), detail.get("message", "request failed"),
            correlation_id(request), detail.get("retryable", False), detail.get("details")))
    return JSONResponse(status_code=exc.status_code, content=error_payload(
        "ERROR", str(detail), correlation_id(request)))


async def validation_handler(request: Request, exc: RequestValidationError):
    return JSONResponse(status_code=400, content=error_payload(
        "VALIDATION", "Request body failed schema validation.",
        correlation_id(request), details={"errors": exc.errors()[:5]}))


async def unhandled_handler(request: Request, exc: Exception):
    return JSONResponse(status_code=500, content=error_payload(
        "INTERNAL", "Unexpected server error (no details leaked).", correlation_id(request)))


def main() -> None:
    import uvicorn
    uvicorn.run("nhi_sentinel.api.app:create_app", factory=True, host="127.0.0.1", port=8650)


if __name__ == "__main__":
    main()
