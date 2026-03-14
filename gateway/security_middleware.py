"""
Security Middleware
===================
Production security middleware for the AI Security Gateway:
  - API Key Authentication
  - Rate Limiting (per-key)
  - Security Headers (HSTS, CSP, X-Frame-Options, etc.)
  - Global Error Handler (never leaks stack traces)
  - Input Sanitization
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import time
import traceback
from typing import Any

from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

logger = logging.getLogger("ai_security_gateway")


# ── API Key Authentication ────────────────────────────────────

# API keys config: stored as SHA-256 hashes for security
# In production, these would come from a database or secret manager.
# Format: { "key_hash": { "name": "...", "permissions": [...] } }

DEFAULT_API_KEYS_FILE = os.path.join(
    os.path.dirname(os.path.dirname(__file__)), "config", "api_keys.json"
)


def _hash_key(key: str) -> str:
    """SHA-256 hash an API key for storage/comparison."""
    return hashlib.sha256(key.encode("utf-8")).hexdigest()


class APIKeyAuth:
    """
    API Key authentication manager.
    Keys are stored hashed — never in plaintext.
    """

    def __init__(self, keys_file: str | None = None) -> None:
        self._keys_file = keys_file or DEFAULT_API_KEYS_FILE
        self._keys: dict[str, dict[str, Any]] = {}
        self._enabled = True
        self._load_keys()

    def _load_keys(self) -> None:
        """Load API keys from config file."""
        if not os.path.exists(self._keys_file):
            logger.warning(
                "API keys file not found at %s — authentication DISABLED. "
                "Create the file to enable API key auth.",
                self._keys_file,
            )
            self._enabled = False
            return

        try:
            with open(self._keys_file, "r", encoding="utf-8") as f:
                config = json.load(f)

            self._keys = config.get("keys", {})
            self._enabled = config.get("enabled", True)

            if self._enabled:
                logger.info("API key auth enabled — %d key(s) loaded", len(self._keys))
            else:
                logger.info("API key auth explicitly disabled in config")
        except Exception as e:
            logger.error("Failed to load API keys: %s", e)
            self._enabled = False

    @property
    def is_enabled(self) -> bool:
        return self._enabled

    def validate(self, api_key: str | None) -> tuple[bool, str, dict[str, Any]]:
        """
        Validate an API key.

        Returns:
            (is_valid, key_name_or_error, key_metadata)
        """
        if not self._enabled:
            return True, "auth_disabled", {}

        if not api_key:
            return False, "Missing X-API-Key header", {}

        key_hash = _hash_key(api_key)
        key_config = self._keys.get(key_hash)

        if not key_config:
            return False, "Invalid API key", {}

        # Check if key is active
        if not key_config.get("active", True):
            return False, "API key is disabled", {}

        return True, key_config.get("name", "unknown"), key_config

    def reload(self) -> None:
        self._load_keys()


# ── Authentication Middleware ─────────────────────────────────

# Paths that don't require authentication
PUBLIC_PATHS = {"/", "/health", "/docs", "/redoc", "/openapi.json", "/favicon.ico", "/audit"}


class AuthMiddleware(BaseHTTPMiddleware):
    """FastAPI middleware for API key authentication."""

    def __init__(self, app: FastAPI, auth: APIKeyAuth) -> None:
        super().__init__(app)
        self._auth = auth

    async def dispatch(self, request: Request, call_next):
        path = request.url.path

        # Skip auth for public paths and static files
        if path in PUBLIC_PATHS or path.startswith("/static"):
            return await call_next(request)

        # Validate API key
        api_key = request.headers.get("X-API-Key")
        is_valid, result, metadata = self._auth.validate(api_key)

        if not is_valid:
            logger.warning(
                "Auth failed: %s | IP: %s | Path: %s",
                result, request.client.host if request.client else "unknown", path,
            )
            return JSONResponse(
                status_code=401,
                content={"detail": result},
                headers={"WWW-Authenticate": "ApiKey"},
            )

        # Attach key info to request state for downstream use
        request.state.api_key_name = result
        request.state.api_key_meta = metadata
        return await call_next(request)


# ── Rate Limiting ─────────────────────────────────────────────

class RateLimiter:
    """
    Simple in-memory sliding window rate limiter.
    Production would use Redis, but this is sufficient for single-server.
    """

    def __init__(
        self,
        max_requests: int = 60,
        window_seconds: int = 60,
    ) -> None:
        self._max_requests = max_requests
        self._window = window_seconds
        self._requests: dict[str, list[float]] = {}

    def is_allowed(self, key: str) -> tuple[bool, int, int]:
        """
        Check if a request is allowed under rate limits.

        Returns:
            (allowed, remaining_requests, retry_after_seconds)
        """
        now = time.time()
        window_start = now - self._window

        # Clean old entries
        if key in self._requests:
            self._requests[key] = [
                t for t in self._requests[key] if t > window_start
            ]
        else:
            self._requests[key] = []

        current_count = len(self._requests[key])

        if current_count >= self._max_requests:
            # Calculate retry-after
            oldest = self._requests[key][0] if self._requests[key] else now
            retry_after = int(oldest + self._window - now) + 1
            return False, 0, retry_after

        # Allow and record
        self._requests[key].append(now)
        remaining = self._max_requests - current_count - 1
        return True, remaining, 0

    def cleanup(self) -> None:
        """Remove expired entries to prevent memory growth."""
        now = time.time()
        window_start = now - self._window
        expired_keys = []
        for key, timestamps in self._requests.items():
            self._requests[key] = [t for t in timestamps if t > window_start]
            if not self._requests[key]:
                expired_keys.append(key)
        for key in expired_keys:
            del self._requests[key]


class RateLimitMiddleware(BaseHTTPMiddleware):
    """FastAPI middleware for rate limiting."""

    def __init__(self, app: FastAPI, limiter: RateLimiter) -> None:
        super().__init__(app)
        self._limiter = limiter

    async def dispatch(self, request: Request, call_next):
        # Skip rate limiting for static files
        if request.url.path.startswith("/static") or request.url.path == "/":
            return await call_next(request)

        # Rate limit by API key name or IP
        key = getattr(request.state, "api_key_name", None)
        if not key:
            key = request.client.host if request.client else "unknown"

        allowed, remaining, retry_after = self._limiter.is_allowed(key)

        if not allowed:
            logger.warning("Rate limit exceeded for %s", key)
            return JSONResponse(
                status_code=429,
                content={"detail": "Rate limit exceeded. Try again later."},
                headers={
                    "Retry-After": str(retry_after),
                    "X-RateLimit-Limit": str(self._limiter._max_requests),
                    "X-RateLimit-Remaining": "0",
                },
            )

        response = await call_next(request)
        response.headers["X-RateLimit-Limit"] = str(self._limiter._max_requests)
        response.headers["X-RateLimit-Remaining"] = str(remaining)
        return response


# ── Security Headers ──────────────────────────────────────────

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Add security headers to all responses."""

    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)

        # Prevent clickjacking
        response.headers["X-Frame-Options"] = "DENY"

        # Prevent MIME type sniffing
        response.headers["X-Content-Type-Options"] = "nosniff"

        # XSS protection
        response.headers["X-XSS-Protection"] = "1; mode=block"

        # Referrer policy
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"

        # Permissions policy
        response.headers["Permissions-Policy"] = (
            "camera=(), microphone=(), geolocation=(), payment=()"
        )

        # Content Security Policy (allows dashboard + fonts)
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
            "font-src 'self' https://fonts.gstatic.com; "
            "script-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; "
            "connect-src 'self';"
        )

        # Cache control for API responses
        if not request.url.path.startswith("/static"):
            response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate"
            response.headers["Pragma"] = "no-cache"

        return response


# ── Global Error Handler ──────────────────────────────────────

def register_error_handlers(app: FastAPI) -> None:
    """Install global error handlers that never leak internal details."""

    @app.exception_handler(HTTPException)
    async def http_exception_handler(request: Request, exc: HTTPException):
        return JSONResponse(
            status_code=exc.status_code,
            content={
                "error": True,
                "detail": exc.detail,
                "status_code": exc.status_code,
            },
        )

    @app.exception_handler(Exception)
    async def unhandled_exception_handler(request: Request, exc: Exception):
        # Log the full traceback internally
        logger.error(
            "Unhandled exception: %s\n%s",
            str(exc),
            traceback.format_exc(),
        )
        # Return a safe response — never expose internals
        return JSONResponse(
            status_code=500,
            content={
                "error": True,
                "detail": "Internal server error. This incident has been logged.",
                "status_code": 500,
            },
        )


# ── Input Validation ──────────────────────────────────────────

MAX_REQUEST_BODY_SIZE = 1 * 1024 * 1024  # 1 MB
MAX_PROMPT_LENGTH = 10_000
MAX_PARAM_DEPTH = 5
MAX_AGENT_ID_LENGTH = 100
MAX_TOOL_NAME_LENGTH = 100


class InputValidationMiddleware(BaseHTTPMiddleware):
    """Validate and sanitize incoming request payloads."""

    async def dispatch(self, request: Request, call_next):
        # Only validate POST requests with JSON bodies
        if request.method == "POST" and request.url.path == "/execute_tool":
            # Check content length
            content_length = request.headers.get("content-length")
            if content_length and int(content_length) > MAX_REQUEST_BODY_SIZE:
                return JSONResponse(
                    status_code=413,
                    content={"detail": "Request body too large (max 1 MB)"},
                )

            try:
                body = await request.body()
                if len(body) > MAX_REQUEST_BODY_SIZE:
                    return JSONResponse(
                        status_code=413,
                        content={"detail": "Request body too large (max 1 MB)"},
                    )

                data = json.loads(body)

                # Validate field sizes
                errors = []
                if len(data.get("agent_id", "")) > MAX_AGENT_ID_LENGTH:
                    errors.append(f"agent_id exceeds max length ({MAX_AGENT_ID_LENGTH})")
                if len(data.get("tool", "")) > MAX_TOOL_NAME_LENGTH:
                    errors.append(f"tool name exceeds max length ({MAX_TOOL_NAME_LENGTH})")
                if len(data.get("original_prompt", "")) > MAX_PROMPT_LENGTH:
                    errors.append(f"original_prompt exceeds max length ({MAX_PROMPT_LENGTH})")

                # Check parameter nesting depth
                if not _check_depth(data.get("parameters", {}), MAX_PARAM_DEPTH):
                    errors.append(f"parameters nesting exceeds max depth ({MAX_PARAM_DEPTH})")

                if errors:
                    return JSONResponse(
                        status_code=400,
                        content={"detail": "Input validation failed", "errors": errors},
                    )

            except json.JSONDecodeError:
                return JSONResponse(
                    status_code=400,
                    content={"detail": "Invalid JSON in request body"},
                )
            except Exception:
                pass  # Let FastAPI handle other parsing issues

        return await call_next(request)


def _check_depth(obj: Any, max_depth: int, current: int = 0) -> bool:
    """Check that a nested object doesn't exceed max depth."""
    if current > max_depth:
        return False
    if isinstance(obj, dict):
        return all(_check_depth(v, max_depth, current + 1) for v in obj.values())
    if isinstance(obj, list):
        return all(_check_depth(v, max_depth, current + 1) for v in obj)
    return True


# ── Middleware Registration ───────────────────────────────────

def install_security_middleware(app: FastAPI) -> dict[str, Any]:
    """
    Install all security middleware on the FastAPI app.
    Returns references to middleware components for runtime access.

    Order matters — middleware is executed in REVERSE order of addition:
    Last added = first executed.
    So we add: error handlers, then security headers, then rate limit,
    then auth, then input validation.
    Input validation runs first (outermost), auth second, etc.
    """
    # Create components
    auth = APIKeyAuth()
    limiter = RateLimiter(max_requests=60, window_seconds=60)

    # Register error handlers
    register_error_handlers(app)

    # Add middleware (reverse order of execution)
    app.add_middleware(SecurityHeadersMiddleware)
    app.add_middleware(RateLimitMiddleware, limiter=limiter)
    app.add_middleware(AuthMiddleware, auth=auth)
    app.add_middleware(InputValidationMiddleware)

    return {
        "auth": auth,
        "rate_limiter": limiter,
    }
