#!/usr/bin/env python3
"""
Defender Hunt MCP — Streamable HTTP Transport.

Uses FastMCP's built-in streamable HTTP support mounted in a Starlette app
with Microsoft Entra authentication, CORS, and health-check endpoints.
Compatible with Microsoft Copilot Studio and GitHub Copilot.
"""

import logging
import os
from contextlib import asynccontextmanager

import uvicorn
from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.middleware.cors import CORSMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Mount, Route
from starlette.types import ASGIApp, Receive, Scope, Send

from auth_context import reset_request_identity, set_request_identity
from cache_runtime import close_cache_service
from config import Config
from entra_auth import AuthenticationError, EntraAuthSettings, EntraTokenValidator
from graph_clients import close_request_credentials

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=getattr(logging, os.getenv("LOG_LEVEL", "INFO").upper(), logging.INFO),
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Authentication
# ---------------------------------------------------------------------------
PUBLIC_ENDPOINTS = {"/health", "/info"}
ALLOWED_ORIGINS = [
    origin.strip() for origin in os.getenv("ALLOWED_ORIGINS", "").split(",") if origin.strip()
]


class EntraAuthMiddleware:
    """Validate Entra access tokens and propagate caller identity."""

    def __init__(self, app: ASGIApp, validator: EntraTokenValidator | None) -> None:
        self.app = app
        self.validator = validator

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or scope["path"] in PUBLIC_ENDPOINTS:
            await self.app(scope, receive, send)
            return

        request = Request(scope)
        authorization = request.headers.get("Authorization", "")
        if self.validator is None:
            await JSONResponse(
                {"error": "Authentication is not configured"},
                status_code=503,
            )(scope, receive, send)
            return
        if not authorization.startswith("Bearer "):
            await self._unauthorized(scope, receive, send, request)
            return

        try:
            identity = await self.validator.validate(authorization[7:])
        except AuthenticationError:
            await self._unauthorized(scope, receive, send, request)
            return

        identity_token = set_request_identity(identity)
        try:
            await self.app(scope, receive, send)
        finally:
            await close_request_credentials()
            reset_request_identity(identity_token)

    async def _unauthorized(
        self,
        scope: Scope,
        receive: Receive,
        send: Send,
        request: Request,
    ) -> None:
        logger.warning(
            "Unauthorized request to %s from %s",
            scope["path"],
            request.client.host if request.client else "?",
        )
        response = JSONResponse(
            {
                "jsonrpc": "2.0",
                "error": {"code": -32001, "message": "Unauthorized"},
                "id": None,
            },
            status_code=401,
            headers={"WWW-Authenticate": "Bearer"},
        )
        await response(scope, receive, send)


# ---------------------------------------------------------------------------
# Utility endpoints
# ---------------------------------------------------------------------------
async def health_check(_request: Request) -> JSONResponse:
    missing_vars = Config.get_missing_vars()
    return JSONResponse(
        {
            "status": "healthy" if not missing_vars else "unhealthy",
            "service": "defender-hunt-mcp",
            "transport": "streamable-http",
            "version": "3.0.0",
            "auth_mode": "entra",
            "missing_configuration": missing_vars,
        },
        status_code=200 if not missing_vars else 503,
    )


async def server_info(_request: Request) -> JSONResponse:
    return JSONResponse(
        {
            "name": "defender_hunt_mcp",
            "version": "3.0.0",
            "protocol": "mcp",
            "transport": "streamable-http",
            "capabilities": {"tools": True, "resources": True, "prompts": False},
        }
    )


# ---------------------------------------------------------------------------
# Build ASGI app
# ---------------------------------------------------------------------------
def create_app(token_validator: EntraTokenValidator | None = None) -> Starlette:
    """Create the Starlette application with the FastMCP streamable-HTTP mount."""
    # Import here so module-level side-effects don't run on import
    from server import mcp as defender_mcp

    mcp_app = defender_mcp.streamable_http_app()

    @asynccontextmanager
    async def lifespan(_app: Starlette):
        logger.info("Defender Hunt MCP (Streamable HTTP) starting…")
        logger.info("Microsoft Entra authentication is ENABLED")
        if not Config.validate():
            logger.warning("Missing env vars: %s", ", ".join(Config.get_missing_vars()))
        # Initialize the MCP sub-app's session manager (task group)
        async with mcp_app.router.lifespan_context(mcp_app):
            yield
        await close_cache_service()
        logger.info("Defender Hunt MCP (Streamable HTTP) shutting down…")

    routes = [
        Route("/health", health_check, methods=["GET"]),
        Route("/info", server_info, methods=["GET"]),
        # Mount FastMCP at root — it registers its own /mcp endpoint internally
        Mount("/", app=mcp_app),
    ]

    middleware = [Middleware(EntraAuthMiddleware, validator=token_validator)]
    if ALLOWED_ORIGINS:
        middleware.insert(
            0,
            Middleware(
                CORSMiddleware,
                allow_origins=ALLOWED_ORIGINS,
                allow_credentials=False,
                allow_methods=["GET", "POST", "DELETE", "OPTIONS"],
                allow_headers=["Authorization", "Content-Type", "Mcp-Session-Id"],
                expose_headers=["Mcp-Session-Id"],
            ),
        )

    return Starlette(
        debug=os.getenv("DEBUG", "false").lower() == "true",
        routes=routes,
        middleware=middleware,
        lifespan=lifespan,
    )


try:
    _token_validator = EntraTokenValidator(EntraAuthSettings.from_environment())
except ValueError:
    _token_validator = None

http_app = create_app(_token_validator)


def main() -> None:
    host = os.getenv("HOST", "0.0.0.0")
    port = int(os.getenv("PORT", "8000"))
    logger.info("Starting Defender Hunt MCP on %s:%d", host, port)
    uvicorn.run(http_app, host=host, port=port, log_level="info", access_log=True)


if __name__ == "__main__":
    main()
