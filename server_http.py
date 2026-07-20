#!/usr/bin/env python3
"""
Defender Hunt MCP — Streamable HTTP Transport.

Uses FastMCP's built-in streamable HTTP support mounted in a Starlette app
with API-key authentication, CORS, and health-check endpoints.
Compatible with Microsoft Copilot Studio and GitHub Copilot.
"""

import logging
import os
import secrets
from contextlib import asynccontextmanager

import uvicorn
from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.middleware.cors import CORSMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Mount, Route
from starlette.types import ASGIApp, Receive, Scope, Send

from config import Config

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
API_KEY = os.getenv("MCP_API_KEY")
PUBLIC_ENDPOINTS = {"/health", "/info"}
ALLOWED_ORIGINS = [
    origin.strip() for origin in os.getenv("ALLOWED_ORIGINS", "").split(",") if origin.strip()
]


class APIKeyAuthMiddleware:
    """Check X-API-Key or Authorization: Bearer <key>."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or scope["path"] in PUBLIC_ENDPOINTS or not API_KEY:
            await self.app(scope, receive, send)
            return

        request = Request(scope)
        api_key = request.headers.get("X-API-Key")
        if not api_key:
            auth = request.headers.get("Authorization", "")
            if auth.startswith("Bearer "):
                api_key = auth[7:]

        if not api_key or not secrets.compare_digest(api_key, API_KEY):
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
            return
        await self.app(scope, receive, send)


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
            "version": "2.0.0",
            "auth_enabled": bool(API_KEY),
            "missing_configuration": missing_vars,
        },
        status_code=200 if not missing_vars else 503,
    )


async def server_info(_request: Request) -> JSONResponse:
    return JSONResponse(
        {
            "name": "defender_hunt_mcp",
            "version": "2.0.0",
            "protocol": "mcp",
            "transport": "streamable-http",
            "capabilities": {"tools": True, "resources": True, "prompts": False},
        }
    )


# ---------------------------------------------------------------------------
# Build ASGI app
# ---------------------------------------------------------------------------
def create_app() -> Starlette:
    """Create the Starlette application with the FastMCP streamable-HTTP mount."""
    # Import here so module-level side-effects don't run on import
    from server import mcp as defender_mcp

    mcp_app = defender_mcp.streamable_http_app()

    @asynccontextmanager
    async def lifespan(_app: Starlette):
        logger.info("Defender Hunt MCP (Streamable HTTP) starting…")
        if API_KEY:
            logger.info("API-key authentication is ENABLED")
        else:
            logger.warning("API-key authentication is DISABLED — server is publicly accessible!")
        if not Config.validate():
            logger.warning("Missing env vars: %s", ", ".join(Config.get_missing_vars()))
        # Initialize the MCP sub-app's session manager (task group)
        async with mcp_app.router.lifespan_context(mcp_app):
            yield
        logger.info("Defender Hunt MCP (Streamable HTTP) shutting down…")

    routes = [
        Route("/health", health_check, methods=["GET"]),
        Route("/info", server_info, methods=["GET"]),
        # Mount FastMCP at root — it registers its own /mcp endpoint internally
        Mount("/", app=mcp_app),
    ]

    middleware = [Middleware(APIKeyAuthMiddleware)]
    if ALLOWED_ORIGINS:
        middleware.insert(
            0,
            Middleware(
                CORSMiddleware,
                allow_origins=ALLOWED_ORIGINS,
                allow_credentials=False,
                allow_methods=["GET", "POST", "DELETE", "OPTIONS"],
                allow_headers=["Authorization", "Content-Type", "Mcp-Session-Id", "X-API-Key"],
                expose_headers=["Mcp-Session-Id"],
            ),
        )

    return Starlette(
        debug=os.getenv("DEBUG", "false").lower() == "true",
        routes=routes,
        middleware=middleware,
        lifespan=lifespan,
    )


http_app = create_app()


def main() -> None:
    host = os.getenv("HOST", "0.0.0.0")
    port = int(os.getenv("PORT", "8000"))
    logger.info("Starting Defender Hunt MCP on %s:%d", host, port)
    uvicorn.run(http_app, host=host, port=port, log_level="info", access_log=True)


if __name__ == "__main__":
    main()
