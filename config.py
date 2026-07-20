#!/usr/bin/env python3
"""
Configuration module for Defender Hunt MCP.
Loads environment variables and provides validation.
"""

import os

from dotenv import load_dotenv

# Load .env file if present
load_dotenv()

# Azure AD / Entra ID credentials
TENANT_ID = os.getenv("AZURE_TENANT_ID")
CLIENT_ID = os.getenv("AZURE_CLIENT_ID")
CLIENT_SECRET = os.getenv("AZURE_CLIENT_SECRET")

# Microsoft Graph scopes
SCOPES = ["https://graph.microsoft.com/.default"]


class Config:
    """Application configuration with validation."""

    LOG_LEVEL: str = os.getenv("LOG_LEVEL", "INFO")

    # Pagination defaults
    DEFAULT_SIGNIN_LOGS: int = 100
    MAX_SIGNIN_LOGS: int = 500
    DEFAULT_AUDIT_LOGS: int = 100
    MAX_AUDIT_LOGS: int = 500
    DEFAULT_RISKY_USERS: int = 50
    MAX_RISKY_USERS: int = 200

    @classmethod
    def validate(cls) -> bool:
        """Check if all required environment variables are set."""
        return all([TENANT_ID, CLIENT_ID, CLIENT_SECRET])

    @classmethod
    def get_missing_vars(cls) -> list[str]:
        """Return list of missing required environment variables."""
        missing: list[str] = []
        if not TENANT_ID:
            missing.append("AZURE_TENANT_ID")
        if not CLIENT_ID:
            missing.append("AZURE_CLIENT_ID")
        if not CLIENT_SECRET:
            missing.append("AZURE_CLIENT_SECRET")
        return missing
