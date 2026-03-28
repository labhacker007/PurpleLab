"""Custom exception hierarchy for Joti Sim.

All application-specific exceptions inherit from JotiSimError so that
a single exception handler in FastAPI can catch and format them consistently.
"""
from __future__ import annotations


class JotiSimError(Exception):
    """Base exception for all Joti Sim errors."""

    def __init__(self, message: str = "An error occurred", status_code: int = 500):
        self.message = message
        self.status_code = status_code
        super().__init__(self.message)


class NotFoundError(JotiSimError):
    """Resource not found."""

    def __init__(self, resource: str = "Resource", identifier: str = ""):
        detail = f"{resource} not found"
        if identifier:
            detail = f"{resource} '{identifier}' not found"
        super().__init__(message=detail, status_code=404)


class ValidationError(JotiSimError):
    """Input validation failed."""

    def __init__(self, message: str = "Validation error"):
        super().__init__(message=message, status_code=422)


class SIEMConnectionError(JotiSimError):
    """Failed to connect to a SIEM platform."""

    def __init__(self, siem_type: str = "", message: str = ""):
        detail = f"SIEM connection failed"
        if siem_type:
            detail = f"{siem_type} connection failed"
        if message:
            detail = f"{detail}: {message}"
        super().__init__(message=detail, status_code=502)


class AgentError(JotiSimError):
    """Error in the AI agent orchestration layer."""

    def __init__(self, message: str = "Agent error"):
        super().__init__(message=message, status_code=500)


class RateLimitError(JotiSimError):
    """Rate limit exceeded."""

    def __init__(self, message: str = "Rate limit exceeded"):
        super().__init__(message=message, status_code=429)


class EncryptionError(JotiSimError):
    """Encryption or decryption failure."""

    def __init__(self, message: str = "Encryption error"):
        super().__init__(message=message, status_code=500)
