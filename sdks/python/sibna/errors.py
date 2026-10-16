"""Typed exceptions for the Sibna Python SDK.

All public API failures raise one of these exception types. Error messages
intentionally avoid exposing private key material, session state internals, or
cryptographic details that could aid an attacker.
"""

from __future__ import annotations


class SibnaError(Exception):
    """Base exception for all Sibna SDK errors.

    Attributes:
        message: Human-readable description (safe to display/log).
        status_code: Optional HTTP or protocol status code.
    """

    def __init__(self, message: str, status_code: int = 0):
        self.message = message
        self.status_code = status_code
        super().__init__(message)

    def __str__(self) -> str:  # pragma: no cover - trivial
        return self.message


class AuthError(SibnaError):
    """Authentication or authorization failure (e.g. invalid signature, 401)."""


class NetworkError(SibnaError):
    """Network or transport failure (e.g. unreachable server, timeout)."""


class CryptoError(SibnaError):
    """Cryptographic operation failure (e.g. decryption/authentication failure)."""


class ValidationError(SibnaError):
    """Input validation failure (e.g. bad key length, invalid encoding)."""


class ProtocolError(SibnaError):
    """Protocol-level violation (e.g. version mismatch, replay detected)."""


class StorageError(SibnaError):
    """Encrypted storage / keystore failure."""


class KeyNotFoundError(SibnaError):
    """Requested key material is not available."""


class SessionNotFoundError(SibnaError):
    """Requested session does not exist."""


__all__ = [
    "SibnaError",
    "AuthError",
    "NetworkError",
    "CryptoError",
    "ValidationError",
    "ProtocolError",
    "StorageError",
    "KeyNotFoundError",
    "SessionNotFoundError",
]
