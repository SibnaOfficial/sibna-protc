"""
Sibna Protocol v3.0.1 — Safety Numbers.

Matches the Rust core (`core/src/safety.rs`) exactly:

    fingerprint = SHA-512(0x01 || "SIBNA_SAFETY_NUMBER_V1" || sorted(our, their))[:32]
    digits      = 80 decimal digits (16 groups of 5, space every 3 groups)

Keys are sorted lexicographically so both peers compute the same fingerprint.
"""

from __future__ import annotations

from dataclasses import dataclass

from .crypto import sha512
from .errors import ValidationError

SAFETY_NUMBER_DOMAIN = b"SIBNA_SAFETY_NUMBER_V1"
SAFETY_NUMBER_DOMAIN_EXTRA = b"SIBNA_SAFETY_NUMBER_V1_EXTRA"
SAFETY_NUMBER_VERSION = 1
SAFETY_NUMBER_DIGIT_COUNT = 80


@dataclass(frozen=True)
class SafetyNumber:
    """An 80-digit safety number for identity verification."""

    digits: str  # 80 digits with spaces every 3 groups (Rust-compatible)
    fingerprint: bytes  # 32-byte raw fingerprint
    version: int = 1

    VERSION = 1

    @classmethod
    def _sort(cls, our_identity: bytes, their_identity: bytes):
        if our_identity < their_identity:
            return our_identity, their_identity
        return their_identity, our_identity

    @classmethod
    def calculate(cls, our_identity: bytes, their_identity: bytes) -> "SafetyNumber":
        if len(our_identity) != 32 or len(their_identity) != 32:
            raise ValidationError("Identity keys must be 32 bytes")
        first, second = cls._sort(our_identity, their_identity)
        hasher = sha512(bytes([cls.VERSION]) + SAFETY_NUMBER_DOMAIN + first + second)
        fingerprint = hasher[:32]
        digits = cls._bytes_to_digits(fingerprint)
        return cls(digits=digits, fingerprint=fingerprint)

    @classmethod
    def calculate_with_extra(
        cls, our_identity: bytes, their_identity: bytes, extra_data: bytes
    ) -> "SafetyNumber":
        first, second = cls._sort(our_identity, their_identity)
        hasher = sha512(
            bytes([cls.VERSION]) + SAFETY_NUMBER_DOMAIN_EXTRA + first + second + extra_data
        )
        fingerprint = hasher[:32]
        digits = cls._bytes_to_digits(fingerprint)
        return cls(digits=digits, fingerprint=fingerprint)

    @classmethod
    def from_string(cls, s: str) -> "SafetyNumber":
        digits = "".join(c for c in s if c.isdigit())
        if len(digits) != SAFETY_NUMBER_DIGIT_COUNT:
            raise ValidationError(f"Expected 80 digits, got {len(digits)}")
        fingerprint = cls._digits_to_bytes(digits)
        # Re-canonicalize the digit string with spaces.
        canonical = cls._bytes_to_digits(fingerprint)
        return cls(digits=canonical, fingerprint=fingerprint)

    # Alias matching the Rust core API.
    parse = from_string

    def as_string(self) -> str:
        return self.digits

    def formatted(self, group_size: int = 5, groups_per_line: int = 8) -> str:
        groups = [self.digits[i : i + group_size] for i in range(0, len(self.digits), group_size)]
        # Strip spaces from digits before re-grouping for display.
        flat = "".join(groups)
        groups = [flat[i : i + group_size] for i in range(0, len(flat), group_size)]
        lines = []
        for i in range(0, len(groups), groups_per_line):
            lines.append(" ".join(groups[i : i + groups_per_line]))
        return "\n".join(lines)

    def qr_data(self) -> bytes:
        """QR code data: version(1) + "SB1"(3) + fingerprint(32) = 36 bytes."""
        return bytes([self.version]) + b"SB1" + self.fingerprint

    def verify(self, other: "SafetyNumber") -> bool:
        """Constant-time-ish fingerprint comparison."""
        from .crypto import hmac_sha256

        k = b"\x00" * 32
        a = hmac_sha256(k, self.fingerprint)
        b = hmac_sha256(k, other.fingerprint)
        return a == b

    def __str__(self) -> str:
        return self.formatted()

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, SafetyNumber):
            return NotImplemented
        return self.fingerprint == other.fingerprint

    def __hash__(self) -> int:
        return hash(self.fingerprint)

    # ── Internal helpers (match Rust bytes_to_digits) ─────────────────

    @staticmethod
    def _bytes_to_digits(data: bytes) -> str:
        """Convert 32 bytes to digits with a space every 3 groups (Rust)."""
        parts = []
        for i in range(0, 32, 2):
            group_index = i // 2
            if group_index > 0 and group_index % 3 == 0:
                parts.append(" ")
            value = (data[i] << 8) | data[i + 1]
            parts.append(f"{value % 100000:05d}")
        return "".join(parts)

    @staticmethod
    def _digits_to_bytes(digits: str) -> bytes:
        """Convert 80 digits back to 32 bytes."""
        result = bytearray()
        for i in range(0, 80, 5):
            chunk = digits[i : i + 5]
            value = int(chunk)
            result.append((value >> 8) & 0xFF)
            result.append(value & 0xFF)
        return bytes(result)


__all__ = [
    "SafetyNumber",
    "SAFETY_NUMBER_VERSION",
    "SAFETY_NUMBER_DIGIT_COUNT",
]
