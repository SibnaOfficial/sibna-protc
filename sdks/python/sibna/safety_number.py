"""
Sibna Protocol v3.0.1 — Safety Numbers

80-digit human-readable fingerprints for identity verification.
Matches the Rust core's SafetyNumber implementation exactly:
  - SHA-512(0x01 || "SIBNA_SAFETY_NUMBER_V1" || first_key || second_key)
  - First 32 bytes of hash → 80 decimal digits (16 groups of 5)
  - QR format: version(1) + "SB1"(3) + fingerprint(32) = 36 bytes
"""

from __future__ import annotations

from dataclasses import dataclass

from .crypto import sha512


@dataclass(frozen=True)
class SafetyNumber:
    """
    An 80-digit safety number for identity verification.

    Generated from two X25519 public keys sorted lexicographically.
    """

    digits: str  # 80-digit string (16 groups of 5 digits)
    fingerprint: bytes  # Raw 32-byte fingerprint
    version: int = 1

    VERSION = 1

    @classmethod
    def calculate(cls, our_identity: bytes, their_identity: bytes) -> "SafetyNumber":
        """
        Calculate safety number from two X25519 public keys.
        Keys are sorted lexicographically for consistent ordering.
        """
        first, second = (
            (our_identity, their_identity)
            if our_identity < their_identity
            else (their_identity, our_identity)
        )

        hasher = sha512(
            bytes([cls.VERSION])
            + b"SIBNA_SAFETY_NUMBER_V1"
            + first
            + second
        )
        fingerprint = hasher[:32]
        digits = cls._bytes_to_digits(fingerprint)

        return cls(digits=digits, fingerprint=fingerprint)

    @classmethod
    def calculate_with_extra(
        cls, our_identity: bytes, their_identity: bytes, extra_data: bytes
    ) -> "SafetyNumber":
        """Calculate safety number with additional data (e.g. for group verification)."""
        first, second = (
            (our_identity, their_identity)
            if our_identity < their_identity
            else (their_identity, our_identity)
        )

        hasher = sha512(
            bytes([cls.VERSION])
            + b"SIBNA_SAFETY_NUMBER_V1_EXTRA"
            + first
            + second
            + extra_data
        )
        fingerprint = hasher[:32]
        digits = cls._bytes_to_digits(fingerprint)

        return cls(digits=digits, fingerprint=fingerprint)

    @classmethod
    def from_string(cls, s: str) -> "SafetyNumber":
        """Parse a safety number from its string representation."""
        digits = "".join(c for c in s if c.isdigit())
        if len(digits) != 80:
            raise ValueError(f"Expected 80 digits, got {len(digits)}")
        fingerprint = cls._digits_to_bytes(digits)
        return cls(digits=digits, fingerprint=fingerprint)

    def as_string(self) -> str:
        """Return the 80-digit formatted string."""
        return self.digits

    def formatted(self, group_size: int = 5, groups_per_line: int = 8) -> str:
        """Return the safety number formatted for display."""
        groups = [
            self.digits[i : i + group_size]
            for i in range(0, len(self.digits), group_size)
        ]
        lines = []
        for i in range(0, len(groups), groups_per_line):
            lines.append(" ".join(groups[i : i + groups_per_line]))
        return "\n".join(lines)

    def qr_data(self) -> bytes:
        """
        QR code data: version(1) + "SB1"(3) + fingerprint(32) = 36 bytes.
        Matches Rust SafetyNumber::qr_data().
        """
        return bytes([self.version]) + b"SB1" + self.fingerprint

    def verify(self, other: "SafetyNumber") -> bool:
        """Constant-time comparison with another safety number."""
        from .crypto import hmac_sha256
        # Use HMAC-based comparison for constant time
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

    # ── Internal helpers ────────────────────────────────────────────────

    @staticmethod
    def _bytes_to_digits(data: bytes) -> str:
        """Convert 32 bytes to 80 decimal digits (16 chunks × 5 digits)."""
        parts = []
        for i in range(0, 32, 2):
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
