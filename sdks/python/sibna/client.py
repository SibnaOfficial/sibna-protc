"""
Sibna Protocol v3.0.1 — Relay transport client.

Unified synchronous HTTP + asynchronous WebSocket client for the Sibna relay
server (`server/`). Matches the retained server API exactly:

  POST /v1/auth/challenge   {identity_key_hex}          -> {challenge_hex, expires_in}
  POST /v1/auth/prove       {identity_key_hex, challenge_hex, signature_hex} -> {token, expires_in}
  POST /v1/prekeys/upload   {bundle_hex, is_last_resort} -> 200
  GET  /v1/prekeys/{root_id}                       -> {bundles_hex: [...]}
  POST /v1/messages/send   {recipient_id, payload_hex, compressed} -> 200/202
  GET  /v1/messages/inbox?identity_key_hex=&token=  -> {messages: [...], count}
  WS   /ws?token=<jwt>                             -> binary WsMessage frames

Authentication is Ed25519 challenge-response → HS256 JWT. The JWT is sent
via the WebSocket ``?token=`` query parameter (matching `server/src/ws.rs`),
NOT via the Authorization header, to remain interoperable with the retained
relay server.

TLS certificate pinning is supported via ``pinned_cert`` and is never
silently disabled.
"""

from __future__ import annotations

import hashlib
import json
import os
import struct
import time
import uuid
from typing import Any, Callable, cast, Dict, List, Optional

import aiohttp
import requests
import ssl

from . import constants as C
from .crypto import Ed25519KeyPair
from .envelope import make_signed_envelope, verify_signed_envelope
from .errors import AuthError, CryptoError, NetworkError, SibnaError


class Identity:
    """Ed25519 identity keypair used for authentication and message signing."""

    def __init__(self, private_key_bytes: Optional[bytes] = None):
        if private_key_bytes is None:
            self._private = Ed25519KeyPair()
        else:
            self._private = Ed25519KeyPair.from_seed(private_key_bytes)

    @property
    def public_key_bytes(self) -> bytes:
        return self._private.public_key

    @property
    def public_key(self) -> bytes:
        return self.public_key_bytes

    @property
    def public_key_hex(self) -> str:
        return self.public_key_bytes.hex()

    @property
    def private_key_bytes(self) -> bytes:
        return self._private.private_key

    def sign(self, data: bytes) -> bytes:
        return self._private.sign(data)

    def sign_hex(self, data: bytes) -> str:
        return self.sign(data).hex()

    def save(self, path: str) -> None:
        directory = os.path.dirname(os.path.abspath(path))
        if directory:
            os.makedirs(directory, exist_ok=True)
        with open(path, "wb") as f:
            f.write(self.private_key_bytes)
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass  # Filesystem may not support chmod (e.g. some Windows setups)

    @classmethod
    def load(cls, path: str) -> "Identity":
        with open(path, "rb") as f:
            return cls(private_key_bytes=f.read())

    def __repr__(self) -> str:
        return f"<Identity public_key={self.public_key_hex[:16]}...>"


# ── HTTP (sync) client ────────────────────────────────────────────────


class SibnaClient:
    """Synchronous Sibna relay client (HTTP REST)."""

    def __init__(
        self,
        server: str = "http://localhost:8080",
        pinned_cert: Optional[str] = None,
        timeout: float = 30.0,
    ):
        self.server = server.rstrip("/")
        self.identity: Optional[Identity] = None
        self.jwt_token: Optional[str] = None
        self.timeout = timeout
        self._session = requests.Session()

        if pinned_cert is not None:
            if not os.path.isfile(pinned_cert):
                raise ValueError(f"pinned_cert path does not exist: {pinned_cert!r}")
            self._session.verify = pinned_cert
        elif server.startswith("https://"):
            import warnings

            warnings.warn(
                "SibnaClient: HTTPS server configured without certificate pinning. "
                "Pass pinned_cert='/path/to/server.pem' to enable pinning.",
                stacklevel=2,
            )

    # ── Identity ────────────────────────────────────────────────────

    def generate_identity(self, private_key_bytes: Optional[bytes] = None) -> Identity:
        self.identity = Identity(private_key_bytes)
        return self.identity

    # ── Auth ────────────────────────────────────────────────────────

    def authenticate(self) -> str:
        """Ed25519 challenge-response → JWT (stored in self.jwt_token)."""
        if not self.identity:
            raise AuthError("No identity loaded. Call generate_identity() first.")

        r = self._session.post(
            f"{self.server}/v1/auth/challenge",
            json={"identity_key_hex": self.identity.public_key_hex},
            timeout=self.timeout,
        )
        self._check_response(r, "auth/challenge")
        challenge_hex = r.json()["challenge_hex"]

        challenge_bytes = bytes.fromhex(challenge_hex)
        signature_hex = self.identity.sign_hex(challenge_bytes)

        r = self._session.post(
            f"{self.server}/v1/auth/prove",
            json={
                "identity_key_hex": self.identity.public_key_hex,
                "challenge_hex": challenge_hex,
                "signature_hex": signature_hex,
            },
            timeout=self.timeout,
        )
        self._check_response(r, "auth/prove")
        self.jwt_token = r.json()["token"]
        return self.jwt_token

    def health(self) -> Dict[str, Any]:
        r = self._session.get(f"{self.server}/health", timeout=self.timeout)
        self._check_response(r, "health")
        return cast(Dict[str, Any], r.json())

    # ── PreKeys ─────────────────────────────────────────────────────

    def upload_prekey(self, bundle_hex: str, is_last_resort: bool = False) -> None:
        headers: Dict[str, str] = {}
        if self.jwt_token:
            headers["Authorization"] = f"Bearer {self.jwt_token}"
        r = self._session.post(
            f"{self.server}/v1/prekeys/upload",
            json={"bundle_hex": bundle_hex, "is_last_resort": is_last_resort},
            headers=headers,
            timeout=self.timeout,
        )
        self._check_response(r, "prekeys/upload")

    def fetch_prekeys(self, root_id_hex: str) -> List[str]:
        headers: Dict[str, str] = {}
        if self.jwt_token:
            headers["Authorization"] = f"Bearer {self.jwt_token}"
        r = self._session.get(
            f"{self.server}/v1/prekeys/{root_id_hex}", headers=headers, timeout=self.timeout
        )
        self._check_response(r, "prekeys/fetch")
        return cast(List[str], r.json()["bundles_hex"])

    # ── Messages ────────────────────────────────────────────────────

    def send_message(
        self,
        recipient_id: str,
        payload_hex: str,
        sign: bool = True,
        compress: bool = False,
    ) -> int:
        """Send a sealed envelope via REST (200 = live, 202 = queued offline)."""
        if sign and self.identity:
            body = make_signed_envelope(
                self.identity, recipient_id, payload_hex, compressed=compress
            )
        else:
            body = {
                "recipient_id": recipient_id,
                "payload_hex": payload_hex,
                "compressed": compress,
            }

        headers: Dict[str, str] = {}
        if self.jwt_token:
            headers["Authorization"] = f"Bearer {self.jwt_token}"

        r = self._session.post(
            f"{self.server}/v1/messages/send",
            json=body,
            headers=headers,
            timeout=self.timeout,
        )
        self._check_response(r, "messages/send")
        return r.status_code

    def fetch_inbox(self) -> List[Dict[str, Any]]:
        if not self.identity or not self.jwt_token:
            raise AuthError("Must authenticate before fetching inbox.")
        headers: Dict[str, str] = {}
        if self.jwt_token:
            headers["Authorization"] = f"Bearer {self.jwt_token}"
        r = self._session.get(
            f"{self.server}/v1/messages/inbox",
            headers=headers,
            params={"identity_key_hex": self.identity.public_key_hex},
            timeout=self.timeout,
        )
        self._check_response(r, "messages/inbox")
        messages = r.json().get("messages", [])
        verified = []
        for msg in messages:
            if verify_signed_envelope(msg):
                verified.append(msg)
        return verified

    # ── Internal ────────────────────────────────────────────────────

    def _check_response(self, r: requests.Response, endpoint: str) -> None:
        if r.status_code == 429:
            raise NetworkError(f"Rate limited on {endpoint}", 429)
        if r.status_code == 401:
            raise AuthError(f"Unauthorized on {endpoint}", 401)
        if r.status_code >= 400:
            raise NetworkError(
                f"{endpoint} failed: HTTP {r.status_code} — {r.text[:200]}",
                r.status_code,
            )

    def __repr__(self) -> str:
        identity_str = self.identity.public_key_hex[:16] if self.identity else "None"
        return f"<SibnaClient server={self.server} identity={identity_str}...>"


# ── Async WebSocket client ───────────────────────────────────────────


class AsyncSibnaClient:
    """Async Sibna relay client with WebSocket real-time relay."""

    def __init__(
        self,
        server: str = "http://localhost:8080",
        pinned_cert: Optional[str] = None,
    ):
        try:
            import aiohttp  # noqa: F401
        except ImportError as exc:  # pragma: no cover - environment-dependent
            raise NetworkError(
                "aiohttp required for AsyncSibnaClient: pip install aiohttp"
            ) from exc

        self.server = server.rstrip("/")
        self.ws_server = server.replace("http://", "ws://").replace("https://", "wss://")
        self.identity: Optional[Identity] = None
        self.jwt_token: Optional[str] = None
        self._ws: Optional[aiohttp.ClientWebSocketResponse] = None
        self._on_message: Optional[Callable[..., Any]] = None
        self._pinned_cert = pinned_cert

        if pinned_cert is not None and not os.path.isfile(pinned_cert):
            raise ValueError(f"pinned_cert path does not exist: {pinned_cert!r}")

    def _make_ssl_context(self) -> ssl.SSLContext:
        ctx = ssl.create_default_context()
        if self._pinned_cert:
            ctx.load_verify_locations(cafile=self._pinned_cert)
        return ctx

    def generate_identity(self, private_key_bytes: Optional[bytes] = None) -> Identity:
        self.identity = Identity(private_key_bytes)
        return self.identity

    async def authenticate(self) -> str:

        if not self.identity:
            raise AuthError("No identity loaded.")
        ssl_ctx = self._make_ssl_context() if self.server.startswith("https://") else None
        connector = aiohttp.TCPConnector(ssl=ssl_ctx) if ssl_ctx else None
        async with aiohttp.ClientSession(connector=connector) as session:
            async with session.post(
                f"{self.server}/v1/auth/challenge",
                json={"identity_key_hex": self.identity.public_key_hex},
            ) as r:
                if r.status != 200:
                    raise AuthError(f"Challenge failed: {r.status}")
                data = await r.json()
                challenge_hex = data["challenge_hex"]

            signature_hex = self.identity.sign_hex(bytes.fromhex(challenge_hex))
            async with session.post(
                f"{self.server}/v1/auth/prove",
                json={
                    "identity_key_hex": self.identity.public_key_hex,
                    "challenge_hex": challenge_hex,
                    "signature_hex": signature_hex,
                },
            ) as r:
                if r.status != 200:
                    raise AuthError(f"Prove failed: {r.status}")
                data = await r.json()
                self.jwt_token = data["token"]
                return self.jwt_token

    async def connect(self, on_message: Optional[Callable[..., Any]] = None) -> None:
        """Connect to the WebSocket relay.

        The JWT is sent via the ``?token=`` query parameter, matching the
        retained server (`server/src/ws.rs`).
        """
        import aiohttp

        if not self.jwt_token:
            raise AuthError("Must authenticate before connecting.")
        self._on_message = on_message

        ssl_ctx = self._make_ssl_context() if self.ws_server.startswith("wss://") else None
        connector = aiohttp.TCPConnector(ssl=ssl_ctx) if ssl_ctx else None

        ws_url = f"{self.ws_server}/ws?token={self.jwt_token}"
        async with aiohttp.ClientSession(connector=connector) as session:
            async with session.ws_connect(ws_url) as ws:
                self._ws = ws
                async for msg in ws:
                    if msg.type == aiohttp.WSMsgType.BINARY:
                        try:
                            ws_msg = json.loads(msg.data)
                            msg_type = ws_msg.get("type", "envelope")
                            if msg_type == "envelope":
                                envelope = ws_msg.get("envelope", ws_msg)
                                if verify_signed_envelope(envelope):
                                    msg_id = envelope.get("message_id")
                                    if msg_id:
                                        await ws.send_bytes(
                                            json.dumps(
                                                {"type": "ack", "message_id": msg_id}
                                            ).encode()
                                        )
                                    if self._on_message:
                                        await self._on_message(envelope)
                                else:
                                    # Invalid signature — drop.
                                    pass
                            elif msg_type == "ack":
                                # Delivery acknowledgement.
                                if self._on_message:
                                    await self._on_message(ws_msg)
                            elif msg_type == "webrtc":
                                if self._on_message:
                                    await self._on_message(ws_msg)
                        except Exception:
                            pass
                    elif msg.type == aiohttp.WSMsgType.ERROR:
                        raise NetworkError(f"WebSocket error: {ws.exception()}")

    async def send(
        self,
        recipient_id: str,
        payload_hex: str,
        sign: bool = True,
        compress: bool = False,
    ) -> None:
        if not self._ws:
            raise NetworkError("Not connected. Call connect() first.")
        if sign and self.identity:
            envelope = make_signed_envelope(
                self.identity, recipient_id, payload_hex, compressed=compress
            )
        else:
            envelope = {
                "recipient_id": recipient_id,
                "payload_hex": payload_hex,
                "compressed": compress,
                "message_id": str(uuid.uuid4()),
                "timestamp": int(time.time()),
            }
        ws_msg = {"type": "envelope", "envelope": envelope}
        await self._ws.send_bytes(json.dumps(ws_msg).encode())

    async def close(self) -> None:
        if self._ws is not None:
            await self._ws.close()
            self._ws = None


__all__ = [
    "Identity",
    "SibnaClient",
    "AsyncSibnaClient",
    "make_signed_envelope",
    "verify_signed_envelope",
]
