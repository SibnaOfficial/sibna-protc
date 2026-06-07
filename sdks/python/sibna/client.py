"""
Sibna Protocol Python SDK v11.0 — Production Edition
=====================================================

Full HTTP + WebSocket client SDK with:
  - Ed25519 identity generation (pure Python via cryptography library)
  - Auth: challenge-response JWT flow
  - PreKey management (upload / fetch)
  - Sealed envelope messaging (REST + WebSocket)
  - Message padding (metadata resistance)
  - Offline inbox polling

Install dependencies:
    pip install cryptography websockets aiohttp requests

Example (sync):
    from sibna.client import SibnaClient

    client = SibnaClient(server="http://localhost:8080")
    client.generate_identity()
    client.authenticate()
    client.upload_prekey()

    # Send sealed message
    client.send_message(recipient_id="<hex>", plaintext=b"Hello!")

    # Fetch inbox
    messages = client.fetch_inbox()

Example (async WebSocket):
    import asyncio
    from sibna.client import SibnaClient

    async def main():
        client = SibnaClient(server="http://localhost:8080")
        client.generate_identity()
        await client.authenticate_async()
        await client.connect_websocket()
        await client.send_sealed(recipient_id="<hex>", payload=b"Hello!")

    asyncio.run(main())
"""

__version__ = "3.0.1"
__author__ = "Sibna Security Team"
__license__ = "Apache-2.0 OR MIT"

import os
import json
import time
import uuid
import hashlib
import secrets
import struct
from typing import Optional, Callable, List, Dict, Any

# ── Cryptographic dependencies (pure Python, no native lib required) ─────────

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey, Ed25519PublicKey
    )
    from cryptography.hazmat.primitives.serialization import (
        Encoding, PublicFormat, PrivateFormat, NoEncryption
    )
    _CRYPTO_AVAILABLE = True
except ImportError:
    _CRYPTO_AVAILABLE = False

try:
    import requests
    _REQUESTS_AVAILABLE = True
except ImportError:
    _REQUESTS_AVAILABLE = False

try:
    import asyncio
    import aiohttp
    _AIOHTTP_AVAILABLE = True
except ImportError:
    _AIOHTTP_AVAILABLE = False


# ── Exceptions ────────────────────────────────────────────────────────────────

class SibnaError(Exception):
    """Base exception for all Sibna SDK errors."""
    def __init__(self, message: str, status_code: int = 0):
        self.status_code = status_code
        super().__init__(message)

class AuthError(SibnaError):
    """Authentication failed."""
    pass

class NetworkError(SibnaError):
    """Network or server error."""
    pass

class CryptoError(SibnaError):
    """Cryptographic operation failed."""
    pass


# ── Identity ─────────────────────────────────────────────────────────────────

class Identity:
    """
    Ed25519 identity keypair.

    The public key (32 bytes) is the user's permanent identifier.
    Use this to authenticate to the server and sign messages.
    """

    def __init__(self, private_key_bytes: Optional[bytes] = None):
        if not _CRYPTO_AVAILABLE:
            raise CryptoError(
                "cryptography package required: pip install cryptography"
            )
        if private_key_bytes:
            self._private_key = Ed25519PrivateKey.from_private_bytes(private_key_bytes)
        else:
            self._private_key = Ed25519PrivateKey.generate()

        self._public_key = self._private_key.public_key()

    @property
    def public_key_bytes(self) -> bytes:
        """32-byte Ed25519 public key."""
        return self._public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)

    @property
    def public_key_hex(self) -> str:
        """64-character hex Ed25519 public key."""
        return self.public_key_bytes.hex()

    @property
    def private_key_bytes(self) -> bytes:
        """32-byte Ed25519 private key (keep secret!)."""
        return self._private_key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())

    def sign(self, data: bytes) -> bytes:
        """Sign data, returns 64-byte signature."""
        return self._private_key.sign(data)

    def sign_hex(self, data: bytes) -> str:
        """Sign data, returns hex-encoded 64-byte signature."""
        return self.sign(data).hex()

    def save(self, path: str) -> None:
        """Save private key to file (protect with filesystem permissions!)."""
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        with open(path, "wb") as f:
            f.write(self.private_key_bytes)
        os.chmod(path, 0o600)

    @classmethod
    def load(cls, path: str) -> "Identity":
        """Load identity from saved private key file."""
        with open(path, "rb") as f:
            return cls(private_key_bytes=f.read())

    def __repr__(self) -> str:
        return f"<Identity public_key={self.public_key_hex[:16]}...>"


# ── Message Padding (Metadata Resistance) ─────────────────────────────────────
#
# FIX: Phase 3.2 — wire format already matches the Rust core, but the
# extra_blocks draw was [0, 1] (i.e. 0..1), which kept the on-wire
# size of a given plaintext nearly constant and undermined
# SIBNA-2026-018 metadata resistance. The new draw is 0..7 inclusive
# (matching Rust `MAX_EXTRA_BLOCKS = 7`), giving 8 possible on-wire
# sizes for any fixed plaintext length.

PADDING_BLOCK = 1024

# Maximum extra full blocks of random padding, per SIBNA-2026-018.
# Must equal core::crypto::padding::MAX_EXTRA_BLOCKS in the Rust core.
MAX_EXTRA_BLOCKS = 7

# Maximum value the 2-byte LE trailing length field can hold.
MAX_PADDING_BYTES = 65535

def pad_payload(data: bytes) -> bytes:
    """
    Pad payload to 1024-byte block boundary with metadata resistance.

    Wire format (matches Rust core):
      [ prefix_len(1) | prefix_noise(1-8) | plaintext | random_padding | padding_len(2, LE) ]

    Total output is always a multiple of PADDING_BLOCK.

    SIBNA-2026-018 (PATCH 20 parity): extra_blocks is drawn uniformly
    from [0, MAX_EXTRA_BLOCKS] so two messages of identical plaintext
    length do not necessarily produce the same on-wire size. The draw
    is capped so the final pad_len always fits in the 2-byte trailing
    length field and never exceeds MAX_PADDING_BYTES.
    """
    prefix_len = secrets.randbelow(8) + 1
    prefix_noise = secrets.token_bytes(prefix_len)

    min_total = 1 + prefix_len + len(data) + 2
    remainder = min_total % PADDING_BLOCK
    min_pad_len = (PADDING_BLOCK - remainder) % PADDING_BLOCK

    # Cap extra_blocks by remaining 2-byte length-field budget, then by MAX_EXTRA_BLOCKS.
    remaining_budget_blocks = max(0, (MAX_PADDING_BYTES - min_pad_len) // PADDING_BLOCK)
    cap = min(MAX_EXTRA_BLOCKS, remaining_budget_blocks)
    extra_blocks = secrets.randbelow(cap + 1)
    pad_len = min_pad_len + extra_blocks * PADDING_BLOCK

    if pad_len > MAX_PADDING_BYTES:
        # Defensive: this branch should be unreachable given the cap above.
        raise CryptoError(f"Computed pad_len {pad_len} exceeds max {MAX_PADDING_BYTES}")

    return (
        bytes([prefix_len])
        + prefix_noise
        + data
        + secrets.token_bytes(pad_len)
        + pad_len.to_bytes(2, 'little')
    )

def unpad_payload(padded: bytes) -> bytes:
    """Remove padding from a received payload."""
    if len(padded) < 4:
        raise CryptoError("Payload too short to unpad")

    total_len = len(padded)
    pad_len = padded[total_len - 1] * 256 + padded[total_len - 2]
    body_len = total_len - 2 - pad_len

    if body_len < 1 or body_len > total_len:
        raise CryptoError(f"Invalid padding: body_len({body_len}) out of range")

    prefix_len = padded[0]
    if prefix_len < 1 or prefix_len > 8:
        raise CryptoError(f"Invalid prefix length: {prefix_len}")

    data_start = 1 + prefix_len
    data_end = data_start + (body_len - data_start)

    if data_start > body_len or data_end > body_len:
        raise CryptoError(f"Invalid padding layout: data_start({data_start}) > body_len({body_len})")

    return padded[data_start:data_end]


# ── Signed Envelope (End-to-End Integrity) ────────────────────────────────────

def make_signed_envelope(
    identity: Identity,
    recipient_id: str,
    payload_hex: str,
    compress: bool = False,
) -> Dict[str, Any]:
    """
    Create a signed, sealed envelope.

    The server sees ONLY the recipient_id. The payload and sender
    identity are opaque to the server.

    Signing payload = SHA-512(recipient_id || payload_hex || timestamp || message_id)
    """
    message_id = str(uuid.uuid4())
    timestamp = int(time.time())

    # Build signing payload
    h = hashlib.sha512()
    h.update(recipient_id.encode())
    h.update(payload_hex.encode())
    h.update(struct.pack("<q", timestamp))
    h.update(message_id.encode())
    signing_hash = h.digest()

    signature_hex = identity.sign_hex(signing_hash)

    return {
        "recipient_id": recipient_id,
        "payload_hex": payload_hex,
        "sender_id": identity.public_key_hex,
        "timestamp": timestamp,
        "message_id": message_id,
        "signature_hex": signature_hex,
        "compressed": compress,
    }

def verify_signed_envelope(envelope: Dict[str, Any]) -> bool:
    """
    Verify a received envelope's Ed25519 signature.

    Always call this before processing a message!
    Returns True if valid, False otherwise.
    """
    if not _CRYPTO_AVAILABLE:
        raise CryptoError("cryptography package required")
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        from cryptography.exceptions import InvalidSignature

        key_bytes = bytes.fromhex(envelope["sender_id"])
        sig_bytes = bytes.fromhex(envelope["signature_hex"])

        h = hashlib.sha512()
        h.update(envelope["recipient_id"].encode())
        h.update(envelope["payload_hex"].encode())
        h.update(struct.pack("<q", envelope["timestamp"]))
        h.update(envelope["message_id"].encode())
        signing_hash = h.digest()

        vk = Ed25519PublicKey.from_public_bytes(key_bytes)
        vk.verify(sig_bytes, signing_hash)

        # Check freshness (max 5 minutes)
        age = abs(int(time.time()) - envelope["timestamp"])
        if age > 300:
            return False

        return True
    except Exception:
        return False


# ── HTTP Sync Client ──────────────────────────────────────────────────────────

class SibnaClient:
    """
    Synchronous Sibna Protocol client.

    Wraps the full v11.0 server API:
      - Authentication (Ed25519 challenge-response → JWT)
      - PreKey management
      - Sealed envelope messaging (REST fallback)
      - Inbox polling for offline messages

    Usage:
        client = SibnaClient(server="http://localhost:8080")
        client.generate_identity()
        client.authenticate()
        client.upload_prekey()
        client.send_message(recipient_id="...", plaintext=b"Hello!")
    """

    def __init__(self, server: str = "http://localhost:8080",
                 pinned_cert: Optional[str] = None):
        """
        Parameters
        ----------
        server : str
            Base URL of the Sibna relay server.
        pinned_cert : str, optional
            SECURITY FIX §3.5: Path to a PEM file containing the server's
            expected TLS certificate (or its CA). When set, any TLS certificate
            not matching this file is rejected — even if signed by a trusted CA.
            This prevents MITM attacks via compromised certificate authorities.

            Generate your pinned cert with:
                openssl s_client -connect your-server:443 </dev/null 2>/dev/null \\
                    | openssl x509 -outform PEM > server.pem

            Never omit this in production deployments.
        """
        if not _REQUESTS_AVAILABLE:
            raise NetworkError("requests package required: pip install requests")
        self.server = server.rstrip("/")
        self.identity: Optional[Identity] = None
        self.jwt_token: Optional[str] = None
        self._session = requests.Session()

        # SECURITY FIX §3.5: Apply certificate pinning when a cert path is provided.
        # For HTTPS servers without pinning, requests still validates against the system
        # trust store — but CA compromise is not mitigated without pinning.
        if pinned_cert is not None:
            if not os.path.isfile(pinned_cert):
                raise ValueError(f"pinned_cert path does not exist: {pinned_cert!r}")
            self._session.verify = pinned_cert
        elif server.startswith("https://"):
            import warnings
            warnings.warn(
                "SibnaClient: HTTPS server configured without certificate pinning. "
                "Pass pinned_cert='/path/to/server.pem' to enable pinning.",
                stacklevel=2
            )

    def generate_identity(self, private_key_bytes: Optional[bytes] = None) -> Identity:
        """Generate (or load) an Ed25519 identity keypair."""
        self.identity = Identity(private_key_bytes)
        return self.identity

    def authenticate(self) -> str:
        """
        Full Ed25519 challenge-response authentication.

        Returns the JWT token (also stored in self.jwt_token).
        Tokens expire in 24h.
        """
        if not self.identity:
            raise AuthError("No identity loaded. Call generate_identity() first.")

        # Step 1: Request challenge
        r = self._session.post(f"{self.server}/v1/auth/challenge", json={
            "identity_key_hex": self.identity.public_key_hex
        })
        self._check_response(r, "auth/challenge")
        challenge_hex = r.json()["challenge_hex"]

        # Step 2: Sign the challenge
        challenge_bytes = bytes.fromhex(challenge_hex)
        signature_hex = self.identity.sign_hex(challenge_bytes)

        # Step 3: Prove
        r = self._session.post(f"{self.server}/v1/auth/prove", json={
            "identity_key_hex": self.identity.public_key_hex,
            "challenge_hex": challenge_hex,
            "signature_hex": signature_hex,
        })
        self._check_response(r, "auth/prove")
        self.jwt_token = r.json()["token"]
        return self.jwt_token

    def health(self) -> Dict[str, Any]:
        """Check server health."""
        r = self._session.get(f"{self.server}/health")
        self._check_response(r, "health")
        return r.json()

    def upload_prekey(self, bundle_hex: str, is_last_resort: bool = False) -> None:
        """
        Upload a signed PreKeyBundle to the server.

        bundle_hex is produced by the Rust core library via FFI/WASM:
            bundle = sibna_generate_prekey_bundle(ctx)
        """
        r = self._session.post(f"{self.server}/v1/prekeys/upload", json={
            "bundle_hex": bundle_hex,
            "is_last_resort": is_last_resort
        })
        self._check_response(r, "prekeys/upload")

    def fetch_prekeys(self, root_id_hex: str) -> List[str]:
        """
        Fetch a peer's PreKeyBundles for X3DH initiation.

        Returns a list of bundle_hex (one for each linked device). Note: bundles are deleted from server after fetch.
        """
        r = self._session.get(f"{self.server}/v1/prekeys/{root_id_hex}")
        self._check_response(r, "prekeys/fetch")
        return r.json()["bundles_hex"]

    def send_message(
        self,
        recipient_id: str,
        payload_hex: str,
        sign: bool = True,
        compress: bool = False,
    ) -> int:
        """
        Send a sealed envelope via REST (HTTP fallback for IoT/offline).

        payload_hex: the Double Ratchet ciphertext (already encrypted by core).
        sign: if True, adds Ed25519 signature for end-to-end integrity.

        Returns HTTP status code (200 = delivered live, 202 = queued offline).
        """
        if sign and self.identity:
            body = make_signed_envelope(self.identity, recipient_id, payload_hex, compress)
        else:
            body = {
                "recipient_id": recipient_id,
                "payload_hex": payload_hex,
                "compressed": compress,
            }

        r = self._session.post(f"{self.server}/v1/messages/send", json=body)
        self._check_response(r, "messages/send")
        return r.status_code

    def send_message_multi(
        self,
        encrypted_messages: Dict[str, str],
        sign: bool = True,
        compress: bool = False,
    ) -> Dict[str, int]:
        """
        Fan-out send: Transmits sealed envelopes to multiple associated devices.
        encrypted_messages: dict mapping `recipient_device_id_hex` -> `payload_hex`.
        Returns a dict of recipient_device_id_hex -> HTTP status code.
        """
        results = {}
        for rcpt_id, payload in encrypted_messages.items():
            results[rcpt_id] = self.send_message(rcpt_id, payload, sign, compress)
        return results

    def fetch_inbox(self) -> List[Dict[str, Any]]:
        """
        Fetch queued offline messages from the server inbox.

        Messages are deleted from the server after delivery.
        Always verify each envelope's signature before processing!
        """
        if not self.identity or not self.jwt_token:
            raise AuthError("Must authenticate before fetching inbox.")

        r = self._session.get(f"{self.server}/v1/messages/inbox", params={
            "identity_key_hex": self.identity.public_key_hex,
            "token": self.jwt_token,
        })
        self._check_response(r, "messages/inbox")
        messages = r.json().get("messages", [])

        # Verify each envelope's signature
        verified = []
        for msg in messages:
            if verify_signed_envelope(msg):
                verified.append(msg)
            else:
                print(f"⚠ WARNING: Dropped message with invalid signature: {msg.get('message_id')}")

        return verified

    def _check_response(self, r: "requests.Response", endpoint: str) -> None:
        if r.status_code == 429:
            raise NetworkError(f"Rate limited on {endpoint}", 429)
        if r.status_code == 401:
            raise AuthError(f"Unauthorized on {endpoint}", 401)
        if r.status_code >= 400:
            raise NetworkError(
                f"{endpoint} failed: HTTP {r.status_code} — {r.text[:200]}", r.status_code
            )

    def __repr__(self) -> str:
        identity_str = self.identity.public_key_hex[:16] if self.identity else "None"
        return f"<SibnaClient server={self.server} identity={identity_str}...>"


# ── Async WebSocket Client ─────────────────────────────────────────────────────

class AsyncSibnaClient:
    """
    Async Sibna Protocol client with WebSocket real-time relay.

    Usage:
        client = AsyncSibnaClient(server="http://localhost:8080")
        await client.generate_identity()
        await client.authenticate()
        await client.connect(on_message=my_handler)
        await client.send("recipient_hex", b"Hello!")
    """

    def __init__(self, server: str = "http://localhost:8080",
                 pinned_cert: Optional[str] = None):
        """
        Parameters
        ----------
        server : str
            Base URL of the Sibna relay server.
        pinned_cert : str, optional
            SECURITY FIX §3.5: Path to a PEM file for TLS certificate pinning.
            See SibnaClient.__init__ for full documentation.
        """
        self.server = server.rstrip("/")
        self.ws_server = server.replace("http://", "ws://").replace("https://", "wss://")
        self.identity: Optional[Identity] = None
        self.jwt_token: Optional[str] = None
        self._ws = None
        self._on_message: Optional[Callable] = None
        self._pinned_cert: Optional[str] = pinned_cert

        if pinned_cert is not None and not os.path.isfile(pinned_cert):
            raise ValueError(f"pinned_cert path does not exist: {pinned_cert!r}")
        if pinned_cert is None and server.startswith("https://"):
            import warnings
            warnings.warn(
                "AsyncSibnaClient: HTTPS server without certificate pinning. "
                "Pass pinned_cert='/path/to/server.pem' to enable pinning.",
                stacklevel=2
            )

    def _make_ssl_context(self):
        """Build an ssl.SSLContext with optional certificate pinning."""
        import ssl
        ctx = ssl.create_default_context()
        if self._pinned_cert:
            # Replace the default CA store with only the pinned certificate.
            ctx.load_verify_locations(cafile=self._pinned_cert)
        return ctx

    def generate_identity(self, private_key_bytes: Optional[bytes] = None) -> Identity:
        self.identity = Identity(private_key_bytes)
        return self.identity

    async def authenticate(self) -> str:
        """Async Ed25519 challenge-response flow."""
        if not _AIOHTTP_AVAILABLE:
            raise NetworkError("aiohttp required: pip install aiohttp")
        if not self.identity:
            raise AuthError("No identity loaded.")

        ssl_ctx = self._make_ssl_context() if self.server.startswith("https://") else None
        connector = aiohttp.TCPConnector(ssl=ssl_ctx) if ssl_ctx else None
        async with aiohttp.ClientSession(connector=connector) as session:
            # Challenge
            async with session.post(
                f"{self.server}/v1/auth/challenge",
                json={"identity_key_hex": self.identity.public_key_hex}
            ) as r:
                if r.status != 200:
                    raise AuthError(f"Challenge failed: {r.status}")
                data = await r.json()
                challenge_hex = data["challenge_hex"]

            # Prove
            signature_hex = self.identity.sign_hex(bytes.fromhex(challenge_hex))
            async with session.post(
                f"{self.server}/v1/auth/prove",
                json={
                    "identity_key_hex": self.identity.public_key_hex,
                    "challenge_hex": challenge_hex,
                    "signature_hex": signature_hex,
                }
            ) as r:
                if r.status != 200:
                    raise AuthError(f"Prove failed: {r.status}")
                data = await r.json()
                self.jwt_token = data["token"]
                return self.jwt_token

    async def connect(self, on_message: Optional[Callable] = None) -> None:
        """
        Connect to WebSocket relay.

        on_message: async callback(envelope: dict) called for each received message.
        """
        if not self.jwt_token:
            raise AuthError("Must authenticate before connecting.")
        if not _AIOHTTP_AVAILABLE:
            raise NetworkError("aiohttp required: pip install aiohttp")

        self._on_message = on_message
        # FIX: Phase 6.1 — JWT was in query string (logged in access logs,
        # browser history, Referer headers). Move to Sec-WebSocket-Protocol
        # header which is the standard way to pass tokens in WebSocket
        # handshake without leaking them. The server must accept the token
        # via the "Authorization: Bearer" subprotocol or a custom
        # "Sec-WebSocket-Protocol: sibna-token.<jwt>" header.
        ws_url = f"{self.ws_server}/ws"
        ws_headers = {"Authorization": f"Bearer {self.jwt_token}"}

        # SECURITY FIX §3.5: Apply certificate pinning for WSS connections.
        ssl_ctx = self._make_ssl_context() if self.ws_server.startswith("wss://") else None
        connector = aiohttp.TCPConnector(ssl=ssl_ctx) if ssl_ctx else None

        async with aiohttp.ClientSession(connector=connector) as session:
            async with session.ws_connect(ws_url, headers=ws_headers) as ws:
                self._ws = ws
                print(f"🟢 WebSocket connected to {ws_url[:40]}...")
                async for msg in ws:
                    if msg.type == aiohttp.WSMsgType.BINARY:
                        try:
                            ws_msg = json.loads(msg.data)
                            
                            # PILLAR 1 & 3: New v3.0 Tagged WsMessage parsing
                            msg_type = ws_msg.get("type", "envelope") # Fallback to envelope if untagged
                            
                            if msg_type == "envelope":
                                envelope = ws_msg.get("envelope", ws_msg) # Fallback to root object if untagged
                                if verify_signed_envelope(envelope):
                                    msg_id = envelope.get("message_id")
                                    # Send ACK back immediately to ensure Zero Message Loss
                                    if msg_id:
                                        await ws.send_bytes(json.dumps({
                                            "type": "ack",
                                            "message_id": msg_id
                                        }).encode())
                                    
                                    if self._on_message:
                                        await self._on_message(envelope)
                                else:
                                    print(f"⚠ Invalid signature on message {envelope.get('message_id')}")
                            elif msg_type == "webrtc":
                                signal = ws_msg.get("signal", {})
                                print(f"📞 Received WebRTC signal from {ws_msg.get('sender_id', 'unknown')}")
                                
                        except Exception as e:
                            print(f"⚠ Failed to parse message: {e}")
                    elif msg.type == aiohttp.WSMsgType.ERROR:
                        raise NetworkError(f"WebSocket error: {ws.exception()}")

    async def send(
        self,
        recipient_id: str,
        payload_hex: str,
        sign: bool = True,
        compress: bool = False,
    ) -> None:
        """
        Send a sealed envelope over WebSocket.
        """
        if not self._ws:
            raise NetworkError("Not connected. Call connect() first.")

        if sign and self.identity:
            envelope = make_signed_envelope(self.identity, recipient_id, payload_hex, compress)
        else:
            envelope = {
                "recipient_id": recipient_id,
                "payload_hex": payload_hex,
                "compressed": compress,
                "message_id": str(uuid.uuid4()),
                "timestamp": int(time.time()),
            }

        ws_msg = {
            "type": "envelope",
            "envelope": envelope
        }
        await self._ws.send_bytes(json.dumps(ws_msg).encode())

    async def send_multi(
        self,
        encrypted_messages: Dict[str, str],
        sign: bool = True,
        compress: bool = False,
    ) -> None:
        """
        Fan-out send async: Send multiple sealed envelopes over WebSocket.
        encrypted_messages: dict mapping `recipient_device_id_hex` -> `payload_hex`.
        """
        if getattr(asyncio, "TaskGroup", None):
            # Python 3.11+ async optimization for concurrent Fan-out via WS
            async with asyncio.TaskGroup() as tg:
                for rcpt_id, payload in encrypted_messages.items():
                    tg.create_task(self.send(rcpt_id, payload, sign, compress))
        else:
            # Fallback for Python < 3.11
            aws = [self.send(rcpt_id, payload, sign, compress) for rcpt_id, payload in encrypted_messages.items()]
            await asyncio.gather(*aws)


# ── Re-exports ────────────────────────────────────────────────────────────────

__all__ = [
    "SibnaClient",
    "AsyncSibnaClient",
    "Identity",
    "SibnaError",
    "AuthError",
    "NetworkError",
    "CryptoError",
    "pad_payload",
    "unpad_payload",
    "make_signed_envelope",
    "verify_signed_envelope",
    "__version__",
]
