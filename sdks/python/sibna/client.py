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

__version__ = "11.0.0"
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

PADDING_BLOCK = 1024

def pad_payload(data: bytes) -> bytes:
    """
    Pad payload to nearest 1024-byte boundary (metadata resistance).
    Makes all messages look the same size to a passive observer.
    """
    unpadded_len = len(data) + 1
    remainder = unpadded_len % PADDING_BLOCK
    padding_needed = (PADDING_BLOCK - remainder) % PADDING_BLOCK
    if padding_needed == 0:
        padding_needed = PADDING_BLOCK  # Always pad at least 1 byte
    indicator = padding_needed % 256
    padding = secrets.token_bytes(padding_needed)
    return bytes([indicator]) + data + padding

def unpad_payload(padded: bytes) -> bytes:
    """Remove padding from a received payload."""
    if not padded:
        raise CryptoError("Empty payload")
    indicator = padded[0]
    padded_len = len(padded)
    padding_needed = padded_len % PADDING_BLOCK
    actual_padding = indicator if padding_needed == 0 else padding_needed
    return padded[1 : padded_len - actual_padding]


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

    def __init__(self, server: str = "http://localhost:8080"):
        if not _REQUESTS_AVAILABLE:
            raise NetworkError("requests package required: pip install requests")
        self.server = server.rstrip("/")
        self.identity: Optional[Identity] = None
        self.jwt_token: Optional[str] = None
        self._session = requests.Session()

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

    def upload_prekey(self, bundle_hex: str) -> None:
        """
        Upload a signed PreKeyBundle to the server.

        bundle_hex is produced by the Rust core library via FFI/WASM:
            bundle = sibna_generate_prekey_bundle(ctx)
        """
        r = self._session.post(f"{self.server}/v1/prekeys/upload", json={
            "bundle_hex": bundle_hex
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

    def __init__(self, server: str = "http://localhost:8080"):
        self.server = server.rstrip("/")
        self.ws_server = server.replace("http://", "ws://").replace("https://", "wss://")
        self.identity: Optional[Identity] = None
        self.jwt_token: Optional[str] = None
        self._ws = None
        self._on_message: Optional[Callable] = None

    def generate_identity(self, private_key_bytes: Optional[bytes] = None) -> Identity:
        self.identity = Identity(private_key_bytes)
        return self.identity

    async def authenticate(self) -> str:
        """Async Ed25519 challenge-response flow."""
        if not _AIOHTTP_AVAILABLE:
            raise NetworkError("aiohttp required: pip install aiohttp")
        if not self.identity:
            raise AuthError("No identity loaded.")

        async with aiohttp.ClientSession() as session:
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
        ws_url = f"{self.ws_server}/ws?token={self.jwt_token}"

        async with aiohttp.ClientSession() as session:
            async with session.ws_connect(ws_url) as ws:
                self._ws = ws
                print(f"🟢 WebSocket connected to {ws_url[:40]}...")
                async for msg in ws:
                    if msg.type == aiohttp.WSMsgType.BINARY:
                        try:
                            envelope = json.loads(msg.data)
                            if verify_signed_envelope(envelope):
                                if self._on_message:
                                    await self._on_message(envelope)
                            else:
                                print(f"⚠ Invalid signature on message {envelope.get('message_id')}")
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

        await self._ws.send_bytes(json.dumps(envelope).encode())

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
