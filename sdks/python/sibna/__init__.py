"""
Sibna Protocol Python SDK - Ultra Secure Edition

A Python wrapper for the Sibna secure communication protocol.

Example usage:
    >>> import sibna
    >>> 
    >>> # Create context
    >>> ctx = sibna.Context(password=b"my_secure_password")
    >>> 
    >>> # Generate identity
    >>> identity = ctx.generate_identity()
    >>> 
    >>> # Create session
    >>> session = ctx.create_session(b"peer_id")
    >>> 
    >>> # Encrypt message
    >>> encrypted = session.encrypt(b"Hello, World!")
    >>> 
    >>> # Decrypt message
    >>> decrypted = session.decrypt(encrypted)
"""

__version__ = "1.0.0"
__author__ = "Sibna Security Team"
__license__ = "Apache-2.0 OR MIT"

from typing import Optional, List, Tuple, Union
import ctypes
import os
import platform

# Load the shared library
def _load_library():
    """Load the Sibna native library."""
    system = platform.system()
    
    if system == "Linux":
        lib_name = "libsibna.so"
    elif system == "Darwin":
        lib_name = "libsibna.dylib"
    elif system == "Windows":
        lib_name = "sibna.dll"
    else:
        raise OSError(f"Unsupported platform: {system}")
    
    # Try to find library in various locations
    search_paths = [
        os.path.dirname(__file__),
        os.path.join(os.path.dirname(__file__), "..", "..", ".."),
        "/usr/local/lib",
        "/usr/lib",
    ]
    
    for path in search_paths:
        lib_path = os.path.join(path, lib_name)
        if os.path.exists(lib_path):
            return ctypes.CDLL(lib_path)
    
    raise OSError(f"Could not find {lib_name}")

# Try to load library (will fail gracefully if not available)
try:
    _lib = _load_library()
except OSError:
    _lib = None


class SibnaError(Exception):
    """Base exception for Sibna errors."""
    
    ERROR_CODES = {
        0: "Success",
        1: "Invalid argument",
        2: "Invalid key",
        3: "Encryption failed",
        4: "Decryption failed",
        5: "Out of memory",
        6: "Invalid state",
        7: "Session not found",
        8: "Key not found",
        9: "Rate limit exceeded",
        10: "Internal error",
        11: "Buffer too small",
        12: "Invalid ciphertext",
        13: "Authentication failed",
    }
    
    def __init__(self, code: int, message: Optional[str] = None):
        self.code = code
        self.message = message or self.ERROR_CODES.get(code, f"Unknown error ({code})")
        super().__init__(self.message)


class ByteBuffer(ctypes.Structure):
    """FFI-safe byte buffer."""
    _fields_ = [
        ("data", ctypes.POINTER(ctypes.c_uint8)),
        ("len", ctypes.c_size_t),
        ("capacity", ctypes.c_size_t),
    ]
    
    def to_bytes(self) -> bytes:
        """Convert buffer to Python bytes."""
        if self.data is None:
            return b""
        return bytes(ctypes.cast(self.data, ctypes.POINTER(ctypes.c_uint8 * self.len)).contents)
    
    def free(self):
        """Free the buffer."""
        if _lib is not None:
            _lib.sibna_free_buffer(ctypes.byref(self))


class Context:
    """Secure context for Sibna protocol operations."""
    
    def __init__(self, password: Optional[bytes] = None):
        """
        Create a new secure context.
        
        Args:
            password: Master password for storage encryption (optional)
        """
        if _lib is None:
            raise RuntimeError("Sibna library not loaded")
        
        self._ctx = ctypes.c_void_p()
        
        if password:
            password_ptr = ctypes.cast(password, ctypes.POINTER(ctypes.c_uint8))
            password_len = len(password)
        else:
            password_ptr = None
            password_len = 0
        
        result = _lib.sibna_context_create(
            password_ptr,
            password_len,
            ctypes.byref(self._ctx)
        )
        
        if result != 0:
            raise SibnaError(result)
    
    def __del__(self):
        """Destroy the context."""
        if hasattr(self, '_ctx') and self._ctx:
            _lib.sibna_context_destroy(self._ctx)
    
    def generate_identity(self) -> 'IdentityKeyPair':
        """Generate a new identity key pair."""
        # This would call into the native library
        # For now, return a placeholder
        return IdentityKeyPair()
    
    def create_session(self, peer_id: bytes) -> 'Session':
        """Create a new session with a peer."""
        session = ctypes.c_void_p()
        result = _lib.sibna_session_create(
            self._ctx,
            ctypes.cast(peer_id, ctypes.POINTER(ctypes.c_uint8)),
            len(peer_id),
            ctypes.byref(session)
        )
        
        if result != 0:
            raise SibnaError(result)
        
        return Session(session)
    
    @staticmethod
    def version() -> str:
        """Get the protocol version."""
        if _lib is None:
            return "1.0.0"
        
        buffer = ctypes.create_string_buffer(32)
        result = _lib.sibna_version(buffer, 32)
        
        if result != 0:
            raise SibnaError(result)
        
        return buffer.value.decode('utf-8')


class IdentityKeyPair:
    """Identity key pair for authentication."""
    
    def __init__(self):
        self._public_key = None
        self._private_key = None
    
    @property
    def public_key(self) -> bytes:
        """Get the public key."""
        return self._public_key or b""
    
    def sign(self, data: bytes) -> bytes:
        """Sign data with the identity key."""
        # TODO: Call native library via FFI
        raise NotImplementedError("Session encrypt requires compiled native library")
    
    def verify(self, data: bytes, signature: bytes) -> bool:
        """Verify a signature."""
        # Implementation would call native library
        return False


class Session:
    """Secure session for encrypted communication."""
    
    def __init__(self, handle: ctypes.c_void_p):
        self._handle = handle
    
    def __del__(self):
        """Destroy the session."""
        if hasattr(self, '_handle') and self._handle:
            _lib.sibna_session_destroy(self._handle)
    
    def encrypt(self, plaintext: bytes, associated_data: Optional[bytes] = None) -> bytes:
        """
        Encrypt a message.
        
        Args:
            plaintext: Message to encrypt
            associated_data: Additional authenticated data (optional)
        
        Returns:
            Encrypted ciphertext
        """
        # TODO: Call native library via FFI
        raise NotImplementedError("Session decrypt requires compiled native library")
    
    def decrypt(self, ciphertext: bytes, associated_data: Optional[bytes] = None) -> bytes:
        """
        Decrypt a message.
        
        Args:
            ciphertext: Ciphertext to decrypt
            associated_data: Additional authenticated data (optional)
        
        Returns:
            Decrypted plaintext
        """
        # Implementation would call native library
        return b""


class Crypto:
    """Standalone cryptographic operations."""
    
    @staticmethod
    def generate_key() -> bytes:
        """Generate a random 32-byte encryption key."""
        if _lib is None:
            raise RuntimeError("Sibna library not loaded")
        
        key = ctypes.create_string_buffer(32)
        result = _lib.sibna_generate_key(key)
        
        if result != 0:
            raise SibnaError(result)
        
        return key.raw
    
    @staticmethod
    def encrypt(key: bytes, plaintext: bytes, associated_data: Optional[bytes] = None) -> bytes:
        """
        Encrypt data with a key.
        
        Args:
            key: 32-byte encryption key
            plaintext: Data to encrypt
            associated_data: Additional authenticated data (optional)
        
        Returns:
            Encrypted ciphertext
        """
        if _lib is None:
            raise RuntimeError("Sibna library not loaded")
        
        if len(key) != 32:
            raise ValueError("Key must be 32 bytes")
        
        ciphertext = ByteBuffer()
        
        ad_ptr = None
        ad_len = 0
        if associated_data:
            ad_ptr = ctypes.cast(associated_data, ctypes.POINTER(ctypes.c_uint8))
            ad_len = len(associated_data)
        
        result = _lib.sibna_encrypt(
            ctypes.cast(key, ctypes.POINTER(ctypes.c_uint8)),
            ctypes.cast(plaintext, ctypes.POINTER(ctypes.c_uint8)),
            len(plaintext),
            ad_ptr,
            ad_len,
            ctypes.byref(ciphertext)
        )
        
        if result != 0:
            raise SibnaError(result)
        
        try:
            return ciphertext.to_bytes()
        finally:
            ciphertext.free()
    
    @staticmethod
    def decrypt(key: bytes, ciphertext: bytes, associated_data: Optional[bytes] = None) -> bytes:
        """
        Decrypt data with a key.
        
        Args:
            key: 32-byte encryption key
            ciphertext: Ciphertext to decrypt
            associated_data: Additional authenticated data (optional)
        
        Returns:
            Decrypted plaintext
        """
        if _lib is None:
            raise RuntimeError("Sibna library not loaded")
        
        if len(key) != 32:
            raise ValueError("Key must be 32 bytes")
        
        plaintext = ByteBuffer()
        
        ad_ptr = None
        ad_len = 0
        if associated_data:
            ad_ptr = ctypes.cast(associated_data, ctypes.POINTER(ctypes.c_uint8))
            ad_len = len(associated_data)
        
        result = _lib.sibna_decrypt(
            ctypes.cast(key, ctypes.POINTER(ctypes.c_uint8)),
            ctypes.cast(ciphertext, ctypes.POINTER(ctypes.c_uint8)),
            len(ciphertext),
            ad_ptr,
            ad_len,
            ctypes.byref(plaintext)
        )
        
        if result != 0:
            raise SibnaError(result)
        
        try:
            return plaintext.to_bytes()
        finally:
            plaintext.free()
    
    @staticmethod
    def random_bytes(length: int) -> bytes:
        """Generate random bytes."""
        if _lib is None:
            raise RuntimeError("Sibna library not loaded")
        
        buffer = ctypes.create_string_buffer(length)
        result = _lib.sibna_random_bytes(length, buffer)
        
        if result != 0:
            raise SibnaError(result)
        
        return buffer.raw


# Convenience functions
def generate_key() -> bytes:
    """Generate a random 32-byte encryption key."""
    return Crypto.generate_key()


def encrypt(key: bytes, plaintext: bytes, associated_data: Optional[bytes] = None) -> bytes:
    """Encrypt data with a key."""
    return Crypto.encrypt(key, plaintext, associated_data)


def decrypt(key: bytes, ciphertext: bytes, associated_data: Optional[bytes] = None) -> bytes:
    """Decrypt data with a key."""
    return Crypto.decrypt(key, ciphertext, associated_data)


def random_bytes(length: int) -> bytes:
    """Generate random bytes."""
    return Crypto.random_bytes(length)


__all__ = [
    "Context",
    "Session",
    "IdentityKeyPair",
    "Crypto",
    "SibnaError",
    "generate_key",
    "encrypt",
    "decrypt",
    "random_bytes",
    "__version__",
]
