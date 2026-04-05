//! Key Derivation Functions
//!
//! Provides secure key derivation using HKDF and Argon2.

use super::{CryptoError, CryptoResult, KEY_LENGTH};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::{Zeroize, Zeroizing};

/// Default number of HKDF iterations
const DEFAULT_HKDF_ITERATIONS: u32 = 1;

/// Maximum HKDF iterations
const MAX_HKDF_ITERATIONS: u32 = 10000;

/// Default Argon2 memory cost (KB)
#[allow(dead_code)]
const DEFAULT_ARGON2_MEMORY: u32 = 65536; // 64 MB

/// Default Argon2 iterations
#[allow(dead_code)]
const DEFAULT_ARGON2_ITERATIONS: u32 = 3;

/// Default Argon2 parallelism
#[allow(dead_code)]
const DEFAULT_ARGON2_PARALLELISM: u32 = 4;

/// Key Derivation using HKDF-SHA256
pub struct HkdfKdf;

impl HkdfKdf {
    /// Derive a key using HKDF
    ///
    /// # Arguments
    /// * `ikm` - Input keying material
    /// * `salt` - Salt (optional, use None for random salt)
    /// * `info` - Context information
    /// * `output_len` - Desired output length
    pub fn derive(
        ikm: &[u8],
        salt: Option<&[u8]>,
        info: &[u8],
        output_len: usize,
    ) -> CryptoResult<Vec<u8>> {
        if output_len == 0 || output_len > 255 * 32 {
            return Err(CryptoError::InvalidKeyLength);
        }

        if info.len() > 256 {
            return Err(CryptoError::InvalidCiphertext);
        }

        let hkdf = Hkdf::<Sha256>::new(salt, ikm);
        let mut okm = vec![0u8; output_len];

        hkdf.expand(info, &mut okm)
            .map_err(|_| CryptoError::KeyDerivationFailed)?;

        Ok(okm)
    }

    /// Derive multiple keys from a single input
    ///
    /// # Arguments
    /// * `ikm` - Input keying material
    /// * `salt` - Salt
    /// * `infos` - Multiple info strings
    pub fn derive_multiple(
        ikm: &[u8],
        salt: &[u8],
        infos: &[&[u8]],
    ) -> CryptoResult<Vec<Vec<u8>>> {
        infos
            .iter()
            .map(|info| Self::derive(ikm, Some(salt), info, KEY_LENGTH))
            .collect()
    }

    /// Derive a key with iterations (for password-based KDF)
    ///
    /// # Arguments
    /// * `ikm` - Input keying material
    /// * `salt` - Salt
    /// * `info` - Context information
    /// * `iterations` - Number of iterations
    pub fn derive_iterated(
        ikm: &[u8],
        salt: &[u8],
        info: &[u8],
        iterations: u32,
    ) -> CryptoResult<Zeroizing<[u8; KEY_LENGTH]>> {
        if iterations == 0 || iterations > MAX_HKDF_ITERATIONS {
            return Err(CryptoError::KeyDerivationFailed);
        }

        let mut current = Self::derive(ikm, Some(salt), info, KEY_LENGTH)?;

        for _ in 1..iterations {
            let next = Self::derive(&current, Some(salt), info, KEY_LENGTH)?;
            current.zeroize();
            current = next;
        }

        let mut result = [0u8; KEY_LENGTH];
        result.copy_from_slice(&current);
        current.zeroize();

        Ok(Zeroizing::new(result))
    }
}

/// Double Ratchet KDF
pub struct RatchetKdf;

impl RatchetKdf {
    /// KDF for root key (KDF_RK)
    ///
    /// Derives new root key and chain key from DH output
    pub fn kdf_rk(
        root_key: &[u8; KEY_LENGTH],
        dh_out: &[u8; KEY_LENGTH],
    ) -> CryptoResult<(Zeroizing<[u8; KEY_LENGTH]>, Zeroizing<[u8; KEY_LENGTH]>)> {
        let hkdf = Hkdf::<Sha256>::new(Some(root_key), dh_out);

        let mut okm = [0u8; 64];
        hkdf.expand(b"SibnaRatchet_v9", &mut okm)
            .map_err(|_| CryptoError::KeyDerivationFailed)?;

        let mut new_rk = [0u8; KEY_LENGTH];
        let mut new_ck = [0u8; KEY_LENGTH];
        new_rk.copy_from_slice(&okm[..KEY_LENGTH]);
        new_ck.copy_from_slice(&okm[KEY_LENGTH..]);

        okm.zeroize();

        Ok((Zeroizing::new(new_rk), Zeroizing::new(new_ck)))
    }

    /// KDF for chain key (KDF_CK)
    ///
    /// Derives message key and next chain key
    pub fn kdf_ck(
        chain_key: &[u8; KEY_LENGTH],
    ) -> CryptoResult<(Zeroizing<[u8; KEY_LENGTH]>, Zeroizing<[u8; KEY_LENGTH]>)> {
        // Message key = HMAC(chain_key, 0x01)
        let mk = Self::hmac_sha256(chain_key, &[0x01])?;

        // Next chain key = HMAC(chain_key, 0x02)
        let next_ck = Self::hmac_sha256(chain_key, &[0x02])?;

        Ok((mk, next_ck))
    }

    /// HMAC-SHA256 helper
    fn hmac_sha256(key: &[u8], data: &[u8]) -> CryptoResult<Zeroizing<[u8; KEY_LENGTH]>> {
        use hmac::{Hmac, Mac};

        let mut mac = Hmac::<Sha256>::new_from_slice(key)
            .map_err(|_| CryptoError::InvalidKeyLength)?;
        mac.update(data);
        let result = mac.finalize();
        let bytes = result.into_bytes();

        let mut output = [0u8; KEY_LENGTH];
        output.copy_from_slice(&bytes);

        Ok(Zeroizing::new(output))
    }
}

/// X3DH Key Derivation
pub struct X3dhKdf;

impl X3dhKdf {
    /// Derive X3DH shared secret from DH results
    pub fn derive_shared_secret(
        dh1: &[u8; KEY_LENGTH],
        dh2: &[u8; KEY_LENGTH],
        dh3: &[u8; KEY_LENGTH],
        dh4: Option<&[u8; KEY_LENGTH]>,
        transcript_hash: &[u8; 32],
    ) -> CryptoResult<Zeroizing<[u8; KEY_LENGTH]>> {
        // Concatenate all DH results + transcript hash
        let mut concatenated = Vec::with_capacity(KEY_LENGTH * 5);
        concatenated.extend_from_slice(dh1);
        concatenated.extend_from_slice(dh2);
        concatenated.extend_from_slice(dh3);
        if let Some(dh4) = dh4 {
            concatenated.extend_from_slice(dh4);
        }
        concatenated.extend_from_slice(transcript_hash);

        // Use HKDF to derive final shared secret
        let hkdf = Hkdf::<Sha256>::new(None, &concatenated);
        let mut okm = [0u8; KEY_LENGTH];

        hkdf.expand(b"SibnaX3DH_v10", &mut okm)
            .map_err(|_| CryptoError::KeyDerivationFailed)?;

        concatenated.zeroize();

        Ok(Zeroizing::new(okm))
    }

    /// Derive hybrid shared secret (ECC + PQC)
    pub fn derive_pq_shared_secret(
        dh1: &[u8; KEY_LENGTH],
        dh2: &[u8; KEY_LENGTH],
        dh3: &[u8; KEY_LENGTH],
        dh4: Option<&[u8; KEY_LENGTH]>,
        pq_shared_secret: &[u8; 32],
        transcript_hash: &[u8; 32],
    ) -> CryptoResult<Zeroizing<[u8; KEY_LENGTH]>> {
        // Concatenate all DH results + PQ shared secret + transcript hash
        let mut concatenated = Vec::with_capacity(KEY_LENGTH * 6);
        concatenated.extend_from_slice(dh1);
        concatenated.extend_from_slice(dh2);
        concatenated.extend_from_slice(dh3);
        if let Some(dh4) = dh4 {
            concatenated.extend_from_slice(dh4);
        }
        concatenated.extend_from_slice(pq_shared_secret);
        concatenated.extend_from_slice(transcript_hash);

        // Use HKDF to derive final hybrid shared secret
        // Note the version bump to v10 for PQC-capable core
        let hkdf = Hkdf::<Sha256>::new(None, &concatenated);
        let mut okm = [0u8; KEY_LENGTH];

        hkdf.expand(b"SibnaPQX3DH_v10", &mut okm)
            .map_err(|_| CryptoError::KeyDerivationFailed)?;

        concatenated.zeroize();

        Ok(Zeroizing::new(okm))
    }
}

/// Password-based key derivation using Argon2
#[cfg(feature = "argon2")]
pub struct Argon2Kdf;

#[cfg(feature = "argon2")]
impl Argon2Kdf {
    /// Derive a key from a password using Argon2id
    ///
    /// # Arguments
    /// * `password` - User password
    /// * `salt` - Random salt (must be unique per password)
    /// * `memory` - Memory cost in KB
    /// * `iterations` - Number of iterations
    /// * `parallelism` - Parallelism factor
    pub fn derive(
        password: &[u8],
        salt: &[u8],
        memory: u32,
        iterations: u32,
        parallelism: u32,
    ) -> CryptoResult<Zeroizing<[u8; KEY_LENGTH]>> {
        use argon2::Argon2;

        let params = argon2::Params::new(memory, iterations, parallelism, Some(KEY_LENGTH))
            .map_err(|_| CryptoError::KeyDerivationFailed)?;
        let argon2 = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);

        let mut output = [0u8; KEY_LENGTH];
        argon2.hash_password_into(password, salt, &mut output)
            .map_err(|_| CryptoError::KeyDerivationFailed)?;

        Ok(Zeroizing::new(output))
    }

    /// Derive with default parameters
    pub fn derive_default(
        password: &[u8],
        salt: &[u8],
    ) -> CryptoResult<Zeroizing<[u8; KEY_LENGTH]>> {
        Self::derive(
            password,
            salt,
            DEFAULT_ARGON2_MEMORY,
            DEFAULT_ARGON2_ITERATIONS,
            DEFAULT_ARGON2_PARALLELISM,
        )
    }
}

/// Simple hash-based key derivation (for compatibility)
/// NOTE: Internally now uses HKDF for resistance against length-extension attacks.
/// V4 FIX: The previous implementation did SHA256(salt ‖ input) which is
/// length-extension-attack-vulnerable. All variants now use HKDF.
pub struct SimpleKdf;

impl SimpleKdf {
    /// Derive a key using HKDF-SHA256
    pub fn derive_sha256(input: &[u8], salt: &[u8]) -> CryptoResult<Zeroizing<[u8; KEY_LENGTH]>> {
        let hkdf = Hkdf::<Sha256>::new(Some(salt), input);
        let mut okm = [0u8; KEY_LENGTH];
        hkdf.expand(b"SibnaSimpleKdf_SHA256", &mut okm)
            .map_err(|_| CryptoError::KeyDerivationFailed)?;
        Ok(Zeroizing::new(okm))
    }

    /// Derive a key using HKDF-SHA512 (truncated to 256 bits)
    pub fn derive_sha512(input: &[u8], salt: &[u8]) -> CryptoResult<Zeroizing<[u8; KEY_LENGTH]>> {
        use hkdf::Hkdf;
        use sha2::Sha512;
        let hkdf = Hkdf::<Sha512>::new(Some(salt), input);
        let mut okm = [0u8; KEY_LENGTH];
        hkdf.expand(b"SibnaSimpleKdf_SHA512", &mut okm)
            .map_err(|_| CryptoError::KeyDerivationFailed)?;
        Ok(Zeroizing::new(okm))
    }
}

/// Key derivation parameters
#[derive(Clone, Debug)]
pub struct KdfParams {
    /// Algorithm to use
    pub algorithm: KdfAlgorithm,
    /// Number of iterations
    pub iterations: u32,
    /// Memory cost (for Argon2)
    pub memory_cost: u32,
    /// Parallelism (for Argon2)
    pub parallelism: u32,
}

impl Default for KdfParams {
    fn default() -> Self {
        Self {
            algorithm: KdfAlgorithm::HkdfSha256,
            iterations: DEFAULT_HKDF_ITERATIONS,
            memory_cost: DEFAULT_ARGON2_MEMORY,
            parallelism: DEFAULT_ARGON2_PARALLELISM,
        }
    }
}

/// Key derivation algorithms
#[derive(Clone, Debug, Copy, PartialEq, Eq)]
pub enum KdfAlgorithm {
    /// HKDF with SHA-256
    HkdfSha256,
    /// HKDF with SHA-512
    HkdfSha512,
    /// Argon2id
    #[cfg(feature = "argon2")]
    Argon2id,
    /// Simple SHA-256
    SimpleSha256,
    /// Simple SHA-512
    SimpleSha512,
}

/// Unified key derivation interface
pub struct KeyDeriver;

impl KeyDeriver {
    /// Derive a key using the specified parameters
    pub fn derive(
        password: &[u8],
        salt: &[u8],
        info: &[u8],
        params: &KdfParams,
    ) -> CryptoResult<Zeroizing<[u8; KEY_LENGTH]>> {
        match params.algorithm {
            KdfAlgorithm::HkdfSha256 => {
                HkdfKdf::derive_iterated(password, salt, info, params.iterations)
            }
            KdfAlgorithm::HkdfSha512 => {
                // FIX: implement HkdfSha512 properly using SHA-512
                use hkdf::Hkdf;
                use sha2::Sha512;
                let hkdf = Hkdf::<Sha512>::new(Some(salt), password);
                let mut okm = [0u8; KEY_LENGTH];
                hkdf.expand(info, &mut okm)
                    .map_err(|_| CryptoError::KeyDerivationFailed)?;
                Ok(zeroize::Zeroizing::new(okm))
            }
            KdfAlgorithm::SimpleSha256 => SimpleKdf::derive_sha256(password, salt),
            KdfAlgorithm::SimpleSha512 => SimpleKdf::derive_sha512(password, salt),
            #[cfg(feature = "argon2")]
            KdfAlgorithm::Argon2id => Argon2Kdf::derive(
                password,
                salt,
                params.memory_cost,
                params.iterations,
                params.parallelism,
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hkdf_derive() {
        let ikm = b"input key material";
        let salt = b"salt";
        let info = b"info";

        let key = HkdfKdf::derive(ikm, Some(salt), info, 32).unwrap();
        assert_eq!(key.len(), 32);
    }

    #[test]
    fn test_hkdf_derive_multiple() {
        let ikm = b"input key material";
        let salt = b"salt";
        let infos: &[&[u8]] = &[b"key1", b"key2", b"key3"];

        let keys = HkdfKdf::derive_multiple(ikm, salt, infos).unwrap();
        assert_eq!(keys.len(), 3);

        // Keys should be different
        assert_ne!(keys[0], keys[1]);
        assert_ne!(keys[1], keys[2]);
    }

    #[test]
    fn test_ratchet_kdf() {
        let root_key = [0x42u8; 32];
        let dh_out = [0x24u8; 32];

        let (new_rk, new_ck) = RatchetKdf::kdf_rk(&root_key, &dh_out).unwrap();

        assert_ne!(new_rk.as_ref(), &root_key);
        assert_ne!(new_ck.as_ref(), &dh_out);
    }

    #[test]
    fn test_ratchet_kdf_ck() {
        let chain_key = [0x42u8; 32];

        let (mk, next_ck) = RatchetKdf::kdf_ck(&chain_key).unwrap();

        // Message key and next chain key should be different
        assert_ne!(mk.as_ref(), next_ck.as_ref());

        // Should be deterministic
        let (mk2, next_ck2) = RatchetKdf::kdf_ck(&chain_key).unwrap();
        assert_eq!(mk.as_ref(), mk2.as_ref());
        assert_eq!(next_ck.as_ref(), next_ck2.as_ref());
    }

    #[test]
    fn test_x3dh_kdf() {
        let dh1 = [0x01u8; 32];
        let dh2 = [0x02u8; 32];
        let dh3 = [0x03u8; 32];
        let dh4 = [0x04u8; 32];
        let hash = [0x55u8; 32];

        let secret1 = X3dhKdf::derive_shared_secret(&dh1, &dh2, &dh3, Some(&dh4), &hash).unwrap();
        let secret2 = X3dhKdf::derive_shared_secret(&dh1, &dh2, &dh3, None, &hash).unwrap();

        // Should be different when dh4 is included vs not
        assert_ne!(secret1.as_ref(), secret2.as_ref());

        // Should be different with different transcript hash
        let hash2 = [0x66u8; 32];
        let secret3 = X3dhKdf::derive_shared_secret(&dh1, &dh2, &dh3, None, &hash2).unwrap();
        assert_ne!(secret2.as_ref(), secret3.as_ref());
    }

    #[test]
    fn test_simple_kdf() {
        let input = b"password";
        let salt = b"salt";

        let key1 = SimpleKdf::derive_sha256(input, salt).unwrap();
        let key2 = SimpleKdf::derive_sha256(input, salt).unwrap();

        // Should be deterministic
        assert_eq!(key1.as_ref(), key2.as_ref());

        // Different salt should give different key
        let key3 = SimpleKdf::derive_sha256(input, b"different salt").unwrap();
        assert_ne!(key1.as_ref(), key3.as_ref());
    }

    #[test]
    fn test_hkdf_iterations() {
        let ikm = b"password";
        let salt = b"salt";
        let info = b"info";

        let key1 = HkdfKdf::derive_iterated(ikm, salt, info, 1).unwrap();
        let key2 = HkdfKdf::derive_iterated(ikm, salt, info, 1000).unwrap();

        // Different iterations should give different keys
        assert_ne!(key1.as_ref(), key2.as_ref());
    }

    #[test]
    fn test_invalid_output_length() {
        let ikm = b"input";
        let result = HkdfKdf::derive(ikm, None, b"info", 0);
        assert!(result.is_err());

        let result = HkdfKdf::derive(ikm, None, b"info", 10000);
        assert!(result.is_err());
    }
}
