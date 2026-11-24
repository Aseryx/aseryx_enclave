//! The two keys a workload generates in memory for a job: the key the dataset key is sealed to, and the key that signs
//! the result. Both exist only inside the attested container; their public halves are named in the attestation.

use crate::consent::Bytes32;
use hpke::kem::X25519HkdfSha256;
use hpke::{Kem, Serializable};
use k256::ecdsa::{RecoveryId, Signature, SigningKey, VerifyingKey};

/// Why a key could not be made or a signature checked.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum KeyError {
    /// The operating system's random source failed.
    #[error("no random bytes")]
    Random,
    /// A signature is not 65 bytes of r, s and a recovery byte of 27 or 28, or does not recover a key.
    #[error("not a recoverable signature")]
    Signature,
    /// A public key is not 33 compressed secp256k1 bytes in hex.
    #[error("not a compressed secp256k1 public key")]
    PublicKey,
}

fn random32() -> Result<[u8; 32], KeyError> {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).map_err(|_| KeyError::Random)?;
    Ok(bytes)
}

/// The X25519 key pair a dataset key is sealed to (RFC 9180 HPKE, the suite the decrypt action uses).
pub struct ResponseKey {
    private: <X25519HkdfSha256 as Kem>::PrivateKey,
    public: [u8; 32],
}

impl ResponseKey {
    /// Generates a fresh key pair.
    ///
    /// # Errors
    ///
    /// [`KeyError::Random`] if no random bytes are available.
    pub fn generate() -> Result<Self, KeyError> {
        let (private, public) = X25519HkdfSha256::derive_keypair(&random32()?);
        Ok(Self {
            private,
            public: public.to_bytes().into(),
        })
    }

    /// The public key as 64 lower-case hex digits, as runtime data carries it.
    #[must_use]
    pub fn public_hex(&self) -> String {
        hex::encode(self.public)
    }

    /// The private key, for opening a sealed response.
    #[must_use]
    pub fn private(&self) -> &<X25519HkdfSha256 as Kem>::PrivateKey {
        &self.private
    }
}

/// The secp256k1 key that signs a job's result.
pub struct ResultKey {
    signing: SigningKey,
}

impl ResultKey {
    /// Generates a fresh key.
    ///
    /// # Errors
    ///
    /// [`KeyError::Random`] if no random bytes are available.
    pub fn generate() -> Result<Self, KeyError> {
        loop {
            if let Ok(signing) = SigningKey::from_slice(&random32()?) {
                return Ok(Self { signing });
            }
        }
    }

    /// A key from its 32 secret bytes, for tests and fixed vectors.
    ///
    /// # Errors
    ///
    /// [`KeyError::PublicKey`] if the bytes are not a valid secp256k1 secret.
    pub fn from_secret(bytes: &[u8; 32]) -> Result<Self, KeyError> {
        SigningKey::from_slice(bytes)
            .map(|signing| Self { signing })
            .map_err(|_| KeyError::PublicKey)
    }

    /// The public key as 66 lower-case hex digits: a compressed secp256k1 point.
    #[must_use]
    pub fn public_hex(&self) -> String {
        hex::encode(self.signing.verifying_key().to_sec1_point(true).as_bytes())
    }

    /// Signs a 32-byte digest and returns r, s and a recovery byte of 27 or 28, the form ethers recovers from. The
    /// signature is deterministic (RFC 6979), and the curve library returns a low s.
    #[must_use]
    pub fn sign(&self, digest: &Bytes32) -> [u8; 65] {
        let (signature, recovery) = self.signing.sign_prehash_recoverable(&digest.0);
        let mut out = [0u8; 65];
        out[..64].copy_from_slice(&signature.to_bytes());
        out[64] = 27 + recovery.to_byte();
        out
    }
}

/// Checks that `signature` over `digest` was made by the key whose compressed public key is `public_hex`.
///
/// # Errors
///
/// [`KeyError::PublicKey`] for a malformed public key and [`KeyError::Signature`] for a malformed signature. A
/// well-formed signature by another key returns `Ok(false)`.
pub fn verify_result_signature(
    public_hex: &str,
    digest: &Bytes32,
    signature: &[u8; 65],
) -> Result<bool, KeyError> {
    let expected = hex::decode(public_hex).map_err(|_| KeyError::PublicKey)?;
    if expected.len() != 33 || !matches!(expected[0], 2 | 3) {
        return Err(KeyError::PublicKey);
    }
    let recovery = signature[64]
        .checked_sub(27)
        .and_then(RecoveryId::from_byte)
        .ok_or(KeyError::Signature)?;
    let parsed = Signature::from_slice(&signature[..64]).map_err(|_| KeyError::Signature)?;
    let recovered = VerifyingKey::recover_from_prehash(&digest.0, &parsed, recovery)
        .map_err(|_| KeyError::Signature)?;
    Ok(recovered.to_sec1_point(true).as_bytes() == expected.as_slice())
}
