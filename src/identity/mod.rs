pub mod keystore;

use ed25519_dalek::{SigningKey, VerifyingKey, Signature, Signer, Verifier};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sha2::{Sha256, Digest};
use crate::error::{DarkTermError, Result};

/// Persistent Ed25519 identity for peer authentication
#[derive(Clone)]
pub struct Identity {
    signing_key: SigningKey,
    verifying_key: VerifyingKey,
    peer_id: PeerId,
}

/// Unique peer identifier derived from public key
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PeerId(pub String);

/// Human-readable fingerprint for TOFU verification
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Fingerprint(pub String);

impl Identity {
    /// Generate a new cryptographic identity
    pub fn generate() -> Self {
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        let peer_id = PeerId::from_public_key(&verifying_key);

        Self {
            signing_key,
            verifying_key,
            peer_id,
        }
    }

    /// Create identity from existing signing key
    pub fn from_signing_key(signing_key: SigningKey) -> Self {
        let verifying_key = signing_key.verifying_key();
        let peer_id = PeerId::from_public_key(&verifying_key);

        Self {
            signing_key,
            verifying_key,
            peer_id,
        }
    }

    /// Get the peer ID
    pub fn peer_id(&self) -> &PeerId {
        &self.peer_id
    }

    /// Get the public key
    pub fn public_key(&self) -> &VerifyingKey {
        &self.verifying_key
    }

    /// Get the signing key bytes (sensitive!)
    pub fn signing_key_bytes(&self) -> [u8; 32] {
        self.signing_key.to_bytes()
    }

    /// Generate fingerprint for TOFU verification
    pub fn fingerprint(&self) -> Fingerprint {
        Fingerprint::from_public_key(&self.verifying_key)
    }

    /// Sign a message
    pub fn sign(&self, message: &[u8]) -> Signature {
        self.signing_key.sign(message)
    }

    /// Verify a signature
    pub fn verify(&self, message: &[u8], signature: &Signature) -> Result<()> {
        self.verifying_key
            .verify(message, signature)
            .map_err(|e| DarkTermError::Crypto(format!("Signature verification failed: {}", e)))
    }
}

impl PeerId {
    /// Derive peer ID from public key
    pub fn from_public_key(public_key: &VerifyingKey) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(public_key.as_bytes());
        let hash = hasher.finalize();
        PeerId(hex::encode(&hash[..16])) // First 16 bytes = 32 hex chars
    }

    /// Create from raw string (for deserialization)
    pub fn from_string(s: String) -> Self {
        PeerId(s)
    }

    /// Get the string representation
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Fingerprint {
    /// Generate human-readable fingerprint from public key
    /// Format: "XXXX-XXXX-XXXX-XXXX" (16 hex chars, grouped for readability)
    pub fn from_public_key(public_key: &VerifyingKey) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(public_key.as_bytes());
        let hash = hasher.finalize();

        // Take first 8 bytes and format as XXXX-XXXX-XXXX-XXXX
        let hex_str = hex::encode(&hash[..8]);
        let formatted = format!(
            "{}-{}-{}-{}",
            &hex_str[0..4],
            &hex_str[4..8],
            &hex_str[8..12],
            &hex_str[12..16]
        );

        Fingerprint(formatted)
    }

    /// Get the fingerprint string
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for PeerId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::fmt::Display for Fingerprint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

// Add hex crate to Cargo.toml
