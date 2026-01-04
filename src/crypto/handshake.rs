use x25519_dalek::{PublicKey, StaticSecret};
use rand::rngs::OsRng;
use sha2::{Sha256, Digest};
use serde::{Deserialize, Serialize};
use crate::error::{DarkTermError, Result};
use crate::identity::{Identity, PeerId};

/// X3DH handshake implementation for session establishment
/// Based on Signal's Extended Triple Diffie-Hellman protocol
pub struct X3DHHandshake;

/// Pre-key bundle published by recipient
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreKeyBundle {
    pub peer_id: PeerId,
    pub identity_key: [u8; 32], // Long-term public key
    pub signed_pre_key: [u8; 32], // Medium-term public key
    pub one_time_pre_key: Option<[u8; 32]>, // Optional one-time key
    pub signature: Vec<u8>, // Signature of signed_pre_key
}

/// Initiator side of X3DH handshake
pub struct HandshakeInitiator {
    identity_secret: StaticSecret,
    ephemeral_secret: StaticSecret,
}

/// Responder side of X3DH handshake
pub struct HandshakeResponder {
    identity_secret: StaticSecret,
    signed_pre_key_secret: StaticSecret,
    one_time_pre_key_secret: Option<StaticSecret>,
}

/// Initial handshake message sent by initiator
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HandshakeMessage {
    pub initiator_peer_id: PeerId,
    pub initiator_identity_key: [u8; 32],
    pub initiator_ephemeral_key: [u8; 32],
    pub used_one_time_key: bool,
}

impl X3DHHandshake {
    /// Create pre-key bundle for publishing
    pub fn create_pre_key_bundle(
        identity: &Identity,
        signed_pre_key_secret: &StaticSecret,
        one_time_pre_key_secret: Option<&StaticSecret>,
    ) -> Result<(PreKeyBundle, StaticSecret, Option<StaticSecret>)> {
        let identity_key = Self::identity_to_x25519_public(identity);
        let signed_pre_key = PublicKey::from(signed_pre_key_secret).to_bytes();

        // Sign the signed_pre_key with identity
        let signature = identity.sign(&signed_pre_key);

        let one_time_pre_key = one_time_pre_key_secret.map(|s| PublicKey::from(s).to_bytes());

        let bundle = PreKeyBundle {
            peer_id: identity.peer_id().clone(),
            identity_key,
            signed_pre_key,
            one_time_pre_key,
            signature: signature.to_vec(),
        };

        Ok((
            bundle,
            signed_pre_key_secret.clone(),
            one_time_pre_key_secret.cloned(),
        ))
    }

    /// Verify pre-key bundle signature
    pub fn verify_pre_key_bundle(bundle: &PreKeyBundle, identity: &Identity) -> Result<()> {
        let signature = ed25519_dalek::Signature::from_slice(&bundle.signature)
            .map_err(|e| DarkTermError::Crypto(format!("Invalid signature format: {}", e)))?;

        identity.verify(&bundle.signed_pre_key, &signature)?;
        Ok(())
    }

    /// Convert Ed25519 identity to X25519 public key for DH
    fn identity_to_x25519_public(identity: &Identity) -> [u8; 32] {
        // In production, use proper Ed25519->X25519 conversion
        // For now, hash the public key (simplified)
        let mut hasher = Sha256::new();
        hasher.update(identity.public_key().as_bytes());
        let hash = hasher.finalize();
        let mut key = [0u8; 32];
        key.copy_from_slice(&hash);
        key
    }

    /// Convert Ed25519 identity to X25519 secret key for DH
    fn identity_to_x25519_secret(identity: &Identity) -> StaticSecret {
        // In production, use proper Ed25519->X25519 conversion
        // For now, hash the signing key (simplified)
        let mut hasher = Sha256::new();
        hasher.update(&identity.signing_key_bytes());
        let hash = hasher.finalize();
        let mut key = [0u8; 32];
        key.copy_from_slice(&hash);
        StaticSecret::from(key)
    }
}

impl HandshakeInitiator {
    /// Create new handshake initiator
    pub fn new(identity: &Identity) -> Self {
        let identity_secret = X3DHHandshake::identity_to_x25519_secret(identity);
        let ephemeral_secret = StaticSecret::random_from_rng(OsRng);

        Self {
            identity_secret,
            ephemeral_secret,
        }
    }

    /// Perform X3DH and generate shared secret
    pub fn perform_handshake(
        &self,
        initiator_identity: &Identity,
        bundle: &PreKeyBundle,
    ) -> Result<([u8; 32], HandshakeMessage)> {
        // X3DH key agreement: DH1 || DH2 || DH3 || (DH4)
        // DH1 = DH(IK_A, SPK_B)
        // DH2 = DH(EK_A, IK_B)
        // DH3 = DH(EK_A, SPK_B)
        // DH4 = DH(EK_A, OPK_B) [optional]

        let recipient_identity_key = PublicKey::from(bundle.identity_key);
        let recipient_signed_pre_key = PublicKey::from(bundle.signed_pre_key);

        // DH1: identity_secret × signed_pre_key
        let dh1 = self.identity_secret.diffie_hellman(&recipient_signed_pre_key);

        // DH2: ephemeral_secret × identity_key
        let dh2 = self.ephemeral_secret.diffie_hellman(&recipient_identity_key);

        // DH3: ephemeral_secret × signed_pre_key
        let dh3 = self.ephemeral_secret.diffie_hellman(&recipient_signed_pre_key);

        // DH4 (optional): ephemeral_secret × one_time_pre_key
        let dh4 = bundle.one_time_pre_key.as_ref().map(|otpk| {
            let otpk_public = PublicKey::from(*otpk);
            self.ephemeral_secret.diffie_hellman(&otpk_public)
        });

        // Derive shared secret: KDF(DH1 || DH2 || DH3 || DH4)
        let mut kdf_input = Vec::new();
        kdf_input.extend_from_slice(dh1.as_bytes());
        kdf_input.extend_from_slice(dh2.as_bytes());
        kdf_input.extend_from_slice(dh3.as_bytes());
        if let Some(ref dh4) = dh4 {
            kdf_input.extend_from_slice(dh4.as_bytes());
        }

        let mut hasher = Sha256::new();
        hasher.update(&kdf_input);
        let shared_secret_hash = hasher.finalize();
        let mut shared_secret = [0u8; 32];
        shared_secret.copy_from_slice(&shared_secret_hash);

        // Create handshake message
        let message = HandshakeMessage {
            initiator_peer_id: initiator_identity.peer_id().clone(),
            initiator_identity_key: PublicKey::from(&self.identity_secret).to_bytes(),
            initiator_ephemeral_key: PublicKey::from(&self.ephemeral_secret).to_bytes(),
            used_one_time_key: dh4.is_some(),
        };

        Ok((shared_secret, message))
    }
}

impl HandshakeResponder {
    /// Create new handshake responder
    pub fn new(
        identity: &Identity,
        signed_pre_key_secret: StaticSecret,
        one_time_pre_key_secret: Option<StaticSecret>,
    ) -> Self {
        let identity_secret = X3DHHandshake::identity_to_x25519_secret(identity);

        Self {
            identity_secret,
            signed_pre_key_secret,
            one_time_pre_key_secret,
        }
    }

    /// Process handshake message and derive shared secret
    pub fn process_handshake(&self, message: &HandshakeMessage) -> Result<[u8; 32]> {
        let initiator_identity_key = PublicKey::from(message.initiator_identity_key);
        let initiator_ephemeral_key = PublicKey::from(message.initiator_ephemeral_key);

        // Perform same DH operations as initiator (but in reverse)
        // DH1 = DH(SPK_B, IK_A)
        let dh1 = self.signed_pre_key_secret.diffie_hellman(&initiator_identity_key);

        // DH2 = DH(IK_B, EK_A)
        let dh2 = self.identity_secret.diffie_hellman(&initiator_ephemeral_key);

        // DH3 = DH(SPK_B, EK_A)
        let dh3 = self.signed_pre_key_secret.diffie_hellman(&initiator_ephemeral_key);

        // DH4 (optional)
        let dh4 = if message.used_one_time_key {
            self.one_time_pre_key_secret.as_ref().map(|otpk| {
                otpk.diffie_hellman(&initiator_ephemeral_key)
            })
        } else {
            None
        };

        // Derive shared secret
        let mut kdf_input = Vec::new();
        kdf_input.extend_from_slice(dh1.as_bytes());
        kdf_input.extend_from_slice(dh2.as_bytes());
        kdf_input.extend_from_slice(dh3.as_bytes());
        if let Some(ref dh4) = dh4 {
            kdf_input.extend_from_slice(dh4.as_bytes());
        }

        let mut hasher = Sha256::new();
        hasher.update(&kdf_input);
        let shared_secret_hash = hasher.finalize();
        let mut shared_secret = [0u8; 32];
        shared_secret.copy_from_slice(&shared_secret_hash);

        Ok(shared_secret)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::Identity;

    #[test]
    fn test_x3dh_handshake() {
        // Setup responder (Bob)
        let bob_identity = Identity::generate();
        let bob_signed_pre_key = StaticSecret::random_from_rng(OsRng);
        let bob_one_time_pre_key = Some(StaticSecret::random_from_rng(OsRng));

        let (bundle, spk_secret, otpk_secret) = X3DHHandshake::create_pre_key_bundle(
            &bob_identity,
            &bob_signed_pre_key,
            bob_one_time_pre_key.as_ref(),
        ).unwrap();

        // Setup initiator (Alice)
        let alice_identity = Identity::generate();
        let alice_initiator = HandshakeInitiator::new(&alice_identity);

        // Alice performs handshake
        let (alice_shared_secret, handshake_msg) = alice_initiator
            .perform_handshake(&alice_identity, &bundle)
            .unwrap();

        // Bob processes handshake
        let bob_responder = HandshakeResponder::new(
            &bob_identity,
            spk_secret,
            otpk_secret,
        );

        let bob_shared_secret = bob_responder.process_handshake(&handshake_msg).unwrap();

        // Both should derive the same shared secret
        assert_eq!(alice_shared_secret, bob_shared_secret);
    }
}
