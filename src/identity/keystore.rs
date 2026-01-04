use std::path::{Path, PathBuf};
use std::fs;
use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};
use directories::ProjectDirs;
use crate::error::{DarkTermError, Result};
use super::{Identity, PeerId, Fingerprint};

/// Persistent keystore for identity management
pub struct Keystore {
    path: PathBuf,
}

/// Serializable identity container
#[derive(Serialize, Deserialize)]
struct IdentityContainer {
    signing_key_bytes: [u8; 32],
    peer_id: String,
    fingerprint: String,
}

/// Trust database for TOFU fingerprint pinning
#[derive(Serialize, Deserialize, Default)]
pub struct TrustDb {
    /// Map of PeerId -> Pinned Fingerprint
    pinned_fingerprints: std::collections::HashMap<String, String>,
}

impl Keystore {
    /// Create keystore with default system path
    pub fn new() -> Result<Self> {
        let path = Self::default_path()?;
        fs::create_dir_all(&path)
            .map_err(|e| DarkTermError::State(format!("Failed to create keystore directory: {}", e)))?;

        Ok(Self { path })
    }

    /// Create keystore with custom path
    pub fn with_path(path: PathBuf) -> Result<Self> {
        fs::create_dir_all(&path)
            .map_err(|e| DarkTermError::State(format!("Failed to create keystore directory: {}", e)))?;

        Ok(Self { path })
    }

    /// Get default keystore path: ~/.local/share/darkterm/ (Linux)
    fn default_path() -> Result<PathBuf> {
        ProjectDirs::from("com", "darkterm", "DarkTerm")
            .map(|proj_dirs| proj_dirs.data_dir().to_path_buf())
            .ok_or_else(|| DarkTermError::State("Failed to determine home directory".to_string()))
    }

    /// Load or create identity
    pub fn load_or_create_identity(&self) -> Result<Identity> {
        let identity_path = self.path.join("identity.json");

        if identity_path.exists() {
            self.load_identity(&identity_path)
        } else {
            let identity = Identity::generate();
            self.save_identity(&identity, &identity_path)?;
            Ok(identity)
        }
    }

    /// Load identity from disk
    fn load_identity(&self, path: &Path) -> Result<Identity> {
        let data = fs::read_to_string(path)
            .map_err(|e| DarkTermError::State(format!("Failed to read identity file: {}", e)))?;

        let container: IdentityContainer = serde_json::from_str(&data)
            .map_err(|e| DarkTermError::Serialization(format!("Failed to deserialize identity: {}", e)))?;

        let signing_key = SigningKey::from_bytes(&container.signing_key_bytes);
        Ok(Identity::from_signing_key(signing_key))
    }

    /// Save identity to disk
    fn save_identity(&self, identity: &Identity, path: &Path) -> Result<()> {
        let container = IdentityContainer {
            signing_key_bytes: identity.signing_key_bytes(),
            peer_id: identity.peer_id().as_str().to_string(),
            fingerprint: identity.fingerprint().as_str().to_string(),
        };

        let data = serde_json::to_string_pretty(&container)
            .map_err(|e| DarkTermError::Serialization(format!("Failed to serialize identity: {}", e)))?;

        // Atomic write: write to temp file, then rename
        let temp_path = path.with_extension("tmp");
        fs::write(&temp_path, data)
            .map_err(|e| DarkTermError::State(format!("Failed to write identity file: {}", e)))?;

        fs::rename(&temp_path, path)
            .map_err(|e| DarkTermError::State(format!("Failed to finalize identity file: {}", e)))?;

        // Set restrictive permissions (Unix only)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = fs::metadata(path)
                .map_err(|e| DarkTermError::State(format!("Failed to get file metadata: {}", e)))?
                .permissions();
            perms.set_mode(0o600); // Owner read/write only
            fs::set_permissions(path, perms)
                .map_err(|e| DarkTermError::State(format!("Failed to set permissions: {}", e)))?;
        }

        Ok(())
    }

    /// Load trust database
    pub fn load_trust_db(&self) -> Result<TrustDb> {
        let trust_path = self.path.join("trust.json");

        if trust_path.exists() {
            let data = fs::read_to_string(&trust_path)
                .map_err(|e| DarkTermError::State(format!("Failed to read trust database: {}", e)))?;

            serde_json::from_str(&data)
                .map_err(|e| DarkTermError::Serialization(format!("Failed to deserialize trust database: {}", e)))
        } else {
            Ok(TrustDb::default())
        }
    }

    /// Save trust database
    pub fn save_trust_db(&self, trust_db: &TrustDb) -> Result<()> {
        let trust_path = self.path.join("trust.json");
        let temp_path = trust_path.with_extension("tmp");

        let data = serde_json::to_string_pretty(trust_db)
            .map_err(|e| DarkTermError::Serialization(format!("Failed to serialize trust database: {}", e)))?;

        fs::write(&temp_path, data)
            .map_err(|e| DarkTermError::State(format!("Failed to write trust database: {}", e)))?;

        fs::rename(&temp_path, &trust_path)
            .map_err(|e| DarkTermError::State(format!("Failed to finalize trust database: {}", e)))?;

        Ok(())
    }

    /// Get keystore path
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl TrustDb {
    /// Pin a fingerprint for a peer (TOFU)
    pub fn pin_fingerprint(&mut self, peer_id: &PeerId, fingerprint: &Fingerprint) {
        self.pinned_fingerprints.insert(
            peer_id.as_str().to_string(),
            fingerprint.as_str().to_string(),
        );
    }

    /// Verify fingerprint matches pinned value
    pub fn verify_fingerprint(&self, peer_id: &PeerId, fingerprint: &Fingerprint) -> Result<()> {
        match self.pinned_fingerprints.get(peer_id.as_str()) {
            Some(pinned) if pinned == fingerprint.as_str() => Ok(()),
            Some(pinned) => Err(DarkTermError::TrustViolation(format!(
                "Fingerprint mismatch for peer {}. Expected: {}, Got: {}. POSSIBLE MITM ATTACK!",
                peer_id, pinned, fingerprint
            ))),
            None => {
                // First contact - fingerprint not yet pinned
                Ok(())
            }
        }
    }

    /// Check if peer is known (fingerprint is pinned)
    pub fn is_peer_known(&self, peer_id: &PeerId) -> bool {
        self.pinned_fingerprints.contains_key(peer_id.as_str())
    }

    /// Get pinned fingerprint for a peer
    pub fn get_pinned_fingerprint(&self, peer_id: &PeerId) -> Option<Fingerprint> {
        self.pinned_fingerprints
            .get(peer_id.as_str())
            .map(|s| Fingerprint(s.clone()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_keystore_create_and_load() {
        let temp_dir = TempDir::new().unwrap();
        let keystore = Keystore::with_path(temp_dir.path().to_path_buf()).unwrap();

        // Create new identity
        let identity1 = keystore.load_or_create_identity().unwrap();
        let peer_id1 = identity1.peer_id().clone();

        // Load existing identity
        let identity2 = keystore.load_or_create_identity().unwrap();
        let peer_id2 = identity2.peer_id();

        assert_eq!(peer_id1, *peer_id2);
    }

    #[test]
    fn test_trust_db_tofu() {
        let temp_dir = TempDir::new().unwrap();
        let keystore = Keystore::with_path(temp_dir.path().to_path_buf()).unwrap();
        let mut trust_db = TrustDb::default();

        let identity = Identity::generate();
        let peer_id = identity.peer_id();
        let fingerprint = identity.fingerprint();

        // First contact - should succeed
        assert!(!trust_db.is_peer_known(peer_id));
        trust_db.pin_fingerprint(peer_id, &fingerprint);

        // Verify pinned fingerprint
        assert!(trust_db.is_peer_known(peer_id));
        assert!(trust_db.verify_fingerprint(peer_id, &fingerprint).is_ok());

        // Save and reload
        keystore.save_trust_db(&trust_db).unwrap();
        let loaded_trust_db = keystore.load_trust_db().unwrap();

        assert!(loaded_trust_db.verify_fingerprint(peer_id, &fingerprint).is_ok());
    }

    #[test]
    fn test_trust_violation_detection() {
        let mut trust_db = TrustDb::default();

        let identity1 = Identity::generate();
        let identity2 = Identity::generate();

        let peer_id = identity1.peer_id();
        let fingerprint1 = identity1.fingerprint();
        let fingerprint2 = identity2.fingerprint();

        // Pin first fingerprint
        trust_db.pin_fingerprint(peer_id, &fingerprint1);

        // Verify with correct fingerprint
        assert!(trust_db.verify_fingerprint(peer_id, &fingerprint1).is_ok());

        // Verify with wrong fingerprint - should detect MITM
        let result = trust_db.verify_fingerprint(peer_id, &fingerprint2);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("MITM"));
    }
}
