use std::path::{Path, PathBuf};
use std::fs;
use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use crate::error::{DarkTermError, Result};
use crate::identity::PeerId;

/// State manager for crash-safe persistence
pub struct StateManager {
    state_dir: PathBuf,
    pickle_key: [u8; 32],
}

/// Session state for a peer connection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionState {
    pub peer_id: PeerId,
    pub ratchet_state: Vec<u8>, // Pickled ratchet session
    pub message_counter: u64,
    pub last_activity: DateTime<Utc>,
    pub established_at: DateTime<Utc>,
}

/// Message log entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessageLog {
    pub messages: Vec<MessageEntry>,
}

/// Individual message entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessageEntry {
    pub peer_id: PeerId,
    pub direction: MessageDirection,
    pub content: String,
    pub timestamp: DateTime<Utc>,
    pub delivered: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MessageDirection {
    Sent,
    Received,
}

impl StateManager {
    /// Create new state manager
    pub fn new(state_dir: PathBuf, pickle_key: [u8; 32]) -> Result<Self> {
        fs::create_dir_all(&state_dir)
            .map_err(|e| DarkTermError::State(format!("Failed to create state directory: {}", e)))?;

        Ok(Self {
            state_dir,
            pickle_key,
        })
    }

    /// Save session state (crash-safe atomic write)
    pub fn save_session_state(&self, state: &SessionState) -> Result<()> {
        let session_path = self.session_state_path(&state.peer_id);
        let temp_path = session_path.with_extension("tmp");

        // Serialize state
        let data = bincode::serialize(state)
            .map_err(|e| DarkTermError::Serialization(format!("Failed to serialize session state: {}", e)))?;

        // Write to temp file
        fs::write(&temp_path, data)
            .map_err(|e| DarkTermError::State(format!("Failed to write session state: {}", e)))?;

        // Atomic rename
        fs::rename(&temp_path, &session_path)
            .map_err(|e| DarkTermError::State(format!("Failed to finalize session state: {}", e)))?;

        // Sync to disk (ensure durability)
        Self::sync_directory(&self.state_dir)?;

        Ok(())
    }

    /// Load session state
    pub fn load_session_state(&self, peer_id: &PeerId) -> Result<Option<SessionState>> {
        let session_path = self.session_state_path(peer_id);

        if !session_path.exists() {
            return Ok(None);
        }

        let data = fs::read(&session_path)
            .map_err(|e| DarkTermError::State(format!("Failed to read session state: {}", e)))?;

        let state: SessionState = bincode::deserialize(&data)
            .map_err(|e| DarkTermError::Serialization(format!("Failed to deserialize session state: {}", e)))?;

        Ok(Some(state))
    }

    /// Delete session state
    pub fn delete_session_state(&self, peer_id: &PeerId) -> Result<()> {
        let session_path = self.session_state_path(peer_id);

        if session_path.exists() {
            fs::remove_file(&session_path)
                .map_err(|e| DarkTermError::State(format!("Failed to delete session state: {}", e)))?;
        }

        Ok(())
    }

    /// List all session states
    pub fn list_sessions(&self) -> Result<Vec<PeerId>> {
        let mut sessions = Vec::new();

        let entries = fs::read_dir(&self.state_dir)
            .map_err(|e| DarkTermError::State(format!("Failed to read state directory: {}", e)))?;

        for entry in entries {
            let entry = entry
                .map_err(|e| DarkTermError::State(format!("Failed to read directory entry: {}", e)))?;

            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) == Some("session") {
                if let Some(stem) = path.file_stem().and_then(|s| s.to_str()) {
                    sessions.push(PeerId::from_string(stem.to_string()));
                }
            }
        }

        Ok(sessions)
    }

    /// Append message to log (crash-safe)
    pub fn append_message(&self, entry: MessageEntry) -> Result<()> {
        let log_path = self.message_log_path();
        let temp_path = log_path.with_extension("tmp");

        // Load existing log
        let mut log = self.load_message_log()?;
        log.messages.push(entry);

        // Serialize
        let data = bincode::serialize(&log)
            .map_err(|e| DarkTermError::Serialization(format!("Failed to serialize message log: {}", e)))?;

        // Write to temp file
        fs::write(&temp_path, data)
            .map_err(|e| DarkTermError::State(format!("Failed to write message log: {}", e)))?;

        // Atomic rename
        fs::rename(&temp_path, &log_path)
            .map_err(|e| DarkTermError::State(format!("Failed to finalize message log: {}", e)))?;

        // Sync to disk
        Self::sync_directory(&self.state_dir)?;

        Ok(())
    }

    /// Load message log
    pub fn load_message_log(&self) -> Result<MessageLog> {
        let log_path = self.message_log_path();

        if !log_path.exists() {
            return Ok(MessageLog { messages: Vec::new() });
        }

        let data = fs::read(&log_path)
            .map_err(|e| DarkTermError::State(format!("Failed to read message log: {}", e)))?;

        let log: MessageLog = bincode::deserialize(&data)
            .map_err(|e| DarkTermError::Serialization(format!("Failed to deserialize message log: {}", e)))?;

        Ok(log)
    }

    /// Get messages for a specific peer
    pub fn get_peer_messages(&self, peer_id: &PeerId) -> Result<Vec<MessageEntry>> {
        let log = self.load_message_log()?;
        Ok(log.messages.into_iter()
            .filter(|m| &m.peer_id == peer_id)
            .collect())
    }

    /// Sync directory to ensure durability
    fn sync_directory(dir: &Path) -> Result<()> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            use std::os::unix::io::AsRawFd;

            let file = std::fs::OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_DIRECTORY)
                .open(dir)
                .map_err(|e| DarkTermError::State(format!("Failed to open directory for sync: {}", e)))?;

            // fsync the directory fd
            unsafe {
                if libc::fsync(file.as_raw_fd()) != 0 {
                    return Err(DarkTermError::State("Failed to sync directory".to_string()));
                }
            }
        }

        Ok(())
    }

    /// Get session state file path
    fn session_state_path(&self, peer_id: &PeerId) -> PathBuf {
        self.state_dir.join(format!("{}.session", peer_id.as_str()))
    }

    /// Get message log file path
    fn message_log_path(&self) -> PathBuf {
        self.state_dir.join("messages.log")
    }

    /// Get pickle key for session encryption
    pub fn pickle_key(&self) -> &[u8; 32] {
        &self.pickle_key
    }
}

impl MessageLog {
    pub fn new() -> Self {
        Self { messages: Vec::new() }
    }

    pub fn add_message(&mut self, entry: MessageEntry) {
        self.messages.push(entry);
    }

    pub fn get_recent(&self, count: usize) -> Vec<&MessageEntry> {
        self.messages.iter().rev().take(count).collect()
    }
}

impl MessageEntry {
    pub fn new_sent(peer_id: PeerId, content: String) -> Self {
        Self {
            peer_id,
            direction: MessageDirection::Sent,
            content,
            timestamp: Utc::now(),
            delivered: false,
        }
    }

    pub fn new_received(peer_id: PeerId, content: String) -> Self {
        Self {
            peer_id,
            direction: MessageDirection::Received,
            content,
            timestamp: Utc::now(),
            delivered: true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    use crate::identity::Identity;

    #[test]
    fn test_session_state_persistence() {
        let temp_dir = TempDir::new().unwrap();
        let pickle_key = [0u8; 32];
        let state_manager = StateManager::new(temp_dir.path().to_path_buf(), pickle_key).unwrap();

        let identity = Identity::generate();
        let peer_id = identity.peer_id().clone();

        let session_state = SessionState {
            peer_id: peer_id.clone(),
            ratchet_state: vec![1, 2, 3, 4],
            message_counter: 42,
            last_activity: Utc::now(),
            established_at: Utc::now(),
        };

        // Save
        state_manager.save_session_state(&session_state).unwrap();

        // Load
        let loaded = state_manager.load_session_state(&peer_id).unwrap();
        assert!(loaded.is_some());
        let loaded = loaded.unwrap();
        assert_eq!(loaded.message_counter, 42);
        assert_eq!(loaded.ratchet_state, vec![1, 2, 3, 4]);
    }

    #[test]
    fn test_message_log() {
        let temp_dir = TempDir::new().unwrap();
        let pickle_key = [0u8; 32];
        let state_manager = StateManager::new(temp_dir.path().to_path_buf(), pickle_key).unwrap();

        let identity = Identity::generate();
        let peer_id = identity.peer_id().clone();

        let entry = MessageEntry::new_sent(peer_id.clone(), "Hello, World!".to_string());

        // Append message
        state_manager.append_message(entry).unwrap();

        // Load log
        let log = state_manager.load_message_log().unwrap();
        assert_eq!(log.messages.len(), 1);
        assert_eq!(log.messages[0].content, "Hello, World!");
    }
}
