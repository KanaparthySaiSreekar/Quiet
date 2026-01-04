use thiserror::Error;

/// Core error types for DarkTerm
#[derive(Error, Debug)]
pub enum DarkTermError {
    #[error("Identity error: {0}")]
    Identity(String),

    #[error("Cryptographic error: {0}")]
    Crypto(String),

    #[error("Network error: {0}")]
    Network(String),

    #[error("State persistence error: {0}")]
    State(String),

    #[error("Protocol error: {0}")]
    Protocol(String),

    #[error("Trust violation: {0}")]
    TrustViolation(String),

    #[error("Session error: {0}")]
    Session(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Serialization error: {0}")]
    Serialization(String),

    #[error("UI error: {0}")]
    Ui(String),
}

pub type Result<T> = std::result::Result<T, DarkTermError>;
