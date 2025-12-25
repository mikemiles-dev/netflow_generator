use std::error::Error as StdError;
use thiserror::Error;

/// Custom error types for the NetFlow generator
#[derive(Error, Debug)]
pub enum NetflowError {
    /// YAML parsing errors
    #[error("Failed to parse YAML: {0}")]
    YamlParse(#[from] serde_yaml::Error),

    /// File I/O errors
    #[error("File I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Network transmission errors
    #[error("Network error: {0}")]
    Network(String),

    /// Validation errors
    #[error("Validation error: {0}")]
    Validation(String),

    /// Packet generation errors
    #[error("Packet generation error: {0}")]
    Generation(String),

    /// Invalid destination address
    #[error("Invalid destination address: {0}")]
    InvalidDestination(String),

    /// NetFlow parser errors
    #[error("NetFlow parser error: {0}")]
    ParserError(#[from] Box<dyn StdError>),
}

/// Result type alias for convenience
pub type Result<T> = std::result::Result<T, NetflowError>;
