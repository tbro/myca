mod cert;
pub use cert::{BuildParams, Cert};
mod chain;
pub use chain::CertChain;

/// A specialized `Result` type.
pub type Result<T> = std::result::Result<T, Error>;
/// This is defined as a convenience.
pub type Error = Box<dyn std::error::Error + Send + Sync>;
