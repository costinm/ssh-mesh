// Auth module - provides authentication for both SSH and mTLS

mod keys;
mod ssh;
mod tls;
mod x509;

// Re-export commonly used items
pub use keys::*;
pub use ssh::*;
pub use tls::*;
pub use x509::*;

use russh::server;

/// Unified authentication result for both SSH and X.509
#[derive(Debug, Clone)]
pub struct AuthResult {
    pub accepted: bool,
    pub identity: String,
    pub options: Option<String>,
}

impl AuthResult {
    pub fn accept(identity: impl Into<String>, options: Option<String>) -> Self {
        Self {
            accepted: true,
            identity: identity.into(),
            options,
        }
    }

    pub fn reject() -> Self {
        Self {
            accepted: false,
            identity: String::new(),
            options: None,
        }
    }
}

/// SSH-specific auth result that wraps AuthResult with russh types
pub struct SshAuthResult {
    pub status: server::Auth,
    pub comment: String,
    pub options: Option<String>,
}

impl SshAuthResult {
    pub fn into_auth_result(self) -> AuthResult {
        AuthResult {
            accepted: matches!(self.status, server::Auth::Accept),
            identity: self.comment,
            options: self.options,
        }
    }
}
