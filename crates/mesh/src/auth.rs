//! Authorization configuration for UDS connections.
//!
//! Defines peer identity types, delegation patterns, and allowlist-based
//! authorization. Supports both standalone `auth.toml` files and embedded
//! `[[peer]]` sections in service TOML configs.
//!
//! # Delegation
//!
//! A peer with a `delegate` pattern is trusted to assert identities on behalf
//! of the real peer. The pattern constrains what identities can be asserted:
//! - `*` — any identity
//! - `*.example.com` — id values that are subdomains of `example.com`,
//!   and email addresses `@example.com` or `@*.example.com`

use serde::{Deserialize, Serialize};
use tracing::warn;

// ============================================================================
// Config Types (TOML)
// ============================================================================

/// Top-level auth config, loaded from `auth.toml` or constructed from
/// `[[peer]]` entries in a service TOML.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct AuthConfig {
    /// Authorized peer entries.
    #[serde(default, rename = "peer")]
    pub peers: Vec<PeerConfig>,
    /// Explicit identity impersonation rules.
    #[serde(default, rename = "impersonation")]
    pub impersonation: Vec<ImpersonationRule>,
}

/// A single `[[peer]]` entry in the auth config.
///
/// At least one of `uid`, `id`, or `email` should be set.
/// If `delegate` is set, this peer is trusted to assert identities
/// on behalf of others, constrained by the delegate pattern.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct PeerConfig {
    /// Local Unix UID. Verified via `SO_PEERCRED` on UDS connections.
    pub uid: Option<u32>,
    /// Workload identity as a FQDN (e.g., `worker-1.mesh.local`).
    pub id: Option<String>,
    /// Email identity, typically from JWT/OAuth.
    pub email: Option<String>,
    /// Delegation pattern. If set, this peer can assert identities
    /// matching the pattern. Examples: `*`, `*.mesh.local`.
    pub delegate: Option<String>,
}

/// A single identity impersonation rule.
///
/// `from` is an authenticated identity, such as a certificate principal.
/// `to` is the requested identity that `from` may act as. Both fields accept
/// exact values and the same wildcard style used by delegate patterns.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct ImpersonationRule {
    pub from: String,
    pub to: String,
}

// ============================================================================
// Runtime Types
// ============================================================================

/// Runtime peer identity, resolved from direct connection or delegation.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct PeerIdentity {
    /// Workload identity (FQDN).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    /// Email identity.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    /// Source IP address.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ip: Option<String>,
    /// Local UID (set for direct UDS connections).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uid: Option<u32>,
}

/// JSON envelope sent by a delegate as the first line on a connection.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DelegationEnvelope {
    /// The asserted peer identity.
    pub peer: PeerIdentity,
}

// ============================================================================
// AuthConfig Methods
// ============================================================================

impl AuthConfig {
    /// Check if a UID is authorized to connect directly.
    ///
    /// Root (UID 0) and the daemon's own UID (`current_uid`) are always
    /// authorized. Otherwise the UID must appear in a `[[peer]]` entry.
    pub fn is_uid_authorized(&self, uid: u32, current_uid: u32) -> bool {
        if uid == 0 || uid == current_uid {
            return true;
        }
        self.peers.iter().any(|p| p.uid == Some(uid))
    }

    /// Get the delegate pattern for a UID, if this UID is a trusted delegate.
    ///
    /// Returns `Some(pattern)` if the UID matches a `[[peer]]` entry with
    /// a `delegate` field set.
    pub fn get_delegate(&self, uid: u32) -> Option<&str> {
        self.peers.iter().find_map(|p| {
            if p.uid == Some(uid) {
                p.delegate.as_deref()
            } else {
                None
            }
        })
    }

    /// Check if a `PeerIdentity` is allowed by the peer allowlist.
    ///
    /// If no `[[peer]]` entries define `id` or `email` fields (i.e., the
    /// allowlist only contains UID entries or is empty), all delegated
    /// identities are accepted.
    ///
    /// Otherwise, the identity's `id` or `email` must match at least one
    /// `[[peer]]` entry.
    pub fn is_peer_allowed(&self, identity: &PeerIdentity) -> bool {
        let has_identity_rules = self
            .peers
            .iter()
            .any(|p| p.id.is_some() || p.email.is_some());
        if !has_identity_rules {
            // No identity-based rules — accept all delegated identities.
            return true;
        }

        self.peers.iter().any(|p| {
            if let (Some(ref peer_id), Some(ref rule_id)) = (&identity.id, &p.id) {
                if peer_id == rule_id {
                    return true;
                }
            }
            if let (Some(ref peer_email), Some(ref rule_email)) = (&identity.email, &p.email) {
                if peer_email == rule_email {
                    return true;
                }
            }
            false
        })
    }

    /// Validate that a delegate (identified by UID) is allowed to assert
    /// the given identity.
    ///
    /// Returns `Ok(())` if the delegation is valid, or `Err` with a reason.
    pub fn validate_delegation(
        &self,
        delegate_uid: u32,
        identity: &PeerIdentity,
    ) -> Result<(), String> {
        let pattern = self
            .get_delegate(delegate_uid)
            .ok_or_else(|| format!("UID {} is not a delegate", delegate_uid))?;

        // Validate id
        if let Some(ref id) = identity.id {
            if !matches_delegate_pattern(pattern, id) {
                return Err(format!(
                    "delegate pattern '{}' does not allow id '{}'",
                    pattern, id
                ));
            }
        }

        // Validate email domain
        if let Some(ref email) = identity.email {
            if let Some(domain) = email.rsplit_once('@').map(|(_, d)| d) {
                if !matches_delegate_pattern(pattern, domain) {
                    return Err(format!(
                        "delegate pattern '{}' does not allow email domain '{}'",
                        pattern, domain
                    ));
                }
            } else {
                return Err(format!("invalid email address: '{}'", email));
            }
        }

        // Must assert at least id or email
        if identity.id.is_none() && identity.email.is_none() {
            return Err("delegation envelope must contain at least 'id' or 'email'".to_string());
        }

        Ok(())
    }

    /// Check whether authenticated identity `from` may act as requested
    /// identity `to`.
    pub fn can_impersonate(&self, from: &str, to: &str) -> bool {
        if from == to {
            return true;
        }

        self.impersonation.iter().any(|rule| {
            matches_identity_pattern(&rule.from, from) && matches_identity_pattern(&rule.to, to)
        })
    }

    /// Return the first candidate identity allowed to act as `to`.
    pub fn authorized_impersonator<'a>(
        &self,
        candidates: &'a [String],
        to: &str,
    ) -> Option<&'a str> {
        candidates
            .iter()
            .find(|candidate| self.can_impersonate(candidate, to))
            .map(String::as_str)
    }

    /// Load an `AuthConfig` from a TOML file.
    pub fn load(path: &std::path::Path) -> Result<Self, crate::config::ConfigError> {
        let content = std::fs::read_to_string(path)?;
        let config: AuthConfig =
            toml::from_str(&content).map_err(crate::config::ConfigError::Toml)?;
        Ok(config)
    }

    /// Load an `AuthConfig` from `$HOME/.config/$APP/auth.toml`.
    ///
    /// Returns `None` if the file does not exist. Logs a warning on parse errors.
    pub fn load_for_app(app_name: &str) -> Option<Self> {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
        let path = std::path::PathBuf::from(format!("{}/.config/{}/auth.toml", home, app_name));
        if !path.exists() {
            return None;
        }
        match Self::load(&path) {
            Ok(config) => Some(config),
            Err(e) => {
                warn!("Failed to load auth config from {}: {}", path.display(), e);
                None
            }
        }
    }
}

// ============================================================================
// Pattern Matching
// ============================================================================

/// Check if a value (FQDN or domain) matches a delegate pattern.
///
/// - `*` matches everything.
/// - `*.example.com` matches `example.com` and any subdomain
///   (e.g., `foo.example.com`, `bar.foo.example.com`).
/// - A literal value matches exactly.
pub fn matches_delegate_pattern(pattern: &str, value: &str) -> bool {
    if pattern == "*" {
        return true;
    }

    if let Some(suffix) = pattern.strip_prefix("*.") {
        // Match the base domain itself or any subdomain
        value == suffix || value.ends_with(&format!(".{}", suffix))
    } else {
        // Exact match
        pattern == value
    }
}

/// Check if an identity value matches an authorization pattern.
///
/// In addition to `matches_delegate_pattern`, this understands email/login
/// domain patterns:
/// - `*@example.com` matches `alice@example.com`
/// - `*.example.com` also matches the domain side of `alice@example.com`
pub fn matches_identity_pattern(pattern: &str, value: &str) -> bool {
    if matches_delegate_pattern(pattern, value) {
        return true;
    }

    if let Some(domain) = value.rsplit_once('@').map(|(_, domain)| domain) {
        if let Some(pattern_domain) = pattern.strip_prefix("*@") {
            return matches_delegate_pattern(pattern_domain, domain);
        }
        if pattern.starts_with("*.") {
            return matches_delegate_pattern(pattern, domain);
        }
    }

    false
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_config() -> AuthConfig {
        AuthConfig {
            peers: vec![
                PeerConfig {
                    uid: Some(1000),
                    ..Default::default()
                },
                PeerConfig {
                    uid: Some(1001),
                    id: Some("sshd.mesh.local".to_string()),
                    delegate: Some("*.mesh.local".to_string()),
                    ..Default::default()
                },
                PeerConfig {
                    uid: Some(1002),
                    id: Some("gateway.mesh.local".to_string()),
                    delegate: Some("*".to_string()),
                    ..Default::default()
                },
                PeerConfig {
                    id: Some("worker-1.mesh.local".to_string()),
                    ..Default::default()
                },
                PeerConfig {
                    email: Some("bob@example.com".to_string()),
                    ..Default::default()
                },
            ],
            impersonation: vec![
                ImpersonationRule {
                    from: "root@example.com".to_string(),
                    to: "*".to_string(),
                },
                ImpersonationRule {
                    from: "gateway.mesh.local".to_string(),
                    to: "*.mesh.local".to_string(),
                },
            ],
        }
    }

    // ========================================================================
    // is_uid_authorized
    // ========================================================================

    #[test]
    fn test_auth_root_always_authorized() {
        let config = AuthConfig::default();
        assert!(config.is_uid_authorized(0, 5000));
    }

    #[test]
    fn test_auth_self_always_authorized() {
        let config = AuthConfig::default();
        assert!(config.is_uid_authorized(5000, 5000));
    }

    #[test]
    fn test_auth_listed_uid_authorized() {
        let config = sample_config();
        assert!(config.is_uid_authorized(1000, 5000));
        assert!(config.is_uid_authorized(1001, 5000));
        assert!(config.is_uid_authorized(1002, 5000));
    }

    #[test]
    fn test_auth_unlisted_uid_rejected() {
        let config = sample_config();
        assert!(!config.is_uid_authorized(9999, 5000));
    }

    // ========================================================================
    // get_delegate
    // ========================================================================

    #[test]
    fn test_auth_get_delegate_pattern() {
        let config = sample_config();
        assert_eq!(config.get_delegate(1001), Some("*.mesh.local"));
        assert_eq!(config.get_delegate(1002), Some("*"));
    }

    #[test]
    fn test_auth_get_delegate_non_delegate() {
        let config = sample_config();
        assert_eq!(config.get_delegate(1000), None);
        assert_eq!(config.get_delegate(9999), None);
    }

    // ========================================================================
    // is_peer_allowed
    // ========================================================================

    #[test]
    fn test_auth_peer_allowed_by_id() {
        let config = sample_config();
        let identity = PeerIdentity {
            id: Some("worker-1.mesh.local".to_string()),
            ..Default::default()
        };
        assert!(config.is_peer_allowed(&identity));
    }

    #[test]
    fn test_auth_peer_allowed_by_email() {
        let config = sample_config();
        let identity = PeerIdentity {
            email: Some("bob@example.com".to_string()),
            ..Default::default()
        };
        assert!(config.is_peer_allowed(&identity));
    }

    #[test]
    fn test_auth_peer_rejected_unknown_id() {
        let config = sample_config();
        let identity = PeerIdentity {
            id: Some("unknown.example.com".to_string()),
            ..Default::default()
        };
        assert!(!config.is_peer_allowed(&identity));
    }

    #[test]
    fn test_auth_peer_no_identity_rules_accepts_all() {
        // Config with only UID entries — no id/email rules
        let config = AuthConfig {
            peers: vec![PeerConfig {
                uid: Some(1000),
                ..Default::default()
            }],
            ..Default::default()
        };
        let identity = PeerIdentity {
            id: Some("anything.example.com".to_string()),
            ..Default::default()
        };
        assert!(config.is_peer_allowed(&identity));
    }

    #[test]
    fn test_auth_peer_empty_config_accepts_all() {
        let config = AuthConfig::default();
        let identity = PeerIdentity {
            id: Some("anything.example.com".to_string()),
            ..Default::default()
        };
        assert!(config.is_peer_allowed(&identity));
    }

    // ========================================================================
    // validate_delegation
    // ========================================================================

    #[test]
    fn test_auth_validate_delegation_wildcard() {
        let config = sample_config();
        let identity = PeerIdentity {
            id: Some("anything.anywhere.com".to_string()),
            ..Default::default()
        };
        assert!(config.validate_delegation(1002, &identity).is_ok());
    }

    #[test]
    fn test_auth_validate_delegation_subdomain_match() {
        let config = sample_config();
        let identity = PeerIdentity {
            id: Some("worker-1.mesh.local".to_string()),
            ..Default::default()
        };
        assert!(config.validate_delegation(1001, &identity).is_ok());
    }

    #[test]
    fn test_auth_validate_delegation_base_domain_match() {
        let config = sample_config();
        let identity = PeerIdentity {
            id: Some("mesh.local".to_string()),
            ..Default::default()
        };
        assert!(config.validate_delegation(1001, &identity).is_ok());
    }

    #[test]
    fn test_auth_validate_delegation_deep_subdomain() {
        let config = sample_config();
        let identity = PeerIdentity {
            id: Some("a.b.c.mesh.local".to_string()),
            ..Default::default()
        };
        assert!(config.validate_delegation(1001, &identity).is_ok());
    }

    #[test]
    fn test_auth_validate_delegation_subdomain_reject() {
        let config = sample_config();
        let identity = PeerIdentity {
            id: Some("worker.evil.com".to_string()),
            ..Default::default()
        };
        assert!(config.validate_delegation(1001, &identity).is_err());
    }

    #[test]
    fn test_auth_validate_delegation_email_domain_match() {
        let config = sample_config();
        let identity = PeerIdentity {
            id: Some("worker-1.mesh.local".to_string()),
            email: Some("alice@mesh.local".to_string()),
            ..Default::default()
        };
        assert!(config.validate_delegation(1001, &identity).is_ok());
    }

    #[test]
    fn test_auth_validate_delegation_email_subdomain_match() {
        let config = sample_config();
        let identity = PeerIdentity {
            id: Some("worker-1.mesh.local".to_string()),
            email: Some("alice@sub.mesh.local".to_string()),
            ..Default::default()
        };
        assert!(config.validate_delegation(1001, &identity).is_ok());
    }

    #[test]
    fn test_auth_validate_delegation_email_domain_reject() {
        let config = sample_config();
        let identity = PeerIdentity {
            id: Some("worker-1.mesh.local".to_string()),
            email: Some("alice@evil.com".to_string()),
            ..Default::default()
        };
        assert!(config.validate_delegation(1001, &identity).is_err());
    }

    #[test]
    fn test_auth_validate_delegation_not_a_delegate() {
        let config = sample_config();
        let identity = PeerIdentity {
            id: Some("worker-1.mesh.local".to_string()),
            ..Default::default()
        };
        assert!(config.validate_delegation(1000, &identity).is_err());
    }

    #[test]
    fn test_auth_validate_delegation_empty_identity() {
        let config = sample_config();
        let identity = PeerIdentity::default();
        assert!(config.validate_delegation(1001, &identity).is_err());
    }

    // ========================================================================
    // impersonation
    // ========================================================================

    #[test]
    fn test_auth_impersonation_exact_source_wildcard_target() {
        let config = sample_config();
        assert!(config.can_impersonate("root@example.com", "root@host3-vm.example.m"));
        assert!(config.can_impersonate("root@example.com", "system"));
        assert!(!config.can_impersonate("alice@example.com", "root@host3-vm.example.m"));
    }

    #[test]
    fn test_auth_impersonation_email_domain_target() {
        let config = sample_config();
        assert!(config.can_impersonate("gateway.mesh.local", "root@mesh.local"));
        assert!(config.can_impersonate("gateway.mesh.local", "root@node.mesh.local"));
        assert!(!config.can_impersonate("gateway.mesh.local", "root@example.com"));
    }

    #[test]
    fn test_auth_authorized_impersonator() {
        let config = sample_config();
        let candidates = vec![
            "alice@example.com".to_string(),
            "root@example.com".to_string(),
        ];
        assert_eq!(
            config.authorized_impersonator(&candidates, "root@host3-vm.example.m"),
            Some("root@example.com")
        );
    }

    // ========================================================================
    // matches_delegate_pattern
    // ========================================================================

    #[test]
    fn test_auth_pattern_wildcard() {
        assert!(matches_delegate_pattern("*", "anything"));
        assert!(matches_delegate_pattern("*", "foo.bar.baz"));
    }

    #[test]
    fn test_auth_pattern_subdomain_wildcard() {
        assert!(matches_delegate_pattern("*.example.com", "example.com"));
        assert!(matches_delegate_pattern("*.example.com", "foo.example.com"));
        assert!(matches_delegate_pattern(
            "*.example.com",
            "bar.foo.example.com"
        ));
    }

    #[test]
    fn test_auth_pattern_subdomain_no_match() {
        assert!(!matches_delegate_pattern("*.example.com", "evil.com"));
        assert!(!matches_delegate_pattern("*.example.com", "notexample.com"));
        assert!(!matches_delegate_pattern("*.example.com", "fooexample.com"));
    }

    #[test]
    fn test_auth_pattern_exact() {
        assert!(matches_delegate_pattern("exact.host", "exact.host"));
        assert!(!matches_delegate_pattern("exact.host", "other.host"));
        assert!(!matches_delegate_pattern("exact.host", "sub.exact.host"));
    }

    #[test]
    fn test_auth_identity_pattern_email_domain() {
        assert!(matches_identity_pattern(
            "*@example.com",
            "root@example.com"
        ));
        assert!(matches_identity_pattern(
            "*.example.com",
            "root@host.example.com"
        ));
        assert!(!matches_identity_pattern("*@example.com", "root@evil.com"));
    }

    // ========================================================================
    // TOML Parsing
    // ========================================================================

    #[test]
    fn test_auth_parse_toml() {
        let toml_str = r#"
[[peer]]
uid = 1000

[[peer]]
uid = 1001
id = "sshd.mesh.local"
delegate = "*.mesh.local"

[[peer]]
id = "worker-1.mesh.local"

[[peer]]
email = "bob@example.com"

[[impersonation]]
from = "root@example.com"
to = "*"
"#;
        let config: AuthConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(config.peers.len(), 4);
        assert_eq!(config.peers[0].uid, Some(1000));
        assert_eq!(config.peers[1].delegate.as_deref(), Some("*.mesh.local"));
        assert_eq!(config.peers[2].id.as_deref(), Some("worker-1.mesh.local"));
        assert_eq!(config.peers[3].email.as_deref(), Some("bob@example.com"));
        assert_eq!(config.impersonation.len(), 1);
        assert_eq!(config.impersonation[0].from.as_str(), "root@example.com");
    }

    #[test]
    fn test_auth_parse_empty_toml() {
        let config: AuthConfig = toml::from_str("").unwrap();
        assert!(config.peers.is_empty());
    }

    // ========================================================================
    // DelegationEnvelope
    // ========================================================================

    #[test]
    fn test_auth_delegation_envelope_deserialize() {
        let json = r#"{"peer": {"id": "worker-1.mesh.local", "ip": "10.0.0.5"}}"#;
        let envelope: DelegationEnvelope = serde_json::from_str(json).unwrap();
        assert_eq!(envelope.peer.id.as_deref(), Some("worker-1.mesh.local"));
        assert_eq!(envelope.peer.ip.as_deref(), Some("10.0.0.5"));
        assert_eq!(envelope.peer.email, None);
    }

    #[test]
    fn test_auth_delegation_envelope_with_email() {
        let json = r#"{"peer": {"id": "worker-1.mesh.local", "ip": "10.0.0.5", "email": "alice@mesh.local"}}"#;
        let envelope: DelegationEnvelope = serde_json::from_str(json).unwrap();
        assert_eq!(envelope.peer.email.as_deref(), Some("alice@mesh.local"));
    }

    #[test]
    fn test_auth_delegation_envelope_serialize() {
        let envelope = DelegationEnvelope {
            peer: PeerIdentity {
                id: Some("worker-1.mesh.local".to_string()),
                ip: Some("10.0.0.5".to_string()),
                email: None,
                uid: None,
            },
        };
        let json = serde_json::to_string(&envelope).unwrap();
        assert!(json.contains("worker-1.mesh.local"));
        assert!(json.contains("10.0.0.5"));
        // uid and email should be omitted
        assert!(!json.contains("uid"));
        assert!(!json.contains("email"));
    }
}
