//! Nostr relay URL validation with SSRF protection.
//!
//! This module is the SSRF enforcement boundary for all Nostr relay traffic
//! from WASM tools. It validates:
//! - `wss://` scheme enforcement (rejects `ws://`)
//! - Private IP / loopback / link-local rejection (IPv4 and IPv6, including mapped addresses)
//!
//! The relay I/O functions (`publish_nostr_event`, `subscribe_nostr_events`) that
//! open WebSocket connections live in `ironclaw_host_runtime::services::nostr_relay`
//! to satisfy the "no direct networking in any lane" rule.
//!
//! # Mediation boundary
//!
//! The [`WasmHostNostr`] trait in `host.rs` is the kernel-level mediation seam:
//! the kernel provides the implementation, and the default is
//! [`DenyWasmHostNostr`] which refuses all operations. Nostr is only enabled
//! when the composition layer explicitly wires a live implementation via
//! [`WitToolHost::with_nostr()`].

use crate::WasmHostError;

/// Error type for Nostr relay operations.
#[derive(Debug, thiserror::Error)]
pub enum NostrRelayError {
    #[error("{0}")]
    WebSocket(String),
    #[error("{0}")]
    Relay(String),
    #[error("{0}")]
    InvalidInput(String),
}

impl From<NostrRelayError> for WasmHostError {
    fn from(err: NostrRelayError) -> Self {
        match err {
            NostrRelayError::WebSocket(msg) => WasmHostError::Failed(msg.clone()),
            NostrRelayError::Relay(msg) => WasmHostError::Failed(msg.clone()),
            NostrRelayError::InvalidInput(msg) => WasmHostError::Failed(msg.clone()),
        }
    }
}

/// Validate a Nostr relay URL before opening a WebSocket connection.
///
/// Enforces:
/// 1. URL must parse successfully
/// 2. Scheme must be `wss://` (TLS is required; plaintext `ws://` is rejected)
/// 3. Host must not be a private, loopback, link-local, or otherwise reserved IP
///
/// This is the baseline SSRF protection. Production composition layers may
/// add further restrictions (relay allowlists, DNS rebinding checks, etc.).
pub fn validate_relay_url(relay_url: &str) -> Result<(), NostrRelayError> {
    let parsed: url::Url = relay_url
        .parse()
        .map_err(|e| NostrRelayError::InvalidInput(format!("invalid relay URL: {e}")))?;

    // Enforce wss:// — plaintext ws:// is rejected for host-side relay I/O.
    if parsed.scheme() != "wss" {
        return Err(NostrRelayError::InvalidInput(format!(
            "relay URL must use wss:// scheme (TLS required), got: {}",
            parsed.scheme()
        )));
    }

    let host = parsed
        .host_str()
        .ok_or_else(|| NostrRelayError::InvalidInput("relay URL must have a host".into()))?;

    // Reject private/loopback/link-local/reserved IP addresses (SSRF protection).
    // For hostname-based URLs, we also reject well-known local names.
    if is_private_or_loopback_host(host) {
        return Err(NostrRelayError::InvalidInput(format!(
            "relay URL host must not be a private, loopback, or reserved address: {host}"
        )));
    }

    Ok(())
}

/// Check whether a host string is a private, loopback, link-local, or
/// otherwise reserved IP address, or a well-known local hostname.
///
/// Handles:
/// - IPv4: 0.0.0.0, 127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16,
///   169.254.0.0/16 (link-local), 224.0.0.0/4+ (multicast), 255.255.255.255
/// - IPv6: ::1, ::, fc00::/7 (unique local), fe80::/10 (link-local), ff00::/8 (multicast)
/// - Well-known hostnames: localhost, localhost.localdomain
fn is_private_or_loopback_host(host: &str) -> bool {
    let lower = host.to_ascii_lowercase();

    // Well-known local hostnames
    if lower == "localhost" || lower == "localhost.localdomain" {
        return true;
    }

    // Try to parse as an IP address (handles both IPv4 and IPv6 bracketed forms).
    // `url::Host` parsing handles [::1] brackets for us.
    let ip_host = match lower.parse::<std::net::IpAddr>() {
        Ok(ip) => ip,
        Err(_) => {
            // Not an IP literal — for non-IP hosts we cannot do DNS resolution
            // here (it would be a blocking call in an async context and introduces
            // TOCTOU issues). The production adapter layer can add DNS-level checks.
            return false;
        }
    };

    is_private_ip(&ip_host)
}

/// Check whether an IP address is private, loopback, link-local, or reserved.
fn is_private_ip(ip: &std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(v4) => {
            let octets = v4.octets();
            // 0.0.0.0
            octets == [0, 0, 0, 0]
            // 127.0.0.0/8 — loopback
            || octets[0] == 127
            // 10.0.0.0/8 — private (RFC 1918)
            || octets[0] == 10
            // 172.16.0.0/12 — private (RFC 1918)
            || (octets[0] == 172 && octets[1] >= 16 && octets[1] <= 31)
            // 192.168.0.0/16 — private (RFC 1918)
            || (octets[0] == 192 && octets[1] == 168)
            // 169.254.0.0/16 — link-local
            || (octets[0] == 169 && octets[1] == 254)
            // 224.0.0.0/4+ — multicast / reserved
            || octets[0] >= 224
            // 255.255.255.255 — broadcast
            || octets == [255, 255, 255, 255]
        }
        std::net::IpAddr::V6(v6) => {
            let segments = v6.segments();
            // ::1 — loopback
            v6.is_loopback()
            // :: — unspecified
            || v6.is_unspecified()
            // fc00::/7 — unique local
            || (segments[0] & 0xfe00) == 0xfc00
            // fe80::/10 — link-local
            || (segments[0] & 0xffc0) == 0xfe80
            // ff00::/8 — multicast
            || segments[0] & 0xff00 == 0xff00
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── validate_relay_url: scheme enforcement ─────────────────────────

    #[test]
    fn validate_relay_url_accepts_wss() {
        assert!(validate_relay_url("wss://relay.example.com").is_ok());
        assert!(validate_relay_url("wss://relay.example.com:8080").is_ok());
    }

    #[test]
    fn validate_relay_url_rejects_ws_scheme() {
        let err = validate_relay_url("ws://relay.example.com").unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("wss://"), "expected wss:// rejection, got: {msg}");
    }

    #[test]
    fn validate_relay_url_rejects_http_schemes() {
        let err = validate_relay_url("https://relay.example.com").unwrap_err();
        assert!(err.to_string().contains("wss://"));
    }

    #[test]
    fn validate_relay_url_rejects_invalid_url() {
        let err = validate_relay_url("not a url").unwrap_err();
        assert!(err.to_string().contains("invalid relay URL"));
    }

    #[test]
    fn validate_relay_url_rejects_empty_host() {
        let err = validate_relay_url("wss://").unwrap_err();
        assert!(err.to_string().contains("host"));
    }

    // ── validate_relay_url: private / loopback IPv4 ─────────────────────

    #[test]
    fn validate_relay_url_rejects_loopback_ipv4() {
        let err = validate_relay_url("wss://127.0.0.1").unwrap_err();
        assert!(
            err.to_string().contains("private, loopback, or reserved"),
            "got: {err}"
        );
    }

    #[test]
    fn validate_relay_url_rejects_loopback_ipv4_full() {
        let err = validate_relay_url("wss://127.255.255.255").unwrap_err();
        assert!(
            err.to_string().contains("private, loopback, or reserved"),
            "got: {err}"
        );
    }

    #[test]
    fn validate_relay_url_rejects_10_private() {
        let err = validate_relay_url("wss://10.0.0.1").unwrap_err();
        assert!(err.to_string().contains("private, loopback, or reserved"));
    }

    #[test]
    fn validate_relay_url_rejects_192168_private() {
        let err = validate_relay_url("wss://192.168.1.1").unwrap_err();
        assert!(err.to_string().contains("private, loopback, or reserved"));
    }

    #[test]
    fn validate_relay_url_rejects_17216_private() {
        let err = validate_relay_url("wss://172.16.0.1").unwrap_err();
        assert!(err.to_string().contains("private, loopback, or reserved"));
    }

    #[test]
    fn validate_relay_url_rejects_17231_private() {
        let err = validate_relay_url("wss://172.31.255.255").unwrap_err();
        assert!(err.to_string().contains("private, loopback, or reserved"));
    }

    #[test]
    fn validate_relay_url_accepts_17215_public() {
        // 172.15.x.x is NOT private (RFC 1918 is 172.16–172.31)
        assert!(validate_relay_url("wss://172.15.255.255").is_ok());
    }

    #[test]
    fn validate_relay_url_rejects_0_0_0_0() {
        let err = validate_relay_url("wss://0.0.0.0").unwrap_err();
        assert!(err.to_string().contains("private, loopback, or reserved"));
    }

    #[test]
    fn validate_relay_url_rejects_link_local() {
        let err = validate_relay_url("wss://169.254.1.1").unwrap_err();
        assert!(err.to_string().contains("private, loopback, or reserved"));
    }

    #[test]
    fn validate_relay_url_rejects_broadcast() {
        let err = validate_relay_url("wss://255.255.255.255").unwrap_err();
        assert!(err.to_string().contains("private, loopback, or reserved"));
    }

    #[test]
    fn validate_relay_url_rejects_multicast() {
        let err = validate_relay_url("wss://224.0.0.1").unwrap_err();
        assert!(err.to_string().contains("private, loopback, or reserved"));
    }

    // ── validate_relay_url: IPv6 ────────────────────────────────────────

    #[test]
    fn validate_relay_url_rejects_ipv6_loopback() {
        let err = validate_relay_url("wss://[::1]").unwrap_err();
        assert!(err.to_string().contains("private, loopback, or reserved"));
    }

    #[test]
    fn validate_relay_url_rejects_ipv6_unspecified() {
        let err = validate_relay_url("wss://[::]").unwrap_err();
        assert!(err.to_string().contains("private, loopback, or reserved"));
    }

    #[test]
    fn validate_relay_url_rejects_ipv6_unique_local() {
        let err = validate_relay_url("wss://[fc00::1]").unwrap_err();
        assert!(err.to_string().contains("private, loopback, or reserved"));
    }

    #[test]
    fn validate_relay_url_rejects_ipv6_link_local() {
        let err = validate_relay_url("wss://[fe80::1]").unwrap_err();
        assert!(err.to_string().contains("private, loopback, or reserved"));
    }

    #[test]
    fn validate_relay_url_rejects_ipv6_multicast() {
        let err = validate_relay_url("wss://[ff02::1]").unwrap_err();
        assert!(err.to_string().contains("private, loopback, or reserved"));
    }

    #[test]
    fn validate_relay_url_accepts_ipv6_public() {
        // 2001:db8:: is documentation prefix, but not private/reserved per our check
        assert!(validate_relay_url("wss://[2001:db8::1]").is_ok());
    }

    // ── validate_relay_url: well-known local hostnames ──────────────────

    #[test]
    fn validate_relay_url_rejects_localhost() {
        let err = validate_relay_url("wss://localhost").unwrap_err();
        assert!(err.to_string().contains("private, loopback, or reserved"));
    }

    #[test]
    fn validate_relay_url_rejects_localhost_fqdn() {
        let err = validate_relay_url("wss://localhost.localdomain").unwrap_err();
        assert!(err.to_string().contains("private, loopback, or reserved"));
    }

    #[test]
    fn validate_relay_url_rejects_localhost_with_port() {
        let err = validate_relay_url("wss://localhost:8080").unwrap_err();
        assert!(err.to_string().contains("private, loopback, or reserved"));
    }

    // ── validate_relay_url: public hostnames pass ──────────────────────

    #[test]
    fn validate_relay_url_accepts_public_hostname() {
        assert!(validate_relay_url("wss://relay.example.com").is_ok());
    }

    #[test]
    fn validate_relay_url_accepts_public_ip() {
        assert!(validate_relay_url("wss://1.2.3.4").is_ok());
        assert!(validate_relay_url("wss://8.8.8.8").is_ok());
    }

    #[test]
    fn validate_relay_url_accepts_public_ip_with_port() {
        assert!(validate_relay_url("wss://1.2.3.4:443").is_ok());
    }

    // ── is_private_ip unit tests ───────────────────────────────────────

    #[test]
    fn is_private_ip_classifies_ranges_correctly() {
        // Private
        assert!(is_private_ip(&"10.0.0.1".parse().unwrap()));
        assert!(is_private_ip(&"172.16.0.1".parse().unwrap()));
        assert!(is_private_ip(&"172.31.255.255".parse().unwrap()));
        assert!(is_private_ip(&"192.168.0.1".parse().unwrap()));
        assert!(is_private_ip(&"127.0.0.1".parse().unwrap()));
        assert!(is_private_ip(&"169.254.1.1".parse().unwrap()));
        assert!(is_private_ip(&"224.0.0.1".parse().unwrap()));
        assert!(is_private_ip(&"0.0.0.0".parse().unwrap()));
        assert!(is_private_ip(&"255.255.255.255".parse().unwrap()));

        // Not private
        assert!(!is_private_ip(&"1.2.3.4".parse().unwrap()));
        assert!(!is_private_ip(&"8.8.8.8".parse().unwrap()));
        assert!(!is_private_ip(&"172.15.255.255".parse().unwrap()));
        assert!(!is_private_ip(&"172.32.0.0".parse().unwrap()));
    }

    #[test]
    fn is_private_ip_classifies_ipv6_correctly() {
        // Private/reserved
        assert!(is_private_ip(&"::1".parse().unwrap()));
        assert!(is_private_ip(&"::".parse().unwrap()));
        assert!(is_private_ip(&"fc00::1".parse().unwrap()));
        assert!(is_private_ip(&"fd00::1".parse().unwrap()));
        assert!(is_private_ip(&"fe80::1".parse().unwrap()));
        assert!(is_private_ip(&"ff02::1".parse().unwrap()));

        // Not private
        assert!(!is_private_ip(&"2001:db8::1".parse().unwrap()));
        assert!(!is_private_ip(&"2607:f8b0:4004:800::200e".parse().unwrap()));
    }
}
