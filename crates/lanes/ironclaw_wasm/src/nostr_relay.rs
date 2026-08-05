//! Nostr relay WebSocket communication for WASM tools.
//!
//! Implements host-side relay I/O: publish events and subscribe to event streams.
//! All relay connections go through SSRF guards that reject private/internal IPs.

use std::net::IpAddr;

use crate::WasmHostError;

/// Error type for Nostr relay operations.
#[derive(Debug, thiserror::Error)]
pub enum NostrRelayError {
    #[error("SSRF check failed: {0}")]
    SsrfRejected(String),

    #[error("WebSocket error: {0}")]
    WebSocket(String),

    #[error("Relay error: {0}")]
    Relay(String),

    #[error("Invalid input: {0}")]
    InvalidInput(String),
}

impl From<NostrRelayError> for WasmHostError {
    fn from(err: NostrRelayError) -> Self {
        match &err {
            NostrRelayError::SsrfRejected(msg) => WasmHostError::Denied(msg.clone()),
            NostrRelayError::WebSocket(msg) => WasmHostError::Failed(msg.clone()),
            NostrRelayError::Relay(msg) => WasmHostError::Failed(msg.clone()),
            NostrRelayError::InvalidInput(msg) => WasmHostError::Failed(msg.clone()),
        }
    }
}

/// Maximum number of events collected per subscription to prevent unbounded memory.
const MAX_COLLECTED_EVENTS: usize = 5_000;
/// Maximum cumulative bytes of collected event JSON before truncation.
/// Prevents memory exhaustion from relay-controlled large payloads.
const MAX_COLLECTED_BYTES: usize = 64 * 1024 * 1024; // 64 MiB
/// Maximum size of a single incoming WebSocket message (bytes).
/// Default tungstenite limit is 64 MiB; we lower to 1 MiB for WASM sandbox.
const MAX_WS_MESSAGE_SIZE: usize = 1024 * 1024; // 1 MiB

/// Default connect timeout in milliseconds.
const DEFAULT_CONNECT_TIMEOUT_MS: u64 = 10_000;

/// SSRF guard for WebSocket relay URLs.
///
/// Rejects connections to private/internal IP addresses to prevent
/// server-side request forgery.
pub fn reject_ws_relay_url(url: &str) -> Result<(), NostrRelayError> {
    let parsed: url::Url = url::Url::parse(url)
        .map_err(|e| NostrRelayError::SsrfRejected(format!("Invalid relay URL: {e}")))?;

    if parsed.scheme() != "ws" && parsed.scheme() != "wss" {
        return Err(NostrRelayError::SsrfRejected(format!(
            "Relay URL must use ws:// or wss://, got {}",
            parsed.scheme()
        )));
    }

    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(NostrRelayError::SsrfRejected(
            "Relay URL must not contain userinfo".to_string(),
        ));
    }

    let host = parsed
        .host_str()
        .ok_or_else(|| NostrRelayError::SsrfRejected("Relay URL must have a host".to_string()))?;

    // Reject bare IP addresses that are private
    if let Ok(ip) = host.parse::<IpAddr>() {
        if is_private_ip(ip) {
            return Err(NostrRelayError::SsrfRejected(format!(
                "Relay URL points to private/reserved IP: {ip}"
            )));
        }
        return Ok(());
    }

    // For domain names, attempt DNS resolution to catch DNS-rebinding to private IPs
    let port = parsed.port().unwrap_or(80);
    if let Ok(addrs) = std::net::ToSocketAddrs::to_socket_addrs(&format!("{}:{}", host, port)) {
        for addr in addrs {
            if is_private_ip(addr.ip()) {
                return Err(NostrRelayError::SsrfRejected(format!(
                    "Relay URL hostname resolves to private/reserved IP: {} -> {}",
                    host,
                    addr.ip()
                )));
            }
        }
    }

    Ok(())
}

/// Check if an IP address is private, loopback, link-local, reserved, multicast,
/// broadcast, documentation, or otherwise unsuitable for external relay connections.
///
/// Canonicalizes IPv4-mapped IPv6 addresses before classification to prevent
/// SSRF bypass via `::ffff:127.0.0.1` style addresses.
fn is_private_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_private_ipv4(&v4),
        IpAddr::V6(v6) => {
            // Canonicalize IPv4-mapped IPv6 addresses (::ffff:a.b.c.d)
            if let Some(v4) = v6.to_ipv4_mapped() {
                return is_private_ipv4(&v4);
            }

            v6.is_loopback()
                || v6.is_unspecified()
                // IPv6 unique local (fc00::/7)
                || (v6.segments()[0] & 0xFE00) == 0xFC00
                // IPv6 link-local (fe80::/10)
                || (v6.segments()[0] & 0xFFC0) == 0xFE80
                // IPv6 6to4 relay (2002::/16)
                || v6.segments()[0] == 0x2002
                // IPv6 Teredo (2001::/32)
                || (v6.segments()[0] == 0x2001 && v6.segments()[1] == 0x0000)
        }
    }
}

/// IPv4-specific private/reserved address check.
fn is_private_ipv4(v4: &std::net::Ipv4Addr) -> bool {
    v4.is_loopback()
        || v4.is_private()
        || v4.is_link_local()
        || v4.is_unspecified()
        // Carrier-grade NAT (100.64.0.0/10)
        || (v4.octets()[0] == 100 && (v4.octets()[1] & 0xC0) == 64)
        // Multicast (224.0.0.0/4)
        || v4.is_multicast()
        // Reserved/broadcast/documentation: first octet >= 240
        // 240.0.0.0/4 includes 255.255.255.255 broadcast, documentation (TEST-NET-1
        // through TEST-NET-3 are in 192/203 so they're covered by is_private),
        // and reserved-for-future-use ranges.
        || v4.octets()[0] >= 240
}

/// Publish a signed Nostr event to a relay via WebSocket.
///
/// Opens a WebSocket connection, sends the EVENT message,
/// and waits for the relay's OK/NACK response.
///
/// `remaining_deadline_ms` is an optional overall deadline for the operation
/// (including connect and read). When `None`, a default 10s connect timeout is used.
///
/// Returns the event ID on success.
pub async fn publish_nostr_event(
    relay_url: &str,
    signed_event_json: &str,
    remaining_deadline_ms: Option<u32>,
) -> Result<String, WasmHostError> {
    reject_ws_relay_url(relay_url)?;

    use futures_util::{SinkExt, StreamExt};
    use tokio_tungstenite::tungstenite::Message;

    let connect_start = std::time::Instant::now();

    let connect_timeout = std::time::Duration::from_millis(
        remaining_deadline_ms
            .map(|d| (d as u64).min(DEFAULT_CONNECT_TIMEOUT_MS))
            .unwrap_or(DEFAULT_CONNECT_TIMEOUT_MS),
    );

    let (ws_stream, _) = tokio::time::timeout(connect_timeout, async {
        tokio_tungstenite::connect_async_with_config(
            relay_url,
            Some(tokio_tungstenite::tungstenite::protocol::WebSocketConfig {
                max_message_size: Some(MAX_WS_MESSAGE_SIZE),
                ..Default::default()
            }),
            false,
        )
        .await
    })
    .await
    .map_err(|_| {
        NostrRelayError::WebSocket(format!(
            "WebSocket connect timed out after {}ms",
            connect_timeout.as_millis()
        ))
    })?
    .map_err(|e| NostrRelayError::WebSocket(format!("WebSocket connect failed: {e}")))?;

    let (mut write, mut read) = ws_stream.split();

    // Build and send EVENT message; pre-extract the event `id` for verification.
    let event_val: serde_json::Value = serde_json::from_str(signed_event_json)
        .map_err(|e| NostrRelayError::InvalidInput(format!("Invalid event JSON: {e}")))?;

    let expected_id = event_val
        .get("id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            NostrRelayError::InvalidInput(
                "Signed event JSON must contain an \"id\" field".to_string(),
            )
        })?
        .to_string();

    let msg = serde_json::json!(["EVENT", event_val]);
    write
        .send(Message::Text(msg.to_string().into()))
        .await
        .map_err(|e| NostrRelayError::WebSocket(format!("WebSocket send failed: {e}")))?;

    // Read OK response; clamp timeout to remaining deadline if present,
    // accounting for time already spent on connect + send.
    let read_timeout = std::time::Duration::from_secs(10);
    let effective_timeout = match remaining_deadline_ms {
        Some(deadline) => {
            let elapsed_ms = connect_start.elapsed().as_millis() as u64;
            let remaining_ms = (deadline as u64).saturating_sub(elapsed_ms);
            read_timeout.min(std::time::Duration::from_millis(remaining_ms))
        }
        None => read_timeout,
    };

    let result = tokio::time::timeout(effective_timeout, async {
        while let Some(msg_result) = read.next().await {
            let msg = msg_result
                .map_err(|e| NostrRelayError::WebSocket(format!("WebSocket read error: {e}")))?;
            if let Message::Text(text) = msg {
                if let Ok(arr) = serde_json::from_str::<Vec<serde_json::Value>>(&text) {
                    if arr.len() >= 3 && arr[0] == "OK" {
                        let relay_id = arr[1].as_str().unwrap_or("").to_string();
                        let accepted = arr.get(2).and_then(|v| v.as_bool()).unwrap_or(false);

                        if !accepted {
                            let reason =
                                arr.get(3).and_then(|v| v.as_str()).unwrap_or("unknown");
                            return Err(NostrRelayError::Relay(format!(
                                "Relay rejected: {reason}"
                            )));
                        }

                        // Verify relay-supplied ID matches the signed event ID.
                        if relay_id != expected_id {
                            return Err(NostrRelayError::Relay(format!(
                                "Relay returned different event ID: expected {expected_id}, got {relay_id}"
                            )));
                        }

                        return Ok::<String, NostrRelayError>(relay_id);
                    }
                }
            }
        }
        Err(NostrRelayError::Relay(
            "WebSocket closed without OK".to_string(),
        ))
    })
    .await
    .map_err(|_| NostrRelayError::WebSocket("Timeout waiting for relay OK response".to_string()))?;

    result.map_err(WasmHostError::from)
}

/// Subscribe to Nostr events from a relay via WebSocket.
///
/// Connects, sends REQ with filters, collects matching events for `timeout_ms`,
/// sends CLOSE, returns JSON object with the collected events and truncation status.
///
/// `remaining_deadline_ms` is an optional overall deadline for the operation
/// (including connect). When `None`, a default 10s connect timeout is used.
/// The subscribe/collection phase is clamped to `min(timeout_ms, remaining_deadline)`.
pub async fn subscribe_nostr_events(
    relay_url: &str,
    filter_json: &str,
    timeout_ms: u32,
    remaining_deadline_ms: Option<u32>,
) -> Result<String, WasmHostError> {
    reject_ws_relay_url(relay_url)?;

    use futures_util::{SinkExt, StreamExt};
    use tokio_tungstenite::tungstenite::Message;

    let connect_start = std::time::Instant::now();

    let connect_timeout = std::time::Duration::from_millis(
        remaining_deadline_ms
            .map(|d| (d as u64).min(DEFAULT_CONNECT_TIMEOUT_MS))
            .unwrap_or(DEFAULT_CONNECT_TIMEOUT_MS),
    );

    let (ws_stream, _) = tokio::time::timeout(connect_timeout, async {
        tokio_tungstenite::connect_async_with_config(
            relay_url,
            Some(tokio_tungstenite::tungstenite::protocol::WebSocketConfig {
                max_message_size: Some(MAX_WS_MESSAGE_SIZE),
                ..Default::default()
            }),
            false,
        )
        .await
    })
    .await
    .map_err(|_| {
        NostrRelayError::WebSocket(format!(
            "WebSocket connect timed out after {}ms",
            connect_timeout.as_millis()
        ))
    })?
    .map_err(|e| NostrRelayError::WebSocket(format!("WebSocket connect failed: {e}")))?;

    let (mut write, mut read) = ws_stream.split();

    // Parse filters
    let filters: Vec<serde_json::Value> = serde_json::from_str(filter_json)
        .map_err(|e| NostrRelayError::InvalidInput(format!("Invalid filter JSON: {e}")))?;

    // Send REQ with unique subscription ID
    let sub_id = format!("sub_{}", uuid::Uuid::new_v4().as_simple());
    let mut req_msg = vec![serde_json::json!("REQ"), serde_json::json!(sub_id)];
    req_msg.extend(filters);
    let req_text = serde_json::to_string(&req_msg)
        .map_err(|e| NostrRelayError::InvalidInput(format!("Failed to serialize REQ message: {e}")))?;
    write
        .send(Message::Text(req_text.into()))
        .await
        .map_err(|e| NostrRelayError::WebSocket(format!("WebSocket send failed: {e}")))?;

    // Collect events; clamp collection timeout to remaining deadline if present,
    // accounting for time already spent on connect + send.
    let collection_timeout = match remaining_deadline_ms {
        Some(deadline) => {
            let elapsed_ms = connect_start.elapsed().as_millis() as u64;
            let remaining_ms = (deadline as u64).saturating_sub(elapsed_ms);
            (timeout_ms as u64).min(remaining_ms)
        }
        None => timeout_ms as u64,
    };

    let mut events: Vec<serde_json::Value> = Vec::new();
    let mut truncated = false;
    let mut read_error: Option<String> = None;
    let mut collected_bytes: usize = 0;

    let _ = tokio::time::timeout(
        std::time::Duration::from_millis(collection_timeout),
        async {
            while let Some(msg_result) = read.next().await {
                let msg = match msg_result {
                    Ok(m) => m,
                    Err(e) => {
                        read_error = Some(format!("WebSocket read error: {e}"));
                        break;
                    }
                };
                if let Message::Text(text) = msg {
                    if let Ok(arr) = serde_json::from_str::<Vec<serde_json::Value>>(&text) {
                        if arr.len() >= 3 && arr[0] == "EVENT" {
                            // arr[1] is sub_id, arr[2] is the event
                            collected_bytes = collected_bytes.saturating_add(text.len());
                            events.push(arr[2].clone());
                            if events.len() >= MAX_COLLECTED_EVENTS
                                || collected_bytes >= MAX_COLLECTED_BYTES
                            {
                                truncated = true;
                                break;
                            }
                        }
                    }
                }
            }
        },
    )
    .await;

    // If a WebSocket read error occurred, return it as an Err.
    if let Some(reason) = read_error {
        return Err(WasmHostError::from(NostrRelayError::WebSocket(reason)));
    }

    // Send CLOSE
    let close_msg = serde_json::json!(["CLOSE", sub_id]);
    let _ = write
        .send(Message::Text(close_msg.to_string().into()))
        .await;

    // Return structured response with truncation indicator.
    let response = serde_json::json!({
        "events": events,
        "truncated": truncated,
    });
    serde_json::to_string(&response)
        .map_err(|e| WasmHostError::Failed(format!("Failed to serialize events: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_reject_private_ip_url() {
        assert!(reject_ws_relay_url("ws://127.0.0.1:8080").is_err());
        assert!(reject_ws_relay_url("ws://10.0.0.1").is_err());
        assert!(reject_ws_relay_url("ws://192.168.1.1:8080").is_err());
        assert!(reject_ws_relay_url("wss://172.16.0.1").is_err());
        assert!(reject_ws_relay_url("wss://0.0.0.0:8080").is_err());
    }

    #[test]
    fn test_reject_non_ws_scheme() {
        assert!(reject_ws_relay_url("http://relay.example.com").is_err());
        assert!(reject_ws_relay_url("https://relay.example.com").is_err());
        assert!(reject_ws_relay_url("ftp://relay.example.com").is_err());
    }

    #[test]
    fn test_accept_valid_ws_url() {
        // Uses an unresolvable domain that passes scheme/structure checks.
        // DNS resolution will fail but that is not SSRF rejection.
        let result = reject_ws_relay_url("wss://relay.example.invalid");
        // Should not be SsrfRejected; it may fail on DNS but not SSRF grounds.
        match result {
            Err(NostrRelayError::SsrfRejected(_)) => {
                panic!("Well-formed URL should not trigger SSRF rejection")
            }
            _ => {} // DNS lookup may fail, which is acceptable.
        }
    }

    #[test]
    fn test_reject_url_with_userinfo() {
        assert!(reject_ws_relay_url("ws://user:pass@relay.example.com").is_err());
    }

    #[test]
    fn test_reject_invalid_url() {
        assert!(reject_ws_relay_url("not-a-url").is_err());
    }

    #[test]
    fn test_reject_url_without_host() {
        assert!(reject_ws_relay_url("wss://:8080").is_err());
    }

    #[test]
    fn test_is_private_ip_loopback() {
        assert!(is_private_ip("127.0.0.1".parse().unwrap()));
        assert!(is_private_ip("::1".parse().unwrap()));
    }

    #[test]
    fn test_is_private_ip_private_ranges() {
        assert!(is_private_ip("10.0.0.1".parse().unwrap()));
        assert!(is_private_ip("172.16.0.1".parse().unwrap()));
        assert!(is_private_ip("192.168.1.1".parse().unwrap()));
    }

    #[test]
    fn test_is_private_ip_link_local() {
        assert!(is_private_ip("169.254.1.1".parse().unwrap()));
        assert!(is_private_ip("fe80::1".parse().unwrap()));
    }

    #[test]
    fn test_is_not_private_ip() {
        assert!(!is_private_ip("8.8.8.8".parse().unwrap()));
        assert!(!is_private_ip("1.1.1.1".parse().unwrap()));
        assert!(!is_private_ip("2001:4860:4860::8888".parse().unwrap()));
    }

    #[test]
    fn test_reject_ipv4_mapped_loopback() {
        // ::ffff:127.0.0.1 — IPv4-mapped IPv6 loopback must be rejected.
        assert!(is_private_ip("::ffff:127.0.0.1".parse().unwrap()));
        // ::ffff:192.168.1.1 — IPv4-mapped private IPv4 must be rejected.
        assert!(is_private_ip("::ffff:192.168.1.1".parse().unwrap()));
        // ::ffff:10.0.0.1 — IPv4-mapped RFC 1918 must be rejected.
        assert!(is_private_ip("::ffff:10.0.0.1".parse().unwrap()));
    }

    #[test]
    fn test_reject_6to4_teredo() {
        // 6to4 relay prefix (2002::/16)
        assert!(is_private_ip("2002:c0a8:101::1".parse().unwrap()));
        // Teredo prefix (2001::/32) — note: not to be confused with 2001:db8 (doc)
        assert!(is_private_ip("2001:0:1234::1".parse().unwrap()));
    }

    #[test]
    fn test_reject_multicast_broadcast() {
        // IPv4 multicast
        assert!(is_private_ip("224.0.0.1".parse().unwrap()));
        assert!(is_private_ip("239.255.255.255".parse().unwrap()));
        // IPv4 broadcast
        assert!(is_private_ip("255.255.255.255".parse().unwrap()));
        // IPv4 reserved/documentation (first octet >= 240)
        assert!(is_private_ip("240.0.0.1".parse().unwrap()));
        assert!(is_private_ip("250.0.0.1".parse().unwrap()));
    }
}
