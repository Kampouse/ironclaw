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

/// Check if an IP address is private, loopback, link-local, or reserved.
fn is_private_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_unspecified()
                || (v4.octets()[0] == 100 && (v4.octets()[1] & 0xC0) == 64)
        }
        IpAddr::V6(v6) => {
            v6.is_loopback()
                || v6.is_unspecified()
                || (v6.segments()[0] & 0xFE00) == 0xFC00
                || (v6.segments()[0] & 0xFFC0) == 0xFE80
        }
    }
}

/// Publish a signed Nostr event to a relay via WebSocket.
///
/// Opens a WebSocket connection, sends the EVENT message,
/// and waits for the relay's OK/NACK response.
///
/// Returns the event ID on success.
pub async fn publish_nostr_event(
    relay_url: &str,
    signed_event_json: &str,
) -> Result<String, WasmHostError> {
    reject_ws_relay_url(relay_url)?;

    use futures_util::{SinkExt, StreamExt};
    use tokio_tungstenite::tungstenite::Message;

    let (ws_stream, _) = tokio_tungstenite::connect_async(relay_url)
        .await
        .map_err(|e| NostrRelayError::WebSocket(format!("WebSocket connect failed: {e}")))?;

    let (mut write, mut read) = ws_stream.split();

    // Build and send EVENT message
    let event_val: serde_json::Value = serde_json::from_str(signed_event_json)
        .map_err(|e| NostrRelayError::InvalidInput(format!("Invalid event JSON: {e}")))?;

    let msg = serde_json::json!(["EVENT", event_val]);
    write
        .send(Message::Text(msg.to_string().into()))
        .await
        .map_err(|e| NostrRelayError::WebSocket(format!("WebSocket send failed: {e}")))?;

    // Read OK response with 10s timeout
    let result = tokio::time::timeout(std::time::Duration::from_secs(10), async {
        while let Some(Ok(msg)) = read.next().await {
            if let Message::Text(text) = msg {
                if let Ok(arr) = serde_json::from_str::<Vec<serde_json::Value>>(&text) {
                    if arr.len() >= 3 && arr[0] == "OK" {
                        let event_id = arr[1].as_str().unwrap_or("").to_string();
                        let accepted = arr.get(2).and_then(|v| v.as_bool()).unwrap_or(false);
                        if accepted {
                            return Ok::<String, NostrRelayError>(event_id);
                        } else {
                            let reason = arr.get(3).and_then(|v| v.as_str()).unwrap_or("unknown");
                            return Err(NostrRelayError::Relay(format!("Relay rejected: {reason}")));
                        }
                    }
                }
            }
        }
        Err(NostrRelayError::Relay("WebSocket closed without OK".to_string()))
    })
    .await
    .map_err(|_| NostrRelayError::WebSocket("Timeout waiting for relay OK response".to_string()))?;

    result.map_err(WasmHostError::from)
}

/// Subscribe to Nostr events from a relay via WebSocket.
///
/// Connects, sends REQ with filters, collects matching events for `timeout_ms`,
/// sends CLOSE, returns JSON array of collected events.
pub async fn subscribe_nostr_events(
    relay_url: &str,
    filter_json: &str,
    timeout_ms: u32,
) -> Result<String, WasmHostError> {
    reject_ws_relay_url(relay_url)?;

    use futures_util::{SinkExt, StreamExt};
    use tokio_tungstenite::tungstenite::Message;

    let (ws_stream, _) = tokio_tungstenite::connect_async(relay_url)
        .await
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

    // Collect events until timeout
    let mut events: Vec<serde_json::Value> = Vec::new();

    let _ = tokio::time::timeout(std::time::Duration::from_millis(timeout_ms as u64), async {
        while let Some(Ok(msg)) = read.next().await {
            if let Message::Text(text) = msg {
                if let Ok(arr) = serde_json::from_str::<Vec<serde_json::Value>>(&text) {
                    if arr.len() >= 3 && arr[0] == "EVENT" {
                        // arr[1] is sub_id, arr[2] is the event
                        events.push(arr[2].clone());
                        if events.len() >= MAX_COLLECTED_EVENTS {
                            break;
                        }
                    }
                }
            }
        }
    })
    .await;

    // Send CLOSE
    let close_msg = serde_json::json!(["CLOSE", sub_id]);
    let _ = write
        .send(Message::Text(close_msg.to_string().into()))
        .await;

    serde_json::to_string(&events)
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
        // Won't reject if DNS resolution passes (may fail on DNS lookup, not SSRF)
        // We just check it doesn't reject on scheme
        assert!(reject_ws_relay_url("wss://nos.lol").is_ok());
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
}
