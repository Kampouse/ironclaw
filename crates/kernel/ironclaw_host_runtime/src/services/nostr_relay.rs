//! Nostr relay I/O with SSRF protection.
//!
//! Host-side relay I/O: publish events and subscribe to event streams.
//!
//! # Why this module lives in `ironclaw_host_runtime` (not `ironclaw_wasm`)
//!
//! Direct WebSocket connections violate the "no direct networking in any lane"
//! rule enforced by `reborn_runtime_http_egress_has_single_network_boundary`.
//! The relay I/O functions that open WebSocket connections live here, in the
//! kernel's host-runtime crate, and are called by [`KernelNostrHost`] in
//! `runtime_adapters.rs`.
//!
//! Pure validation helpers (SSRF checks, URL validation) remain in
//! `ironclaw_wasm::nostr_relay` — they are pure functions with no network I/O.

use std::sync::LazyLock;

use ironclaw_wasm::validate_relay_url;
use ironclaw_wasm::WasmHostError;

/// Error type for Nostr relay operations.
#[derive(Debug, thiserror::Error)]
pub(crate) enum NostrRelayError {
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

/// Derive a connect timeout from the remaining execution deadline.
///
/// Caps at `DEFAULT_CONNECT_TIMEOUT_MS` (10s) to avoid long hangs.
/// Falls back to the default when no deadline is specified.
#[expect(dead_code, reason = "used by async relay functions in this module")]
fn connect_timeout_for(remaining_deadline_ms: Option<u32>) -> std::time::Duration {
    let ms = remaining_deadline_ms
        .map(|d| (d as u64).min(DEFAULT_CONNECT_TIMEOUT_MS))
        .unwrap_or(DEFAULT_CONNECT_TIMEOUT_MS);
    std::time::Duration::from_millis(ms)
}

/// Dedicated Tokio runtime for Nostr relay egress.
///
/// Lazily initialised on first use.
static NOSTR_EGRESS_RUNTIME: LazyLock<Result<tokio::runtime::Runtime, WasmHostError>> =
    LazyLock::new(|| {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .thread_name("ironclaw-nostr-egress")
            .enable_all()
            .build()
            .map_err(|e| WasmHostError::Failed(format!("nostr egress runtime: {e}")))
    });

/// Publish a signed Nostr event to a relay via WebSocket.
///
/// Opens a WebSocket connection, sends the EVENT message,
/// and waits for the relay's OK/NACK response.
///
/// `remaining_deadline_ms` is an optional overall deadline for the operation
/// (including connect and read). When `None`, a default 10s connect timeout is used.
///
/// Returns the event ID on success.
pub(crate) async fn publish_nostr_event(
    relay_url: &str,
    signed_event_json: &str,
    remaining_deadline_ms: Option<u32>,
) -> Result<String, WasmHostError> {
    validate_relay_url(relay_url)?;
    use futures_util::{SinkExt, StreamExt};
    use tokio_tungstenite::tungstenite::Message;

    let connect_start = std::time::Instant::now();

    let connect_timeout = connect_timeout_for(remaining_deadline_ms);

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
        .send(Message::Text(msg.to_string()))
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
            if let Message::Text(text) = msg
                && let Ok(arr) = serde_json::from_str::<Vec<serde_json::Value>>(&text)
                    && arr.len() >= 3
                    && arr[0] == "OK"
            {
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
pub(crate) async fn subscribe_nostr_events(
    relay_url: &str,
    filter_json: &str,
    timeout_ms: u32,
    remaining_deadline_ms: Option<u32>,
) -> Result<String, WasmHostError> {
    validate_relay_url(relay_url)?;
    use futures_util::{SinkExt, StreamExt};
    use tokio_tungstenite::tungstenite::Message;

    let connect_start = std::time::Instant::now();

    let connect_timeout = connect_timeout_for(remaining_deadline_ms);

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
        .send(Message::Text(req_text))
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
                if let Message::Text(text) = msg
                    && let Ok(arr) = serde_json::from_str::<Vec<serde_json::Value>>(&text)
                        && arr.len() >= 3
                        && arr[0] == "EVENT"
                {
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
        .send(Message::Text(close_msg.to_string()))
        .await;

    // Return structured response with truncation indicator.
    let response = serde_json::json!({
        "events": events,
        "truncated": truncated,
    });
    serde_json::to_string(&response)
        .map_err(|e| WasmHostError::Failed(format!("Failed to serialize events: {e}")))
}

/// Block on an async future using the dedicated Nostr egress runtime.
///
/// Uses the same thread-scope + block_on pattern as the kernel's
/// `block_on_filesystem` in http_body.rs: spawn a dedicated thread inside
/// `std::thread::scope`, call `block_on` there, and wrap the result in
/// `catch_unwind` so panics are reported as errors rather than aborting.
pub(crate) fn block_on_nostr<F, T>(future: F) -> Result<T, WasmHostError>
where
    F: std::future::Future<Output = Result<T, WasmHostError>> + Send + 'static,
    T: Send + 'static,
{
    use std::panic::AssertUnwindSafe;

    let runtime = NOSTR_EGRESS_RUNTIME.as_ref().map_err(|e| e.clone())?;
    let handle = runtime.handle().clone();
    std::thread::scope(|scope| {
        let joined = scope.spawn(move || {
            let result =
                std::panic::catch_unwind(AssertUnwindSafe(|| handle.block_on(future)));
            match result {
                Ok(Ok(value)) => Ok(value),
                Ok(Err(error)) => Err(error),
                Err(_) => Err(WasmHostError::Failed(
                    "Nostr egress task panicked".to_string(),
                )),
            }
        });
        joined.join().unwrap_or_else(|_| {
            Err(WasmHostError::Failed(
                "Nostr egress thread panicked".to_string(),
            ))
        })
    })
}
