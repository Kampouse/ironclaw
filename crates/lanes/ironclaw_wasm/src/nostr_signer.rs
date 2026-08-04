//! Nostr event signing for WASM tools.
//!
//! Implements host-side Nostr event signing: the host holds the private key,
//! WASM provides the unsigned event, and the host returns a fully signed event.
//!
//! Follows the NIP-01 event serialization and signing spec:
//! 1. Serialize event fields as `[0, pubkey, created_at, kind, tags, content]`
//! 2. SHA-256 hash the serialized JSON
//! 3. Schnorr sign the hash with the private key (BIP-340)
//! 4. Return the complete event with `id` and `sig` fields

use sha2::{Digest, Sha256};
use crate::WasmHostError;

/// Error type for Nostr signing operations.
#[derive(Debug, thiserror::Error)]
pub enum NostrSignError {
    #[error("Invalid unsigned event: {0}")]
    InvalidEvent(String),

    #[error("Invalid private key: {0}")]
    InvalidKey(String),

    #[error("Signing failed: {0}")]
    SigningFailed(String),
}

impl From<NostrSignError> for WasmHostError {
    fn from(err: NostrSignError) -> Self {
        WasmHostError::Failed(err.to_string())
    }
}

/// Decode a Nostr private key from hex or nsec bech32 format.
/// Returns the raw 32-byte secret key.
pub fn decode_nostr_private_key(key: &str) -> Result<[u8; 32], NostrSignError> {
    let trimmed = key.trim();

    // Try hex first (64 hex chars → 32 bytes)
    if let Ok(bytes) = hex_decode(trimmed) {
        if bytes.len() == 32 {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            return Ok(arr);
        }
        return Err(NostrSignError::InvalidKey(format!(
            "hex key must be 32 bytes, got {}",
            bytes.len()
        )));
    }

    // Try nsec bech32 (nsec1... prefix, 5-bit encoded)
    if trimmed.starts_with("nsec1") {
        return decode_nsec_bech32(trimmed);
    }

    Err(NostrSignError::InvalidKey(
        "key must be 64-char hex or nsec1... bech32".to_string(),
    ))
}

/// Decode hex string to bytes (no external dependency).
fn hex_decode(s: &str) -> Result<Vec<u8>, ()> {
    if s.len() % 2 != 0 {
        return Err(());
    }
    let mut bytes = Vec::with_capacity(s.len() / 2);
    for i in (0..s.len()).step_by(2) {
        let byte = u8::from_str_radix(&s[i..i + 2], 16).map_err(|_| ())?;
        bytes.push(byte);
    }
    Ok(bytes)
}

/// Encode bytes to hex string.
fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Minimal bech32 decode for nsec keys (no external dependency).
/// nsec uses bech32 with HRP "nsec", converts 5-bit groups to 8-bit bytes.
fn decode_nsec_bech32(bech32_str: &str) -> Result<[u8; 32], NostrSignError> {
    // Bech32 charset (lowercase)
    const CHARSET: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";

    let pos = bech32_str.rfind('1').ok_or_else(|| {
        NostrSignError::InvalidKey("bech32: missing separator '1'".to_string())
    })?;

    // Extract HRP (everything before last '1') — keep original case for checksum
    let hrp = &bech32_str[..pos];
    let data_part = &bech32_str[pos + 1..];
    let data_part_upper = data_part.to_uppercase();

    // Verify minimum length: 6-char checksum + at least 1 data char
    if data_part_upper.len() < 6 {
        return Err(NostrSignError::InvalidKey(
            "bech32: data part too short".to_string(),
        ));
    }

    let data_len = data_part_upper.len() - 6;
    let data_part_without_checksum = &data_part_upper[..data_len];

    // Verify HRP (case-insensitive comparison)
    if hrp.to_lowercase() != "nsec" {
        return Err(NostrSignError::InvalidKey(format!(
            "bech32: expected HRP 'nsec', got '{}'",
            hrp
        )));
    }

    // Expand HRP (case-sensitive for checksum verification)
    let mut expanded = Vec::with_capacity(hrp.len() * 2 + 7);
    for c in hrp.chars() {
        expanded.push((c as u8) >> 5);
    }
    expanded.push(0u8);
    for c in hrp.chars() {
        expanded.push((c as u8) & 31);
    }

    // Decode data characters to 5-bit values
    for c in data_part_upper.chars() {
        let byte = c as u8;
        let idx = CHARSET.iter().position(|&ch| ch == byte.to_ascii_lowercase())
            .ok_or_else(|| {
                NostrSignError::InvalidKey(format!("bech32: invalid character '{c}'"))
            })?;
        expanded.push(idx as u8);
    }

    // Verify checksum (bech32 checksum constant = 1)
    let checksum = bech32_polymod(&expanded);
    if checksum != 1 {
        return Err(NostrSignError::InvalidKey(
            "bech32: invalid checksum".to_string(),
        ));
    }

    // Convert 5-bit groups to 8-bit bytes
    let mut five_bit: Vec<u8> = Vec::with_capacity(data_len);
    for c in data_part_without_checksum.chars() {
        let byte = c as u8;
        let idx = CHARSET.iter().position(|&ch| ch == byte.to_ascii_lowercase())
            .ok_or_else(|| {
                NostrSignError::InvalidKey(format!("bech32: invalid data character '{c}'"))
            })?;
        five_bit.push(idx as u8);
    }

    // 5-bit → 8-bit conversion
    let mut bytes = Vec::new();
    let mut buffer: u64 = 0;
    let mut bits = 0u32;
    for &val in &five_bit {
        buffer = (buffer << 5) | (val as u64);
        bits += 5;
        while bits >= 8 {
            bits -= 8;
            bytes.push((buffer >> bits) as u8);
        }
    }

    if bytes.len() != 32 {
        return Err(NostrSignError::InvalidKey(format!(
            "nsec decoded to {} bytes, expected 32",
            bytes.len()
        )));
    }

    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}

/// Bech32 checksum polynomial.
fn bech32_polymod(values: &[u8]) -> u32 {
    const GENERATORS: [u32; 5] = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
    let mut chk: u32 = 1;
    for &v in values {
        let top = (chk >> 25) as u8;
        chk = (chk & 0x1ffffff) << 5 ^ v as u32;
        for i in 0..5 {
            if (top >> i) & 1 == 1 {
                chk ^= GENERATORS[i];
            }
        }
    }
    chk
}

/// Sign an unsigned Nostr event with a private key.
///
/// The unsigned event JSON must contain: `pubkey`, `created_at`, `kind`, `tags`, `content`.
/// The `pubkey` in the event must match the public key derived from the private key.
///
/// Returns the complete signed event JSON string with `id` and `sig` added.
pub fn sign_nostr_event(
    unsigned_json: &str,
    private_key_bytes: &[u8; 32],
) -> Result<String, NostrSignError> {
    use secp256k1::{Keypair, Secp256k1, SecretKey, Message};

    let mut event: serde_json::Value =
        serde_json::from_str(unsigned_json).map_err(|e| NostrSignError::InvalidEvent(e.to_string()))?;

    // Validate required fields
    let _kind = event
        .get("kind")
        .ok_or_else(|| NostrSignError::InvalidEvent("missing 'kind' field".into()))?
        .as_u64()
        .ok_or_else(|| NostrSignError::InvalidEvent("'kind' must be a number".into()))?;

    let _content = event
        .get("content")
        .ok_or_else(|| NostrSignError::InvalidEvent("missing 'content' field".into()))?;

    let _tags = event
        .get("tags")
        .ok_or_else(|| NostrSignError::InvalidEvent("missing 'tags' field".into()))?;

    let _created_at = event
        .get("created_at")
        .ok_or_else(|| NostrSignError::InvalidEvent("missing 'created_at' field".into()))?
        .as_u64()
        .ok_or_else(|| NostrSignError::InvalidEvent("'created_at' must be a number".into()))?;

    let event_pubkey = event
        .get("pubkey")
        .ok_or_else(|| NostrSignError::InvalidEvent("missing 'pubkey' field".into()))?
        .as_str()
        .ok_or_else(|| NostrSignError::InvalidEvent("'pubkey' must be a string".into()))?
        .to_string();

    // Create keypair from the host-held private key
    let secp = Secp256k1::new();
    let secret_key = SecretKey::from_slice(private_key_bytes)
        .map_err(|e| NostrSignError::InvalidKey(format!("invalid secret key bytes: {e}")))?;
    let key_pair = Keypair::from_secret_key(&secp, &secret_key);

    // Derive x-only public key and verify it matches the event pubkey
    let (x_only_pubkey, _) = key_pair.x_only_public_key();
    let derived_pubkey = hex_encode(&x_only_pubkey.serialize());
    if derived_pubkey != event_pubkey {
        return Err(NostrSignError::SigningFailed(format!(
            "event pubkey {event_pubkey} does not match keypair pubkey {derived_pubkey}"
        )));
    }

    // Serialize event for ID computation: [0, pubkey, created_at, kind, tags, content]
    let serialized = serde_json::to_string(&serde_json::json!([
        0,
        event["pubkey"],
        event["created_at"],
        event["kind"],
        event["tags"],
        event["content"],
    ]))
    .map_err(|e| NostrSignError::InvalidEvent(format!("failed to serialize event: {e}")))?;

    // Compute event ID: SHA-256 of serialized event
    let mut hasher = Sha256::new();
    hasher.update(serialized.as_bytes());
    let event_id = hasher.finalize();
    let event_id_hex = hex_encode(&event_id);

    // Create message and sign with Schnorr
    let msg = Message::from_digest_slice(&event_id)
        .map_err(|e| NostrSignError::SigningFailed(format!("invalid message: {e}")))?;
    let aux_rand_bytes = SecretKey::new(&mut secp256k1::rand::thread_rng()).secret_bytes();
    let signature = secp.sign_schnorr_with_aux_rand(&msg, &key_pair, &aux_rand_bytes);

    // Add id and sig to the event
    if let Some(obj) = event.as_object_mut() {
        obj.insert("id".to_string(), serde_json::Value::String(event_id_hex));
        obj.insert("sig".to_string(), serde_json::Value::String(signature.to_string()));
    }

    serde_json::to_string(&event)
        .map_err(|e| NostrSignError::SigningFailed(format!("failed to serialize signed event: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Known test vector: deterministic key for testing.
    /// Private key: 000...001
    /// Public key (x-only): 79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798

    fn make_test_privkey() -> [u8; 32] {
        let mut key = [0u8; 32];
        key[31] = 1;
        key
    }

    #[test]
    fn test_decode_hex_private_key() {
        let bytes = decode_nostr_private_key(
            "0000000000000000000000000000000000000000000000000000000000000001",
        )
        .unwrap();
        assert_eq!(bytes.len(), 32);
        assert_eq!(bytes[31], 1);
    }

    #[test]
    fn test_decode_nsec_bech32_private_key() {
        // nsec encoding of key 000...001
        let nsec = "nsec1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqsmhltgl";
        let bytes = decode_nostr_private_key(nsec).unwrap();
        assert_eq!(bytes.len(), 32);
        assert_eq!(bytes[31], 1);
    }

    #[test]
    fn test_decode_nsec_roundtrip_with_hex() {
        let hex = "0000000000000000000000000000000000000000000000000000000000000001";
        let nsec = "nsec1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqsmhltgl";
        let from_hex = decode_nostr_private_key(hex).unwrap();
        let from_nsec = decode_nostr_private_key(nsec).unwrap();
        assert_eq!(from_hex, from_nsec, "hex and nsec must decode to same bytes");
    }

    #[test]
    fn test_reject_wrong_hrp_bech32() {
        // npub is a public key HRP, not valid for secret key decoding
        let npub = "npub1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq39ehqx";
        let result = decode_nostr_private_key(npub);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("nsec"),
            "wrong HRP prefix should be rejected: {err}"
        );
    }

    #[test]
    fn test_reject_invalid_key_format() {
        let result = decode_nostr_private_key("totally_wrong_format");
        assert!(result.is_err());
    }

    #[test]
    fn test_sign_simple_event() {
        let privkey = make_test_privkey();
        let pubkey = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";

        let unsigned = r#"{
            "pubkey": "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
            "created_at": 1690000000,
            "kind": 1,
            "tags": [],
            "content": "hello from nostr"
        }"#;

        let result = sign_nostr_event(unsigned, &privkey).expect("signing failed");
        let event: serde_json::Value = serde_json::from_str(&result).unwrap();

        // Must have id and sig
        assert!(event.get("id").unwrap().is_string());
        let sig = event.get("sig").unwrap().as_str().unwrap();
        // Schnorr sig is 128 hex chars (64 bytes)
        assert_eq!(sig.len(), 128);

        // id is SHA-256 hex (64 chars)
        let id = event.get("id").unwrap().as_str().unwrap();
        assert_eq!(id.len(), 64);
    }

    #[test]
    fn test_reject_wrong_pubkey() {
        let privkey = make_test_privkey();

        let unsigned = r#"{
            "pubkey": "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            "created_at": 1690000000,
            "kind": 1,
            "tags": [],
            "content": "hello"
        }"#;

        let result = sign_nostr_event(unsigned, &privkey);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("does not match keypair pubkey"),
            "err: {err}"
        );
    }

    #[test]
    fn test_reject_missing_fields() {
        let privkey = make_test_privkey();
        let unsigned = r#"{"kind": 1}"#;

        let result = sign_nostr_event(unsigned, &privkey);
        assert!(result.is_err());
    }

    #[test]
    fn test_reject_invalid_private_key_bytes() {
        // secp256k1 rejects the zero key
        let zero_key = [0u8; 32];
        let unsigned = r#"{
            "pubkey": "0000000000000000000000000000000000000000000000000000000000000000",
            "created_at": 1690000000,
            "kind": 1,
            "tags": [],
            "content": "hello"
        }"#;

        let result = sign_nostr_event(unsigned, &zero_key);
        assert!(result.is_err());
    }
}
