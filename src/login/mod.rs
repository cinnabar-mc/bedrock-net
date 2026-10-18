//! Network-level Login requests and verified server key exchange.
//!
//! The caller owns the connection proof key, UTC clock and client-data schema.
//! These helpers return the opaque request consumed by protocolgen's Login packet
//! and the existing directional batch ciphers. They perform no I/O or account authentication.

mod error;
mod jwt;

use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use bytes::Bytes;
use p384::ecdsa::SigningKey;
use p384::pkcs8::EncodePublicKey;
use serde::Serialize;
use serde_json::value::RawValue;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::encryption::{BatchDecryptor, BatchEncryptor};

pub use error::LoginError;

const OFFLINE_VALIDITY_SECONDS: i64 = 6 * 60 * 60;
const MULTIPLAYER_AUDIENCE: &str = "api://auth-minecraft-services/multiplayer";

/// Explicit identity claims for a self-signed, unauthenticated Login.
///
/// Values are preserved as supplied. Clearing account-only fields and supplying
/// default names or UUIDs belong to the application, rather than the wire encoder.
pub struct OfflineIdentity<'a> {
    /// Player name presented to the server.
    pub display_name: &'a str,
    /// Offline UUID string; an empty value is omitted from the token.
    pub identity: &'a str,
    /// Explicit Xbox identifier, normally empty for an offline identity.
    pub xuid: &'a str,
    /// Explicit PlayFab master-player identifier, normally empty offline.
    pub playfab_id: &'a str,
    /// Explicit PlayFab title identifier, normally empty offline.
    pub playfab_title_id: &'a str,
}

#[derive(Serialize)]
struct OfflineClaims<'a> {
    aud: &'static str,
    exp: i64,
    nbf: i64,
    ipt: &'static str,
    mid: &'a str,
    tid: &'a str,
    cpk: &'a str,
    xid: &'a str,
    xname: &'a str,
    #[serde(skip_serializing_if = "str::is_empty")]
    leguuid: &'a str,
}

#[derive(Serialize)]
struct AuthEnvelope<'a> {
    #[serde(rename = "AuthenticationType")]
    authentication_type: u8,
    #[serde(rename = "Token")]
    token: &'a str,
}

/// Encodes a self-signed Login connection request using the connection's proof key.
///
/// `client_data` is already validated JSON owned by the application's metadata
/// schema. Its representation is retained and terminated with a newline before
/// signing. Use the same key for identity-aware transport and key exchange.
/// The returned bytes exclude the packet header and protocol version.
///
/// # Errors
/// Returns a size, timestamp, serialization, key or signature error before
/// exposing any partial request. `max_request_bytes` bounds the complete result.
pub fn encode_offline_request(
    key: &SigningKey,
    identity: &OfflineIdentity<'_>,
    client_data: &RawValue,
    now: SystemTime,
    max_request_bytes: usize,
) -> Result<Bytes, LoginError> {
    validate_client_data(client_data, max_request_bytes)?;
    let now = unix_seconds(now)?;
    let exp = now
        .checked_add(OFFLINE_VALIDITY_SECONDS)
        .ok_or(LoginError::InvalidTime)?;
    let nbf = now
        .checked_sub(OFFLINE_VALIDITY_SECONDS)
        .ok_or(LoginError::InvalidTime)?;
    let der = key
        .verifying_key()
        .to_public_key_der()
        .map_err(LoginError::PublicKey)?;
    let public_key = STANDARD.encode(der.as_bytes());
    let claims = OfflineClaims {
        aud: MULTIPLAYER_AUDIENCE,
        exp,
        nbf,
        ipt: "",
        mid: identity.playfab_id,
        tid: identity.playfab_title_id,
        cpk: &public_key,
        xid: identity.xuid,
        xname: identity.display_name,
        leguuid: identity.identity,
    };
    let claims = jwt::json_line(&claims, max_request_bytes)?;
    let token = jwt::sign(key, &public_key, &claims, max_request_bytes)?;
    let envelope = jwt::json_line(
        &AuthEnvelope {
            authentication_type: 2,
            token: &token,
        },
        max_request_bytes,
    )?;
    encode_request(key, &public_key, &envelope, client_data, max_request_bytes)
}

/// Encodes a Login using an already acquired multiplayer credential.
///
/// The caller acquires the token for this key and retains the same private owner
/// through client-data signing and server key exchange. The token is preserved;
/// this formatter performs no account I/O or issuer verification. Client data
/// remains application-owned JSON. Returned bytes exclude the packet header
/// and protocol version.
///
/// # Errors
/// Rejects an empty or oversized token, non-object client data and encoding,
/// key or signature failures before returning a partial request.
pub fn encode_authenticated_request(
    key: &SigningKey,
    multiplayer_token: &str,
    client_data: &RawValue,
    max_request_bytes: usize,
) -> Result<Bytes, LoginError> {
    if multiplayer_token.is_empty() {
        return Err(LoginError::EmptyAuthenticationToken);
    }
    if multiplayer_token.len() > max_request_bytes {
        return Err(LoginError::LimitExceeded {
            limit: max_request_bytes,
        });
    }
    validate_client_data(client_data, max_request_bytes)?;
    let der = key
        .verifying_key()
        .to_public_key_der()
        .map_err(LoginError::PublicKey)?;
    let public_key = STANDARD.encode(der.as_bytes());
    let envelope = jwt::json_line(
        &AuthEnvelope {
            authentication_type: 0,
            token: multiplayer_token,
        },
        max_request_bytes,
    )?;
    encode_request(key, &public_key, &envelope, client_data, max_request_bytes)
}

/// Rejects non-object or oversized application JSON before any signature work.
fn validate_client_data(client_data: &RawValue, limit: usize) -> Result<(), LoginError> {
    if !client_data.get().trim_start().starts_with('{') {
        return Err(LoginError::InvalidClientData);
    }
    if client_data.get().len() > limit {
        return Err(LoginError::LimitExceeded { limit });
    }
    Ok(())
}

/// Signs validated application JSON and frames the complete, bounded request.
fn encode_request(
    key: &SigningKey,
    public_key: &str,
    envelope: &[u8],
    client_data: &RawValue,
    max_request_bytes: usize,
) -> Result<Bytes, LoginError> {
    let mut client_json = client_data.get().as_bytes().to_vec();
    client_json.push(b'\n');
    let client_token = jwt::sign(key, public_key, &client_json, max_request_bytes)?;
    let size = 8_usize
        .checked_add(envelope.len())
        .and_then(|size| size.checked_add(client_token.len()))
        .ok_or(LoginError::InvalidLength)?;
    if size > max_request_bytes {
        return Err(LoginError::LimitExceeded {
            limit: max_request_bytes,
        });
    }
    let envelope_len = i32::try_from(envelope.len()).map_err(|_| LoginError::InvalidLength)?;
    let client_len = i32::try_from(client_token.len()).map_err(|_| LoginError::InvalidLength)?;
    let mut request = Vec::with_capacity(size);
    request.extend_from_slice(&envelope_len.to_le_bytes());
    request.extend_from_slice(envelope);
    request.extend_from_slice(&client_len.to_le_bytes());
    request.extend_from_slice(client_token.as_bytes());
    Ok(request.into())
}

/// Verifies the server token and derives outgoing and incoming batch ciphers.
///
/// The token's signature proves possession of its `x5u` key; it does not establish
/// server trust. Endpoint authentication belongs to the transport/application.
/// Call once for an accepted handshake and retain both streams for the session;
/// never restart them with the same derived key.
///
/// # Errors
/// Rejects oversized or malformed tokens, unsupported headers, invalid public
/// keys/signatures and invalid salt before creating either cipher direction.
pub fn finish_key_exchange(
    key: &SigningKey,
    server_token: &str,
    max_token_bytes: usize,
) -> Result<(BatchEncryptor, BatchDecryptor), LoginError> {
    let (public, salt) = jwt::verify_server(server_token, max_token_bytes)?;
    let shared = p384::ecdh::diffie_hellman(key.as_nonzero_scalar(), public.as_affine());
    let mut hash = Sha256::new();
    hash.update(salt);
    hash.update(shared.raw_secret_bytes());
    let mut session_key = Zeroizing::new([0_u8; 32]);
    hash.finalize_into((&mut *session_key).into());
    Ok((
        BatchEncryptor::new(*session_key),
        BatchDecryptor::new(*session_key),
    ))
}

/// Converts UTC to Unix seconds, rounding fractional pre-epoch values downward.
fn unix_seconds(now: SystemTime) -> Result<i64, LoginError> {
    match now.duration_since(UNIX_EPOCH) {
        Ok(elapsed) => i64::try_from(elapsed.as_secs()).map_err(|_| LoginError::InvalidTime),
        Err(error) => {
            let elapsed = error.duration();
            let seconds = elapsed
                .as_secs()
                .checked_add(u64::from(elapsed.subsec_nanos() != 0))
                .ok_or(LoginError::InvalidTime)?;
            i64::try_from(seconds)
                .ok()
                .and_then(i64::checked_neg)
                .ok_or(LoginError::InvalidTime)
        }
    }
}

#[cfg(test)]
mod tests;
