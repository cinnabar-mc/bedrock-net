//! Opaque offline Login capability, with account claims kept separate from provider authority.

use super::{ClientExchangeKey, LoginError, client_data, jwt};
use std::time::SystemTime;

mod claims;
use claims::{Identity, Registered};
use jwt::Object;
use serde_json::value::RawValue;

/// Untrusted identity text retained without an authenticated player projection.
#[derive(Default)]
pub(super) struct Claims {
    pub(super) name: String,
    pub(super) xuid: String,
    pub(super) uuid: String,
    pub(super) projected_uuid: String,
    pub(super) playfab_id: String,
    pub(super) playfab_title_id: String,
}

/// Validated client-signed metadata with explicitly untrusted account claims.
///
/// This owner proves the metadata signature under the supplied identity key,
/// not an account or possession of a rotated exchange key. Application admission
/// and the original connection deadline remain caller-owned. No later provider
/// revalidation is applicable to this owner.
///
/// It cannot be converted into provider-authenticated authority:
/// ```compile_fail
/// use bedrock_net::login::{AuthenticatedLogin, OfflineLogin};
/// fn authenticated(_: AuthenticatedLogin) {}
/// fn admit(login: OfflineLogin) { authenticated(login); }
/// ```
/// ```compile_fail
/// use bedrock_net::login::{OfflineLogin, TrustedIdentity};
/// fn promote(login: OfflineLogin) -> TrustedIdentity { login.into() }
/// ```
/// ```compile_fail
/// use bedrock_net::login::OfflineLogin;
/// let forged = OfflineLogin::default();
/// ```
pub struct OfflineLogin {
    identity: Claims,
    signing_key: ClientExchangeKey,
    exchange_key: ClientExchangeKey,
    metadata: client_data::Payload,
}

impl OfflineLogin {
    /// Borrows the exact key that verified the original client metadata JWT.
    pub fn signing_key(&self) -> &ClientExchangeKey {
        &self.signing_key
    }

    /// Borrows the final signed key for transport comparison and key exchange.
    pub fn exchange_key(&self) -> &ClientExchangeKey {
        &self.exchange_key
    }

    /// Borrows validated presentation; unauthenticated requests use ThirdPartyName.
    /// This accessor grants no provider or world identity authority.
    pub fn display_name(&self) -> &str {
        &self.identity.name
    }

    /// Borrows validated client JSON, retaining its original spelling for valid UTF-8.
    pub fn client_data(&self) -> &RawValue {
        self.metadata.client_data()
    }

    /// Borrows the original signed JSON value bytes before UTF-8 replacement.
    /// Insignificant whitespace surrounding the JSON value is omitted.
    pub fn client_data_json_bytes(&self) -> &[u8] {
        self.metadata.client_data_json_bytes()
    }

    /// Borrows the client-signed nonce; it grants no world access.
    pub fn nonce(&self) -> &str {
        self.metadata.nonce()
    }

    /// Borrows an untrusted, shape-checked XUID claim; it grants no account authority.
    pub fn claimed_xuid(&self) -> &str {
        &self.identity.xuid
    }

    /// Borrows the original untrusted UUID text, which may be empty or malformed.
    pub fn legacy_uuid_claim(&self) -> &str {
        &self.identity.uuid
    }

    /// Borrows the untrusted identity text, including modern claimed-XUID derivation.
    /// This value is never a world-approved or authenticated player UUID.
    pub fn claimed_identity(&self) -> &str {
        &self.identity.projected_uuid
    }

    /// Borrows the untrusted PlayFab master-player claim.
    pub fn claimed_playfab_id(&self) -> &str {
        &self.identity.playfab_id
    }

    /// Borrows the untrusted PlayFab title claim.
    pub fn claimed_playfab_title_id(&self) -> &str {
        &self.identity.playfab_title_id
    }
}

/// Parses a modern offline Login without granting provider authority.
///
/// This entry point requires a nonempty identity Token; legacy chains are not yet supported.
/// Identity signatures, issuer, audience and time are deliberately unverified. Metadata must
/// verify under the identity-selected key and pass the shared ClientData validator.
/// Mode 1 is unsupported. Application admission and its original deadline remain caller-owned.
/// `resolve` must supply an already acquired cached UDP lookup result without blocking or I/O.
///
/// # Errors
/// Rejects malformed framing, unsupported authentication, invalid identity or metadata,
/// failed metadata signatures, and required cached address results that are absent or failed.
pub fn parse_offline_request(
    request: &[u8],
    _now: SystemTime,
    max_request_bytes: usize,
    resolve: impl FnOnce(&str) -> Result<(), LoginError>,
) -> Result<OfflineLogin, LoginError> {
    if max_request_bytes == 0 || request.len() > max_request_bytes {
        return Err(LoginError::LimitExceeded {
            limit: max_request_bytes,
        });
    }
    let mut rest = request;
    let envelope = Object::outer(super::take_field(&mut rest)?)?;
    if envelope.number::<u8>("AuthenticationType")? == Some(1) {
        return Err(LoginError::UnsupportedAuthentication);
    }
    let certificate = envelope.text("Certificate")?.unwrap_or_default();
    envelope.strings("chain")?;
    if !certificate.is_empty() {
        Object::outer(certificate.as_bytes())?.strings("chain")?;
    }
    let modern = envelope
        .text("Token")?
        .filter(|token| !token.is_empty())
        .ok_or(LoginError::UnsupportedAuthentication)?;
    let client = take_client(&mut rest)?;
    let token = jwt::Token::parse(&modern, max_request_bytes, true)?;
    let claims = Object::parse(&token.payload)?;
    Registered::default().merge(&claims)?;
    let key = jwt::key(&claims.text("cpk")?.unwrap_or_default())?;
    let mut identity = Identity::modern(&claims)?;
    let client = std::str::from_utf8(client).map_err(|_| LoginError::MalformedToken)?;
    let payload = jwt::verify_client_with(client, max_request_bytes, |input, signature| {
        key.verify_es384(input, signature)
    })?;
    let mut metadata = client_data::validate_payload(&payload, resolve)?;
    identity.name = metadata.take_display_name();
    Ok(OfflineLogin {
        identity,
        exchange_key: metadata
            .take_exchange_key()
            .unwrap_or_else(|| key.duplicate()),
        signing_key: key,
        metadata,
    })
}

/// Applies Buffer.Next semantics only to the final offline field, retaining the caller's cap.
fn take_client<'a>(rest: &mut &'a [u8]) -> Result<&'a [u8], LoginError> {
    let prefix = rest.get(..4).ok_or(LoginError::InvalidLength)?;
    let length = i32::from_le_bytes(prefix.try_into().map_err(|_| LoginError::InvalidLength)?);
    let bytes = &rest[4..];
    let length = usize::try_from(length).map_err(|_| LoginError::InvalidLength)?;
    if length < bytes.len() {
        return Err(LoginError::InvalidLength);
    }
    *rest = &[];
    Ok(bytes)
}
