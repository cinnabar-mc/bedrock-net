//! Authenticated accepting Login, with issuer policy supplied by its existing caller owner.

use super::{LoginError, PlayerIdentity, jwt};
use p384::ecdsa::VerifyingKey;
use serde_json::value::RawValue;
use std::time::SystemTime;
use zeroize::Zeroizing;

pub(super) mod client_data;
mod exchange_key;
mod fields;
mod offline;
pub use exchange_key::ClientExchangeKey;
pub use offline::{OfflineLogin, parse_offline_request};

/// Pure authority for the configured multiplayer provider, never a client-selected issuer/key.
///
/// Implementations must verify signature, supported algorithm/critical headers,
/// configured issuer/audience, finite temporal claims and authenticated Xbox
/// identity before returning the provider's `cpk`. Reuse the application's
/// existing provider verifier and acquired metadata. This interface performs no
/// discovery, HTTP, refresh or account binding to the local host's XUID.
pub trait LoginVerifier {
    /// Verifies this exact bounded credential at caller-supplied provider UTC.
    ///
    /// # Errors
    /// Return an authentication error without credential/claim contents on any policy failure.
    fn verify(&self, token: &str, now: SystemTime) -> Result<TrustedIdentity, LoginError>;

    /// Requires a cached result equivalent to Go's `ResolveUDPAddr("udp", address)`.
    /// Called only for a validated signed UDP address needing the configured resolver,
    /// including empty IPv6 zones and IP spellings that fail literal parsing.
    /// This callback must not block or perform network I/O; acquire/cache its result before
    /// submitting Login to the consuming engine. A miss must return `AddressResolutionRequired`.
    /// The pure parser can be retried with the same request after asynchronous acquisition.
    ///
    /// # Errors
    /// Return `InvalidClientData` for a failed resolution, or `AddressResolutionRequired` on a cache miss.
    fn resolve_client_address(&self, _address: &str) -> Result<(), LoginError> {
        Err(LoginError::AddressResolutionRequired)
    }
}

/// Identity asserted by a trusted provider-verification implementation.
/// No Debug implementation exposes its account identifier.
pub struct TrustedIdentity {
    xuid: String,
    public_key: VerifyingKey,
    player: Option<PlayerIdentity>,
}

impl TrustedIdentity {
    /// Records an already provider-verified XUID and its signed P384 `cpk`.
    ///
    /// This constructor does not authenticate claims; only a trusted
    /// [`LoginVerifier`] may use it after completing its configured provider policy.
    /// Presentation remains absent until [`Self::with_player_identity`] records it.
    ///
    /// # Errors
    /// Rejects an empty or non-int64 XUID before retaining it.
    pub fn new(xuid: String, public_key: VerifyingKey) -> Result<Self, LoginError> {
        if xuid.is_empty() || xuid.parse::<i64>().is_err() {
            return Err(LoginError::Authentication);
        }
        Ok(Self {
            xuid,
            public_key,
            player: None,
        })
    }

    /// Retains provider-verified presentation using this identity's original XUID.
    ///
    /// This asserts already verified claims; it does not authenticate them. Names
    /// and `PlayFab` fields must come from the same provider credential as this
    /// XUID/key, never client metadata. Missing/empty legacy UUID derives from XUID.
    ///
    /// # Errors
    /// Rejects an empty name or malformed/nil legacy UUID without returning an identity.
    pub fn with_player_identity(
        mut self,
        display_name: String,
        legacy_uuid: Option<&str>,
        playfab_id: String,
        playfab_title_id: String,
    ) -> Result<Self, LoginError> {
        self.player = Some(PlayerIdentity::new(
            &self.xuid,
            display_name,
            legacy_uuid,
            playfab_id,
            playfab_title_id,
        )?);
        Ok(self)
    }

    /// Borrows presentation retained from the same provider-verified credential.
    pub fn player_identity(&self) -> Option<&PlayerIdentity> {
        self.player.as_ref()
    }
}

/// Provider-authenticated identity and client-signed metadata from one exact Login.
///
/// Client metadata remains player-controlled even though its signature proves
/// possession of the provider-bound key. A nonce requires the application's
/// current directory/world approval. No Clone, Debug or serialization exposes
/// credentials or allows this owner to be silently substituted.
pub struct AuthenticatedLogin {
    identity: TrustedIdentity,
    exchange_key: ClientExchangeKey,
    credential: Zeroizing<String>,
    metadata: client_data::Payload,
}

impl AuthenticatedLogin {
    /// Borrows the provider-authenticated joining player's XUID, never the host account's XUID.
    pub fn xuid(&self) -> &str {
        &self.identity.xuid
    }

    /// Borrows the provider-bound metadata signing key. Use `exchange_key()` for transport binding.
    pub fn public_key(&self) -> &VerifyingKey {
        &self.identity.public_key
    }

    /// Borrows the original provider-bound metadata signer, also retained for provider revalidation.
    pub fn signing_key(&self) -> &VerifyingKey {
        &self.identity.public_key
    }

    /// Borrows the final signed exchange key, which may differ from the metadata signer.
    pub fn exchange_key(&self) -> &ClientExchangeKey {
        &self.exchange_key
    }

    /// Borrows authenticated presentation if the trusted verifier supplied it.
    /// A world consumer requiring a name/UUID must reject None, without client-data fallback.
    pub fn player_identity(&self) -> Option<&PlayerIdentity> {
        self.identity.player_identity()
    }

    /// Borrows validated client JSON, replacing invalid UTF-8 as Go does.
    /// Valid UTF-8 retains its original spelling, including escaped surrogates.
    /// Application policy remains caller-owned; required address lookups have a successful cached result.
    pub fn client_data(&self) -> &RawValue {
        self.metadata.client_data()
    }

    /// Borrows the original signed JSON value bytes before UTF-8 replacement.
    /// Insignificant whitespace surrounding the JSON value is omitted.
    pub fn client_data_json_bytes(&self) -> &[u8] {
        self.metadata.client_data_json_bytes()
    }

    /// Borrows the original client-signed title nonce; this value alone grants no world access.
    pub fn nonce(&self) -> &str {
        self.metadata.nonce()
    }

    /// Splits a listener override or the interpreted joined address without DNS or route authority.
    pub fn return_target(&self, override_address: &str) -> Option<(Vec<u8>, u16)> {
        self.metadata.return_target(override_address)
    }

    /// Rechecks the exact original credential after any application approval/capacity wait.
    ///
    /// # Errors
    /// Rejects expiry/provider failure or changed authenticated account, key or presentation.
    /// No fallback or retry occurs.
    pub fn revalidate(
        &self,
        verifier: &impl LoginVerifier,
        now: SystemTime,
    ) -> Result<(), LoginError> {
        let identity = verifier
            .verify(&self.credential, now)
            .map_err(LoginError::redact_peer)?;
        if identity.xuid != self.identity.xuid
            || identity.public_key != self.identity.public_key
            || identity.player != self.identity.player
        {
            return Err(LoginError::IdentityChanged);
        }
        Ok(())
    }
}

/// Verifies modern authenticated Login and its metadata without I/O or a hidden clock.
///
/// The required caller verifier establishes issuer trust. The existing Login
/// ES384 owner then verifies client JSON against the provider's `cpk`, ignoring
/// any client-header key. Legacy chains, offline and guest modes are explicitly
/// unsupported; they never fall through to raw JWT claims or self-signed trust.
///
/// # Errors
/// Rejects an oversized/truncated/negative-length/trailing frame, unsupported
/// authentication, provider rejection, invalid signed client claims, or a required address lookup
/// without a successful cached result.
pub fn verify_authenticated_request(
    request: &[u8],
    verifier: &impl LoginVerifier,
    now: SystemTime,
    max_request_bytes: usize,
) -> Result<AuthenticatedLogin, LoginError> {
    if max_request_bytes == 0 || request.len() > max_request_bytes {
        return Err(LoginError::LimitExceeded {
            limit: max_request_bytes,
        });
    }
    let mut rest = request;
    let envelope = take_field(&mut rest)?;
    let client = take_field(&mut rest)?;
    if !rest.is_empty() {
        return Err(LoginError::InvalidLength);
    }
    let envelope: fields::Envelope =
        serde_json::from_slice(envelope).map_err(|_| LoginError::MalformedJson)?;
    if envelope.mode != Some(0) {
        return Err(LoginError::UnsupportedAuthentication);
    }
    let token = envelope
        .token
        .filter(|token| !token.is_empty())
        .ok_or(LoginError::EmptyAuthenticationToken)?;
    let identity = verifier
        .verify(&token, now)
        .map_err(LoginError::redact_peer)?;
    let client = std::str::from_utf8(client).map_err(|_| LoginError::MalformedToken)?;
    let payload = jwt::verify_client(client, &identity.public_key, max_request_bytes)?;
    let mut metadata = client_data::validate_payload(&payload, |address| {
        verifier.resolve_client_address(address)
    })?;
    let exchange_key = metadata
        .take_exchange_key()
        .map(Ok)
        .unwrap_or_else(|| ClientExchangeKey::from_signer(&identity.public_key))?;
    Ok(AuthenticatedLogin {
        identity,
        exchange_key,
        credential: Zeroizing::new(token),
        metadata,
    })
}

/// Takes one positive signed-i32-sized field without truncation or unchecked arithmetic.
fn take_field<'a>(rest: &mut &'a [u8]) -> Result<&'a [u8], LoginError> {
    let prefix = rest.get(..4).ok_or(LoginError::InvalidLength)?;
    let length = i32::from_le_bytes(prefix.try_into().map_err(|_| LoginError::InvalidLength)?);
    let length = usize::try_from(length)
        .ok()
        .filter(|length| *length > 0)
        .ok_or(LoginError::InvalidLength)?;
    let end = 4usize
        .checked_add(length)
        .ok_or(LoginError::InvalidLength)?;
    let field = rest.get(4..end).ok_or(LoginError::InvalidLength)?;
    *rest = rest.get(end..).ok_or(LoginError::InvalidLength)?;
    Ok(field)
}

#[cfg(test)]
mod tests;
