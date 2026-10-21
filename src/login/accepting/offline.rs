//! Opaque offline Login capability, with account claims kept separate from provider authority.

use super::{ClientExchangeKey, client_data};
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
