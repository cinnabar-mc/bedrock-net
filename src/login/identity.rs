//! Canonical player metadata asserted only by an authenticated provider verifier.

use super::LoginError;
use md5::{Digest, Md5};
use uuid::Uuid;

const XUID_UUID_PREFIX: &[u8] = b"pocket-auth-1-xuid:";

/// Provider-authenticated presentation, distinct from client-signed metadata.
/// No Debug or serialization exposes player identifiers in diagnostics.
#[derive(PartialEq, Eq)]
pub struct PlayerIdentity {
    uuid: Uuid,
    display_name: String,
    playfab_id: String,
    playfab_title_id: String,
}

impl PlayerIdentity {
    /// Projects verified claims using the same Xbox identity retained by the Login owner.
    pub(super) fn new(
        xuid: &str,
        display_name: String,
        legacy_uuid: Option<&str>,
        playfab_id: String,
        playfab_title_id: String,
    ) -> Result<Self, LoginError> {
        if display_name.is_empty() {
            return Err(LoginError::Authentication);
        }
        let uuid = match legacy_uuid.filter(|value| !value.is_empty()) {
            Some(value) => Uuid::parse_str(value).map_err(|_| LoginError::Authentication)?,
            None => xuid_uuid(xuid),
        };
        if uuid.is_nil() {
            return Err(LoginError::Authentication);
        }
        Ok(Self {
            uuid,
            display_name,
            playfab_id,
            playfab_title_id,
        })
    }

    /// The signed legacy UUID, otherwise the canonical UUID derived from the verified XUID.
    pub fn uuid(&self) -> Uuid {
        self.uuid
    }

    /// The provider's authenticated player name, never `ThirdPartyName` from client metadata.
    pub fn display_name(&self) -> &str {
        &self.display_name
    }

    /// The provider's `PlayFab` master-player identifier; empty means it was absent.
    pub fn playfab_id(&self) -> &str {
        &self.playfab_id
    }

    /// The provider's `PlayFab` title identifier; empty means it was absent.
    pub fn playfab_title_id(&self) -> &str {
        &self.playfab_title_id
    }
}

/// Applies the Bedrock identity namespace and UUID bits; MD5 is an identifier mapping, not trust.
pub(super) fn xuid_uuid(xuid: &str) -> Uuid {
    let mut bytes: [u8; 16] = Md5::new()
        .chain_update(XUID_UUID_PREFIX)
        .chain_update(xuid.as_bytes())
        .finalize()
        .into();
    bytes[6] = (bytes[6] & 0x0f) | 0x30;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    Uuid::from_bytes(bytes)
}

#[cfg(test)]
mod tests;
