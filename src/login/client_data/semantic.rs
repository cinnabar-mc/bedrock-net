// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Consuming relay metadata validation before any canonical identity overlay or credential mint.

use super::RawClientData;
use std::{fmt, io};

mod address;
mod locale;
mod locale_generated;
mod name;
mod skin;
mod unicode_generated;

/// A redacted metadata refusal that grants no account or transport authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ValidationError {
    /// Framing/types or independent invalid metadata cannot be repaired by one presentation change.
    Generic,
    /// The downstream protocol/version does not match the selected title version.
    OutdatedClient,
    /// The downstream protocol is newer than this selected title version.
    OutdatedServer,
    /// Replacing the whole skin aggregate makes all metadata valid.
    InvalidSkin,
    /// Replacing only the name makes the original metadata valid.
    InvalidName,
}

impl fmt::Display for ValidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("native client metadata refused")
    }
}

impl std::error::Error for ValidationError {}

/// Metadata accepted by the title validator, without account or device authority.
/// It cannot be decoded or constructed directly, and its final raw claims require consumption.
/// Incoming addresses never grant authority; DNS/OS-service resolution is deliberately omitted.
/// Raw lexeme retention does not promise Go's normalization of arbitrary duplicate known claims.
#[must_use]
pub struct ValidatedClientData {
    raw: RawClientData,
    name: String,
}

impl fmt::Debug for ValidatedClientData {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ValidatedClientData")
            .finish_non_exhaustive()
    }
}

impl ValidatedClientData {
    /// Returns requested presentation after validation, never a verified account name or XUID.
    pub fn requested_name(&self) -> &str {
        &self.name
    }

    /// Consumes the validated metadata for the caller's final identity/transport overlay.
    pub fn into_raw(self) -> RawClientData {
        self.raw
    }
}

/// Validates version before projecting the original typed metadata, without applying device policy.
pub(super) fn validate(
    raw: RawClientData,
    protocol: i32,
    expected_protocol: i32,
    expected_version: &str,
) -> Result<ValidatedClientData, ValidationError> {
    let version = raw
        .game_version()
        .map_err(|_| ValidationError::Generic)?
        .unwrap_or_default();
    if protocol != expected_protocol || version != expected_version {
        return Err(if protocol > expected_protocol {
            ValidationError::OutdatedServer
        } else {
            ValidationError::OutdatedClient
        });
    }
    let view = View::read(&raw).map_err(|_| ValidationError::Generic)?;
    view.check()?;
    Ok(ValidatedClientData {
        raw,
        name: view.name,
    })
}

struct View {
    device_os: i64,
    language: String,
    offline_id: String,
    online_id: String,
    self_signed_id: String,
    address: String,
    playfab: String,
    ui: i64,
    name: String,
    skin: skin::Skin,
}

impl View {
    /// Projects only values actually consumed by Validate; exhaustive JSON types have another owner.
    fn read(raw: &RawClientData) -> io::Result<Self> {
        Ok(Self {
            device_os: raw.integer("DeviceOS")?.unwrap_or_default(),
            language: raw.read("LanguageCode")?.unwrap_or_default(),
            offline_id: raw.read("PlatformOfflineId")?.unwrap_or_default(),
            online_id: raw.read("PlatformOnlineId")?.unwrap_or_default(),
            self_signed_id: raw.read("SelfSignedId")?.unwrap_or_default(),
            address: raw.read("ServerAddress")?.unwrap_or_default(),
            playfab: raw.read("PlayFabId")?.unwrap_or_default(),
            ui: raw.integer("UIProfile")?.unwrap_or_default(),
            name: raw.read("ThirdPartyName")?.unwrap_or_default(),
            skin: skin::Skin::read(raw)?,
        })
    }

    /// Replaces whole skin, then whole name, while retaining every independent invalid field.
    fn check(&self) -> Result<(), ValidationError> {
        let other = (1..=15).contains(&self.device_os)
            && locale::valid(&self.language)
            && optional_uuid(&self.offline_id)
            && (self.online_id.is_empty()
                || self.online_id.bytes().all(|byte| byte.is_ascii_digit())
                    && self.online_id.parse::<u64>().is_ok())
            && optional_uuid(&self.self_signed_id)
            && address::valid(&self.address)
            && self
                .playfab
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            && (0..=2).contains(&self.ui);
        let skin = self.skin.valid();
        let name = name::valid(&self.name);
        if other && skin && name {
            Ok(())
        } else if other && name {
            // A valid replacement changes the entire skin aggregate and no other field.
            Err(ValidationError::InvalidSkin)
        } else if other && skin {
            // This tests the original skin with only the name replaced, not the previous replacement.
            Err(ValidationError::InvalidName)
        } else {
            Err(ValidationError::Generic)
        }
    }
}

/// Matches google/uuid.Parse's accepted encodings, including its unchecked38-byte wrapper bytes.
fn optional_uuid(value: &str) -> bool {
    let bytes = value.as_bytes();
    let body = match bytes.len() {
        0 => return true,
        32 | 36 => bytes,
        38 => &bytes[1..37],
        45 if bytes[..9].eq_ignore_ascii_case(b"urn:uuid:") => &bytes[9..],
        _ => return false,
    };
    std::str::from_utf8(body).is_ok_and(|body| uuid::Uuid::parse_str(body).is_ok())
}

#[cfg(test)]
mod tests;
