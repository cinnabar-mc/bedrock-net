//! Validates standard client-signed claims without changing their original representation.
// Validation rules follow gophertunnel's MIT-licensed ClientData.Validate; see `THIRD_PARTY_NOTICES.md#gophertunnel`.

use super::super::{LoginError, client_data::schema_generated::Record};
use base64::Engine as _;
use std::borrow::Cow;
mod address;
mod language;
mod name_letters;
use super::ClientExchangeKey;
use address::resolution;
use language::valid_language;

pub(super) mod claims;
use claims::Claims;
pub(in crate::login) use claims::{jose_values, normalize, standard_json_values};

/// Decodes signed JSON without imposing UTF-8 rules stricter than Go's JSON decoder.
pub(in crate::login) fn parse_json(
    bytes: &[u8],
) -> Result<Box<serde_json::value::RawValue>, LoginError> {
    let text = go_utf8(bytes);
    serde_json::from_str(&text).map_err(|_| LoginError::MalformedJson)
}

/// Replaces each invalid UTF-8 byte, including each byte of an incomplete sequence.
pub(in crate::login) fn go_utf8(mut bytes: &[u8]) -> Cow<'_, str> {
    if let Ok(text) = std::str::from_utf8(bytes) {
        return Cow::Borrowed(text);
    }
    let mut text = String::with_capacity(bytes.len());
    while !bytes.is_empty() {
        match std::str::from_utf8(bytes) {
            Ok(rest) => {
                text.push_str(rest);
                break;
            }
            Err(error) => {
                let (valid, rest) = bytes.split_at(error.valid_up_to());
                text.push_str(std::str::from_utf8(valid).expect("validated UTF-8 prefix"));
                text.push('\u{fffd}');
                bytes = &rest[1..];
            }
        }
    }
    Cow::Owned(text)
}

/// Retains validated JSON, its original signed bytes and interpreted protocol metadata together.
pub(super) struct Payload {
    client_data: Box<serde_json::value::RawValue>,
    original_client_data: Option<Box<[u8]>>,
    metadata: Metadata,
}

impl Payload {
    /// Borrows the one validated JSON allocation, preserving valid input spelling.
    pub(super) fn client_data(&self) -> &serde_json::value::RawValue {
        &self.client_data
    }

    /// Borrows original signed bytes, including invalid UTF-8 repaired only for interpretation.
    pub(super) fn client_data_json_bytes(&self) -> &[u8] {
        self.original_client_data
            .as_deref()
            .unwrap_or_else(|| self.client_data.get().as_bytes())
    }

    /// Borrows the original signed nonce under the retained metadata lifetime.
    pub(super) fn nonce(&self) -> &str {
        &self.metadata.nonce
    }

    /// Consumes the validated presentation name when offline policy selects it.
    pub(super) fn take_display_name(&mut self) -> String {
        std::mem::take(&mut self.metadata.display_name)
    }

    /// Consumes the optional signed key update once without copying metadata fields.
    pub(super) fn take_exchange_key(&mut self) -> Option<ClientExchangeKey> {
        self.metadata.exchange_key.take()
    }
}

/// Validates metadata after its caller has verified the exact signed payload bytes.
pub(super) fn validate_payload(
    payload: &[u8],
    resolve: impl FnOnce(&str) -> Result<(), LoginError>,
) -> Result<Payload, LoginError> {
    let original_client_data = std::str::from_utf8(payload)
        .err()
        .map(|_| payload.trim_ascii().to_vec().into_boxed_slice());
    let client_data = parse_json(payload)?;
    let metadata = validate(&client_data, resolve)?;
    Ok(Payload {
        client_data,
        original_client_data,
        metadata,
    })
}

pub(super) struct Metadata {
    pub(super) nonce: zeroize::Zeroizing<String>,
    pub(super) display_name: String,
    pub(super) exchange_key: Option<ClientExchangeKey>,
}

/// Validates both signed claim views, final nonce/key state and required cached UDP resolution.
pub(super) fn validate(
    raw: &serde_json::value::RawValue,
    resolve: impl FnOnce(&str) -> Result<(), LoginError>,
) -> Result<Metadata, LoginError> {
    let normalized = claims::normalize(raw.get()).ok_or(LoginError::MalformedJson)?;
    let interpreted: &serde_json::value::RawValue =
        serde_json::from_str(&normalized).map_err(|_| LoginError::MalformedJson)?;
    if !claims::json_values(interpreted, true) {
        return Err(LoginError::InvalidClientData);
    }
    let mut data = Claims::default();
    data.merge(&normalized, Record::Client)
        .ok_or(LoginError::InvalidClientData)?;
    let exchange_key = data
        .key_update()
        .map(|raw| {
            serde_json::from_str::<String>(raw.get())
                .ok()
                .and_then(|value| decode(&value))
                .and_then(|bytes| ClientExchangeKey::parse(&bytes))
                .ok_or(LoginError::InvalidClientData)
        })
        .transpose()?;
    let valid = (1..=15).contains(&data.number("DeviceOS"))
        // The baseline accepts any version containing at least one digit or dot.
        && data.text("GameVersion").bytes().any(|b| b.is_ascii_digit() || b == b'.')
        && valid_language(data.text("LanguageCode"))
        && ["PlatformOfflineId", "SelfSignedId"].iter().all(|name| valid_uuid(data.text(name)))
        && (data.text("PlatformOnlineId").is_empty() || (data.text("PlatformOnlineId").bytes().all(|b| b.is_ascii_digit()) && data.text("PlatformOnlineId").parse::<u64>().is_ok()))
        && image(data.text("SkinData"), data.number("SkinImageWidth"), data.number("SkinImageHeight"))
        && image(data.text("CapeData"), data.number("CapeImageWidth"), data.number("CapeImageHeight"))
        && data.text("PlayFabId").bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        && ["SkinGeometryData", "SkinResourcePatch"].iter().all(|name| json_base64(data.text(name)))
        && !data.text("SkinId").is_empty()
        && (0..=2).contains(&data.number("UIProfile"))
        && !data.text("ThirdPartyName").is_empty()
        && data.text("ThirdPartyName").len() <= 16
        && name_letters::contains_letter_or_space(data.text("ThirdPartyName"))
        && data.entries("AnimatedImageData").iter().all(|entry| {
            image(entry.text("Image"),entry.number("ImageWidth"),entry.number("ImageHeight"))
                && (0..=3).contains(&entry.number("Type"))
        });
    if !valid {
        return Err(LoginError::InvalidClientData);
    }
    if let Some(address) =
        resolution(data.text("ServerAddress")).ok_or(LoginError::InvalidClientData)?
    {
        resolve(&address).map_err(LoginError::redact_peer)?;
    }
    Ok(Metadata {
        nonce: zeroize::Zeroizing::new(data.take_text("Nonce")),
        display_name: data.take_text("ThirdPartyName"),
        exchange_key,
    })
}

/// Accepts the UUID spellings used by Go, including case-insensitive URN prefixes.
fn valid_uuid(value: &str) -> bool {
    value.is_empty() || parse_uuid(value).is_some()
}

/// Parses Go's UUID spellings while preserving the caller's original claim text separately.
pub(super) fn parse_uuid(value: &str) -> Option<uuid::Uuid> {
    let bytes = value.as_bytes();
    let bytes = match bytes.len() {
        32 | 36 => bytes,
        38 => &bytes[1..37],
        45 if bytes[..9].eq_ignore_ascii_case(b"urn:uuid:") => &bytes[9..],
        _ => return None,
    };
    std::str::from_utf8(bytes)
        .ok()
        .and_then(|value| uuid::Uuid::parse_str(value).ok())
}

/// Decodes standard base64 while retaining Go's tolerance for embedded CR and LF.
fn decode(value: &str) -> Option<Vec<u8>> {
    let value = if value.bytes().any(|b| matches!(b, b'\r' | b'\n')) {
        Cow::Owned(value.replace(['\r', '\n'], ""))
    } else {
        Cow::Borrowed(value)
    };
    // Go accepts nonzero unused bits in the final base64 sextet.
    base64::engine::GeneralPurpose::new(
        &base64::alphabet::STANDARD,
        base64::engine::GeneralPurposeConfig::new().with_decode_allow_trailing_bits(true),
    )
    .decode(value.as_bytes())
    .ok()
}

/// Checks the decoded image length using the baseline's signed 64-bit dimension arithmetic.
fn image(value: &str, width: i64, height: i64) -> bool {
    let length = width.wrapping_mul(height).wrapping_mul(4);
    decode(value).is_some_and(|bytes| i64::try_from(bytes.len()) == Ok(length))
}

/// Accepts empty or null/object JSON payloads, as Go's map decoder does.
fn json_base64(value: &str) -> bool {
    decode(value).is_some_and(|bytes| {
        bytes.is_empty()
            || claims::normalize(&go_utf8(&bytes))
                .and_then(|text| serde_json::value::RawValue::from_string(text.into_owned()).ok())
                .is_some_and(|value| {
                    let text = value.get().trim_start();
                    (text.starts_with('{') || text == "null") && claims::json_values(&value, false)
                })
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn standard_claims_match_the_signed_go_fixtures() {
        let fixtures: Vec<serde_json::Value> = serde_json::from_str(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tools/go-oracle/client-data-cases.json"
        )))
        .unwrap();
        assert!(!fixtures.is_empty());
        for fixture in fixtures {
            let mut base = serde_json::json!({"DeviceOS":1,"GameVersion":"1.26.51","LanguageCode":"en_US","SkinId":"synthetic","ThirdPartyName":"Probe"});
            for field in fixture["remove"].as_array().unwrap() {
                base.as_object_mut()
                    .unwrap()
                    .remove(field.as_str().unwrap());
            }
            let base = base.to_string();
            let mut raw = base.as_bytes()[..base.len() - 1].to_vec();
            raw.push(b',');
            let claims = fixture["claims_base64"]
                .as_str()
                .map(|s| base64::engine::general_purpose::STANDARD.decode(s).unwrap())
                .unwrap_or_else(|| fixture["claims"].as_str().unwrap().as_bytes().to_vec());
            raw.extend_from_slice(&claims);
            raw.push(b'}');
            let raw = parse_json(&raw).unwrap();
            if let Some(expected_address) = fixture["resolve_address"].as_str() {
                for cached in [None, Some(false), Some(true)] {
                    let queried = std::cell::Cell::new(false);
                    let result = validate(&raw, |address| {
                        assert_eq!(address, expected_address, "{}", fixture["name"]);
                        queried.set(true);
                        match cached {
                            None => Err(LoginError::AddressResolutionRequired),
                            Some(false) => Err(LoginError::InvalidClientData),
                            Some(true) => Ok(()),
                        }
                    });
                    assert!(queried.get(), "resolver bypassed for {}", fixture["name"]);
                    match cached {
                        None => {
                            assert!(matches!(result, Err(LoginError::AddressResolutionRequired)))
                        }
                        Some(false) => {
                            assert!(matches!(result, Err(LoginError::InvalidClientData)))
                        }
                        Some(true) => assert!(result.is_ok(), "{}", fixture["name"]),
                    }
                }
            } else {
                assert_eq!(
                    validate(&raw, |address| panic!(
                        "unexpected resolver request {address} for {}",
                        fixture["name"]
                    ))
                    .is_ok(),
                    fixture["accepted"],
                    "{}",
                    fixture["name"]
                );
            }
        }
    }
}
