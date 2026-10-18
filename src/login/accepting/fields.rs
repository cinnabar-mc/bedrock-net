//! Go-compatible recognized Login field matching without rewriting signed JSON.

use serde::de::{self, IgnoredAny, MapAccess, Visitor};
use serde::{Deserialize, Deserializer};
use std::fmt;

pub(super) struct Envelope {
    pub(super) mode: Option<u8>,
    pub(super) token: Option<String>,
}

impl<'de> Deserialize<'de> for Envelope {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Fields;
        impl<'de> Visitor<'de> for Fields {
            type Value = Envelope;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a Login authentication object")
            }

            fn visit_map<M: MapAccess<'de>>(self, mut map: M) -> Result<Self::Value, M::Error> {
                let mut mode = None;
                let mut token = None;
                let mut mode_seen = false;
                let mut token_seen = false;
                while let Some(name) = map.next_key::<String>()? {
                    if matches_field(&name, "AuthenticationType") {
                        if mode_seen {
                            return Err(de::Error::custom("ambiguous Login authentication field"));
                        }
                        mode_seen = true;
                        mode = map.next_value()?;
                    } else if matches_field(&name, "Token") {
                        if token_seen {
                            return Err(de::Error::custom("ambiguous Login credential field"));
                        }
                        token_seen = true;
                        token = map.next_value()?;
                    } else {
                        map.next_value::<IgnoredAny>()?;
                    }
                }
                Ok(Envelope { mode, token })
            }
        }
        deserializer.deserialize_map(Fields)
    }
}

pub(super) struct Metadata {
    pub(super) nonce: String,
}

impl<'de> Deserialize<'de> for Metadata {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Fields;
        impl<'de> Visitor<'de> for Fields {
            type Value = Metadata;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a client metadata object")
            }

            fn visit_map<M: MapAccess<'de>>(self, mut map: M) -> Result<Self::Value, M::Error> {
                let mut nonce = None;
                let mut seen = false;
                while let Some(name) = map.next_key::<String>()? {
                    if matches_field(&name, "Nonce") {
                        if seen {
                            return Err(de::Error::custom("ambiguous Login nonce field"));
                        }
                        seen = true;
                        nonce = map.next_value::<Option<String>>()?;
                    } else {
                        map.next_value::<IgnoredAny>()?;
                    }
                }
                Ok(Metadata {
                    nonce: nonce.unwrap_or_default(),
                })
            }
        }
        deserializer.deserialize_map(Fields)
    }
}

/// Matches Go's Unicode SimpleFold for ASCII field names, including its K/S fold orbits.
/// This is confined to outer Login/client fields; JWT claims and JWS headers never use it.
fn matches_field(name: &str, expected: &str) -> bool {
    name.chars()
        .map(|rune| match rune {
            '\u{212a}' => 'K',
            '\u{017f}' => 'S',
            rune => rune.to_ascii_uppercase(),
        })
        .eq(expected.chars().map(|rune| rune.to_ascii_uppercase()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

    #[test]
    fn go_field_folding_preserves_unknown_values_and_refuses_folded_duplicates() {
        let envelope: Envelope = serde_json::from_str(
            r#"{"authenticationtype":0,"ToKen":"exact-token","opaque":{"Token":"ignored"}}"#,
        )
        .unwrap();
        assert_eq!(envelope.mode, Some(0));
        assert_eq!(envelope.token.as_deref(), Some("exact-token"));
        for raw in [
            r#"{"Token":"one","ToKen":"one"}"#,
            r#"{"Token":null,"token":"one"}"#,
            r#"{"AuthenticationType":null,"authenticationtype":0}"#,
        ] {
            assert!(serde_json::from_str::<Envelope>(raw).is_err());
        }
        let metadata: Metadata =
            serde_json::from_str(r#"{"nonce":null,"opaque":{"Nonce":"ignored"}}"#).unwrap();
        assert_eq!(metadata.nonce, "");
        assert!(
            serde_json::from_str::<Metadata>(r#"{"nonce":null,"Nonce":"replacement"}"#).is_err()
        );
        // Unicode uppercase expansion is not SimpleFold; this spelling must remain unknown.
        let envelope: Envelope =
            serde_json::from_str(r#"{"AuthentıcationType":0,"Token":"exact"}"#).unwrap();
        assert_eq!(envelope.mode, None);
        let key = p384::ecdsa::SigningKey::from_slice(&[1; 48]).unwrap();
        let header = URL_SAFE_NO_PAD.encode(br#"{"ALG":"ES384"}"#);
        let token = format!("{header}.e30.AA");
        assert!(
            matches!(
                crate::login::finish_key_exchange(&key, &token, 1024),
                Err(crate::login::LoginError::MalformedJson)
            ),
            "outer field folding must never alter JWS header policy"
        );
    }
}
