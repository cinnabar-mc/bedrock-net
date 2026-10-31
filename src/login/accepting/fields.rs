//! Go-compatible recognized Login field matching without rewriting signed JSON.

pub(super) use super::super::fields::matches_field;
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
        // Unicode uppercase expansion is not SimpleFold; this spelling must remain unknown.
        let envelope: Envelope =
            serde_json::from_str(r#"{"AuthentıcationType":0,"Token":"exact"}"#).unwrap();
        assert_eq!(envelope.mode, None);
        let header = URL_SAFE_NO_PAD.encode(br#"{"ALG":"ES384"}"#);
        let token = format!("{header}.e30.AA");
        assert!(
            matches!(
                crate::login::verify_server_handshake(&token, 1024),
                Err(crate::login::LoginError::MalformedJson)
            ),
            "outer field folding must never alter JWS header policy"
        );
    }
}
