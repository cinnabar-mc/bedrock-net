//! Shape decoding for JOSE headers, without modern signature or critical-header policy.
// Copyright 2014 Square Inc.
// The decoding rules follow go-jose, under Apache-2.0; see LICENSE-APACHE and NOTICE.

use super::client_data::jose_values;
use super::{ClientExchangeKey, LoginError, Object, decode};

use super::{certificate, url};
use certificate::PublicKey;
mod jwk;

/// Interpreted protected fields, kept separate from the original authenticated bytes.
pub(in crate::login) struct Header(Object);

impl Header {
    /// Decodes known JOSE fields and generic extensions before consuming identity claims.
    pub(super) fn parse(bytes: &[u8]) -> Result<Self, LoginError> {
        let header = Object::parse(bytes)?;
        for (name, raw) in header.members() {
            if raw.get() == "null" {
                continue;
            }
            let valid = match name {
                "alg" | "kid" | "nonce" => header.text(name).is_ok(),
                "jwk" => jwk::parse(raw).is_some(),
                "x5c" => certificate::chain(raw).is_some(),
                _ => jose_values(raw),
            };
            if !valid {
                return Err(LoginError::MalformedJson);
            }
        }
        Ok(Self(header))
    }

    /// Allows RS256 only for the explicitly unverified modern identity role.
    pub(super) fn algorithm(&self, modern: bool) -> Result<(), LoginError> {
        match self.0.text("alg")?.as_deref() {
            Some("ES384") => Ok(()),
            Some("RS256") if modern => Ok(()),
            None => Err(LoginError::MalformedJson),
            _ => Err(LoginError::UnsupportedHeader),
        }
    }

    /// Applies critical-header policy only when a caller verifies the signature.
    pub(super) fn critical(&self) -> Result<(), LoginError> {
        if self
            .0
            .strings("crit")?
            .iter()
            .flatten()
            .any(|name| name != "b64")
        {
            return Err(LoginError::UnsupportedHeader);
        }
        Ok(())
    }

    /// Extracts a string only for roles that explicitly select their key from x5u.
    pub(in crate::login) fn key_text(&self) -> Result<String, LoginError> {
        self.0.text("x5u")?.ok_or(LoginError::UnsupportedHeader)
    }

    /// Uses raw payload authentication only for exact false; null and other values default true.
    pub(super) fn encoded_payload(&self) -> bool {
        self.0.exact("b64").is_none_or(|raw| raw.get() != "false")
    }
}
