// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Provider policy over the existing pure `NetherNet` JWS/JWK/claims implementation.
//!
//! Acquisition, service clocks and refresh policy belong to the caller. Verification
//! performs no I/O and uses only explicitly supplied provider UTC.

mod claims;
mod player;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use nethernet::identity::{
    MINECRAFT_AUDIENCE,
    jwk::{Jwk, JwkSet},
    jwt::{Claims, Jws},
};
use p384::ecdsa::VerifyingKey;
use serde::Deserialize;
use std::{io, time::SystemTime};

const MAX_TOKEN_BYTES: usize = 64 * 1024;
const MAX_KEYS: usize = 32;
const MAX_KEY_ID_BYTES: usize = 256;
const MAX_RSA_MODULUS_TEXT: usize = 1024;

/// Trusted keys and issuer acquired from the configured authorization environment.
/// No transport crypto types, HTTP client, refresh task or unverified trust mode are exposed.
#[derive(Clone)]
pub struct ProviderVerifier {
    issuer: String,
    keys: JwkSet,
}

impl ProviderVerifier {
    /// Shared encoded-document bound for public provider metadata and acquired credentials.
    pub const MAX_DOCUMENT_BYTES: usize = MAX_TOKEN_BYTES;

    /// Bounds configured issuer and public key-discovery URLs before HTTP or token verification.
    pub const MAX_PROVIDER_URL_BYTES: usize = 4096;

    /// Admits bounded HTTPS-acquired `OpenID` metadata. The issuer comes from service discovery,
    /// never token claims; the caller normalizes it as the configured environment requires.
    /// Only RS256 is currently supported; another advertised algorithm fails explicitly.
    ///
    /// # Errors
    /// Rejects malformed/oversized metadata, unsupported algorithms or unusable public keys.
    pub fn new(issuer: String, algorithms: &[String], jwks: &[u8]) -> io::Result<Self> {
        if issuer.is_empty()
            || issuer.len() > Self::MAX_PROVIDER_URL_BYTES
            || issuer.chars().any(char::is_control)
            || jwks.len() > MAX_TOKEN_BYTES
        {
            return Err(rejected());
        }
        if algorithms.len() > 32 || algorithms.iter().any(|algorithm| algorithm.len() > 64) {
            return Err(rejected());
        }
        if !algorithms.is_empty() && !algorithms.iter().any(|algorithm| algorithm == "RS256") {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "authorization provider does not advertise supported multiplayer signing",
            ));
        }
        #[derive(Deserialize)]
        struct PublishedKey {
            #[serde(flatten)]
            key: Jwk,
            alg: Option<String>,
            #[serde(rename = "use")]
            usage: Option<String>,
            #[serde(default)]
            key_ops: Vec<String>,
        }
        #[derive(Deserialize)]
        struct PublishedKeys {
            keys: Vec<PublishedKey>,
        }
        let published: PublishedKeys = serde_json::from_slice(jwks).map_err(|_| rejected())?;
        if published.keys.is_empty()
            || published.keys.len() > MAX_KEYS
            || published.keys.iter().any(|published| {
                let key = &published.key;
                key.kid
                    .as_ref()
                    .is_some_and(|id| id.len() > MAX_KEY_ID_BYTES)
                    || key
                        .n
                        .as_ref()
                        .is_some_and(|n| n.len() > MAX_RSA_MODULUS_TEXT)
                    || key.e.as_ref().is_some_and(|e| e.len() > 16)
            })
        {
            return Err(rejected());
        }
        let keys = JwkSet {
            keys: published
                .keys
                .into_iter()
                .filter(|published| {
                    published.key.kty == "RSA"
                        && published.key.n.is_some()
                        && published.key.e.is_some()
                        && published.alg.as_deref().is_none_or(|alg| alg == "RS256")
                        && published
                            .usage
                            .as_deref()
                            .is_none_or(|usage| usage == "sig")
                        && (published.key_ops.is_empty()
                            || published.key_ops.iter().any(|op| op == "verify"))
                        && published.key.validate_rs256().is_ok()
                })
                .map(|published| published.key)
                .collect(),
        };
        if keys.keys.is_empty() {
            return Err(rejected());
        }
        Ok(Self { issuer, keys })
    }

    /// Checks bounded token syntax and supported signature headers without establishing trust.
    ///
    /// # Errors
    /// Rejects empty/oversized credentials, malformed JWS and unsupported algorithm/extensions.
    pub fn validate_format(token: &str) -> io::Result<()> {
        parsed(token).map(|_| ())
    }

    /// Reports an unknown key ID for the provider's on-demand, rate-bounded refresh policy.
    /// A token without kid tries all published keys, matching the existing verifier owner.
    ///
    /// # Errors
    /// Rejects malformed, oversized or unsupported tokens before key lookup.
    pub fn recognizes(&self, token: &str) -> io::Result<bool> {
        let token = parsed(token)?;
        Ok(!self
            .keys
            .candidates(token.header.kid.as_deref().filter(|id| !id.is_empty()))
            .is_empty())
    }

    /// Verifies signature, provider policy and the selected account/proof binding.
    ///
    /// # Errors
    /// Rejects malformed, untrusted, expired or mismatched credentials without claim details.
    pub fn verify_bound(
        &self,
        token: &str,
        key: &VerifyingKey,
        xuid: &str,
        now: SystemTime,
    ) -> io::Result<VerifiedClaims> {
        let claims = self.verify_peer(token, now)?;
        claims::validate_binding(&claims, xuid, key)?;
        Ok(VerifiedClaims { claims })
    }

    /// Shares issuer, audience, signature and temporal policy with remote SDP verification.
    /// A remote peer is not required to carry the local selected account's XUID or proof key.
    ///
    /// # Errors
    /// Rejects malformed, untrusted or expired credentials without exposing claim details.
    pub fn verify_peer(&self, token: &str, now: SystemTime) -> io::Result<Claims> {
        let token = parsed(token)?;
        if !self
            .keys
            .candidates(token.header.kid.as_deref().filter(|id| !id.is_empty()))
            .iter()
            .any(|key| {
                key.verify_rs256(token.signing_input.as_bytes(), &token.signature)
                    .is_ok()
            })
        {
            return Err(rejected());
        }
        let claims = token.claims().map_err(|_| rejected())?;
        let audience_well_formed = match claims.values().get("aud") {
            Some(serde_json::Value::String(_)) => true,
            Some(serde_json::Value::Array(values)) => {
                values.iter().all(serde_json::Value::is_string)
            }
            _ => false,
        };
        if claims.issuer() != Some(self.issuer.as_str())
            || !audience_well_formed
            || !claims.audience().contains(&MINECRAFT_AUDIENCE)
        {
            return Err(rejected());
        }
        claims::validate_identity(&claims, now)?;
        Ok(claims)
    }
}

impl nethernet::identity::TokenVerifier for ProviderVerifier {
    /// Pure provider policy for the remote peer's own claims, before SDP fingerprint binding.
    fn verify(&self, token: &str, now: SystemTime) -> nethernet::identity::error::Result<Claims> {
        self.verify_peer(token, now).map_err(|_| {
            nethernet::identity::error::IdentityError::Untrusted(
                "configured native multiplayer verification failed".to_owned(),
            )
        })
    }
}

impl super::LoginVerifier for ProviderVerifier {
    /// Authenticates the joining peer through the same configured provider owner used for SDP.
    /// The peer's own XUID/cpk are retained; no local selected-host identity is substituted.
    fn verify(
        &self,
        token: &str,
        now: SystemTime,
    ) -> Result<super::TrustedIdentity, super::LoginError> {
        use super::LoginError;
        let claims = self
            .verify_peer(token, now)
            .map_err(|_| LoginError::Authentication)?;
        player::identity(&claims)
    }
}

/// Bounds credential decoding and admits only the configured verifier's supported signature algorithm.
fn parsed(token: &str) -> io::Result<Jws> {
    if token.is_empty() || token.len() > MAX_TOKEN_BYTES {
        return Err(rejected());
    }
    let parsed = Jws::parse(token).map_err(|_| rejected())?;
    if parsed.header.alg != "RS256" || parsed.signature.is_empty() {
        return Err(rejected());
    }
    // The shared JWS parser retains alg/kid; inspect only its otherwise unretained critical-header policy.
    #[derive(Deserialize)]
    struct Extensions {
        #[serde(default)]
        crit: Vec<String>,
        b64: Option<bool>,
    }
    let header = URL_SAFE_NO_PAD
        .decode(token.split('.').next().ok_or_else(rejected)?)
        .map_err(|_| rejected())?;
    let extensions: Extensions = serde_json::from_slice(&header).map_err(|_| rejected())?;
    if !extensions.crit.is_empty() || extensions.b64 == Some(false) {
        return Err(rejected());
    }
    Ok(parsed)
}

/// Keeps parser, token, subject and key details out of errors.
fn rejected() -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        "native multiplayer credential verification failed",
    )
}

/// Claims authenticated and bound to the caller's selected account and proof key.
/// No Debug implementation exposes the credential's account or key material.
pub struct VerifiedClaims {
    claims: Claims,
}

impl VerifiedClaims {
    /// Borrows the original authenticated claims, including their finite expiry.
    pub fn claims(&self) -> &Claims {
        &self.claims
    }

    /// Projects the provider's canonical player identity without client-metadata fallback.
    ///
    /// # Errors
    /// Rejects malformed optional presentation fields without exposing their contents.
    pub fn identity(&self) -> Result<super::TrustedIdentity, super::LoginError> {
        player::identity(&self.claims)
    }
}

#[cfg(test)]
mod tests;
