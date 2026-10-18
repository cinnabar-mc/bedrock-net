//! Bounded compact ES384 tokens with the Login wire representation.

use std::io::{self, Write};

use base64::Engine;
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE_NO_PAD};
use p384::PublicKey;
use p384::ecdsa::signature::{Signer, Verifier};
use p384::ecdsa::{Signature, SigningKey, VerifyingKey};
use p384::pkcs8::DecodePublicKey;
use serde::{Deserialize, Serialize};

use super::LoginError;

#[derive(Serialize)]
struct SigningHeader<'a> {
    alg: &'static str,
    x5u: &'a str,
}

#[derive(Deserialize)]
struct TokenHeader {
    alg: String,
    #[serde(default)]
    x5u: Option<String>,
    #[serde(default)]
    crit: Option<Vec<String>>,
    #[serde(default)]
    b64: Option<bool>,
}

#[derive(Deserialize)]
struct SaltClaims {
    #[serde(default)]
    salt: Option<String>,
}

/// Serializes one line of JSON without allowing the writer to exceed its byte limit.
pub(super) fn json_line(value: &impl Serialize, limit: usize) -> Result<Vec<u8>, LoginError> {
    let mut writer = LimitedWriter {
        bytes: Vec::new(),
        limit,
        exceeded: false,
    };
    let result = serde_json::to_writer(&mut writer, value);
    if writer.exceeded || writer.bytes.len() == limit {
        return Err(LoginError::LimitExceeded { limit });
    }
    result.map_err(LoginError::Json)?;
    writer.bytes.push(b'\n');
    Ok(writer.bytes)
}

/// Signs the exact payload bytes with a line-terminated Login header.
pub(super) fn sign(
    key: &SigningKey,
    public_key: &str,
    payload: &[u8],
    limit: usize,
) -> Result<String, LoginError> {
    let header = json_line(
        &SigningHeader {
            alg: "ES384",
            x5u: public_key,
        },
        limit,
    )?;
    let length = base64::encoded_len(header.len(), false)
        .and_then(|length| length.checked_add(1))
        .and_then(|length| {
            base64::encoded_len(payload.len(), false)
                .and_then(|payload| length.checked_add(payload))
        })
        .ok_or(LoginError::InvalidLength)?;
    if length > limit {
        return Err(LoginError::LimitExceeded { limit });
    }
    let mut token = String::with_capacity(length);
    URL_SAFE_NO_PAD.encode_string(header, &mut token);
    token.push('.');
    URL_SAFE_NO_PAD.encode_string(payload, &mut token);
    let signature: Signature = key
        .try_sign(token.as_bytes())
        .map_err(LoginError::Signature)?;
    let signature = signature.to_bytes();
    let length = base64::encoded_len(signature.len(), false)
        .and_then(|length| length.checked_add(1))
        .and_then(|length| token.len().checked_add(length))
        .ok_or(LoginError::InvalidLength)?;
    if length > limit {
        return Err(LoginError::LimitExceeded { limit });
    }
    token.push('.');
    URL_SAFE_NO_PAD.encode_string(signature, &mut token);
    Ok(token)
}

/// Verifies a bounded server token before decoding its salt or deriving any key.
pub(super) fn verify_server(token: &str, limit: usize) -> Result<(PublicKey, Vec<u8>), LoginError> {
    let parsed = Parsed::new(token, limit)?;
    let der = STANDARD
        .decode(
            parsed
                .header
                .x5u
                .as_deref()
                .ok_or(LoginError::UnsupportedHeader)?,
        )
        .map_err(LoginError::Base64)?;
    let public = PublicKey::from_public_key_der(&der).map_err(LoginError::PublicKey)?;
    parsed.verify(&VerifyingKey::from(public))?;
    let claims: SaltClaims = serde_json::from_slice(&parsed.payload).map_err(LoginError::Json)?;
    let salt = STANDARD_NO_PAD
        .decode(claims.salt.unwrap_or_default().trim_end_matches('='))
        .map_err(LoginError::Base64)?;
    Ok((public, salt))
}

/// Verifies client JSON against the provider-authenticated key, never the untrusted header key.
pub(super) fn verify_client(
    token: &str,
    public: &VerifyingKey,
    limit: usize,
) -> Result<Vec<u8>, LoginError> {
    let parsed = Parsed::new(token, limit)?;
    parsed.verify(public)?;
    Ok(parsed.payload)
}

/// Shared bounded compact framing and signature policy for both Login directions.
struct Parsed<'a> {
    input: &'a str,
    header: TokenHeader,
    signature: Signature,
    payload: Vec<u8>,
}

impl<'a> Parsed<'a> {
    /// Parses framing and supported headers without trusting a payload or header-supplied key.
    fn new(token: &'a str, limit: usize) -> Result<Self, LoginError> {
        if token.len() > limit {
            return Err(LoginError::LimitExceeded { limit });
        }
        let (input, signature) = token.rsplit_once('.').ok_or(LoginError::MalformedToken)?;
        let (header, payload) = input.split_once('.').ok_or(LoginError::MalformedToken)?;
        if payload.contains('.') {
            return Err(LoginError::MalformedToken);
        }
        let header: TokenHeader =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(header).map_err(LoginError::Base64)?)
                .map_err(LoginError::Json)?;
        if header.alg != "ES384" || header.crit.iter().flatten().any(|name| name != "b64") {
            return Err(LoginError::UnsupportedHeader);
        }
        let signature = URL_SAFE_NO_PAD
            .decode(signature)
            .map_err(LoginError::Base64)?;
        let signature = Signature::from_slice(&signature).map_err(LoginError::Signature)?;
        let payload = URL_SAFE_NO_PAD
            .decode(payload)
            .map_err(LoginError::Base64)?;
        Ok(Self {
            input,
            header,
            signature,
            payload,
        })
    }

    /// Checks the exact signed representation before any payload deserialization.
    fn verify(&self, public: &VerifyingKey) -> Result<(), LoginError> {
        let unencoded_input;
        let signing_input = if self.header.b64 == Some(false) {
            let protected = self
                .input
                .split_once('.')
                .ok_or(LoginError::MalformedToken)?
                .0;
            unencoded_input = [protected.as_bytes(), b".", self.payload.as_slice()].concat();
            unencoded_input.as_slice()
        } else {
            self.input.as_bytes()
        };
        public
            .verify(signing_input, &self.signature)
            .map_err(LoginError::Signature)
    }
}

struct LimitedWriter {
    bytes: Vec<u8>,
    limit: usize,
    exceeded: bool,
}

impl Write for LimitedWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > self.limit.saturating_sub(self.bytes.len()) {
            self.exceeded = true;
            return Err(io::Error::from(io::ErrorKind::FileTooLarge));
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
