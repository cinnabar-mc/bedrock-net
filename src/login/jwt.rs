//! Bounded compact ES384 tokens with the Login wire representation.

use std::{
    borrow::Cow,
    io::{self, Write},
};

use base64::engine::general_purpose::{STANDARD_NO_PAD, URL_SAFE_NO_PAD};
use base64::{
    Engine, alphabet,
    engine::{DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig},
};
use p384::PublicKey;
use p384::ecdsa::signature::{Signer, Verifier};
use p384::ecdsa::{Signature, SigningKey, VerifyingKey};
use p384::pkcs8::DecodePublicKey;
use serde::{Deserialize, Serialize};

use super::{ClientExchangeKey, LoginError, accepting::client_data, url};

mod certificate;
mod header;
mod object;
use header::Header;
pub(super) use object::Object;

#[derive(Serialize)]
struct SigningHeader<'a> {
    alg: &'static str,
    x5u: &'a str,
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
    let parsed = Token::parse(token, limit, false)?;
    let der = decode(&parsed.header.key_text()?, false)?;
    let public = PublicKey::from_public_key_der(&der).map_err(LoginError::PublicKey)?;
    parsed.verify(&VerifyingKey::from(public))?;
    let claims: SaltClaims =
        serde_json::from_slice(&parsed.payload).map_err(|_| LoginError::MalformedJson)?;
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
    verify_client_with(token, limit, |input, signature| {
        let signature = Signature::from_slice(signature).map_err(LoginError::Signature)?;
        public
            .verify(input, &signature)
            .map_err(LoginError::Signature)
    })
}

/// Verifies compact ES384 framing with the caller-selected signer before releasing payload bytes.
pub(super) fn verify_client_with(
    token: &str,
    limit: usize,
    verify: impl FnOnce(&[u8], &[u8; 96]) -> Result<(), LoginError>,
) -> Result<Vec<u8>, LoginError> {
    let parsed = Token::parse(token, limit, false)?;
    parsed.verify_with(verify)?;
    Ok(parsed.payload)
}

/// Shared bounded compact framing with role-specific verification after header interpretation.
pub(super) struct Token<'a> {
    input: Cow<'a, [u8]>,
    pub(super) header: Header,
    signature: Vec<u8>,
    pub(super) payload: Vec<u8>,
}

impl<'a> Token<'a> {
    /// Parses framing and supported headers without trusting a payload or header-supplied key.
    pub(super) fn parse(token: &'a str, limit: usize, modern: bool) -> Result<Self, LoginError> {
        if token.len() > limit {
            return Err(LoginError::LimitExceeded { limit });
        }
        let (input, signature) = token.rsplit_once('.').ok_or(LoginError::MalformedToken)?;
        let (header, payload) = input.split_once('.').ok_or(LoginError::MalformedToken)?;
        if payload.contains('.') {
            return Err(LoginError::MalformedToken);
        }
        let (protected, canonical_header) = decode_compact(header)?;
        let header = Header::parse(&protected)?;
        header.algorithm(modern)?;
        let signature = decode_compact(signature)?.0;
        let (payload, canonical_payload) = decode_compact(payload)?;
        let input = authentication_input(
            input,
            &protected,
            &payload,
            header.encoded_payload(),
            canonical_header && canonical_payload,
        );
        Ok(Self {
            input,
            header,
            signature,
            payload,
        })
    }

    /// Checks signed-token policy and raw ES384 width before the caller's existing crypto verifier.
    pub(super) fn verify_with(
        &self,
        verify: impl FnOnce(&[u8], &[u8; 96]) -> Result<(), LoginError>,
    ) -> Result<(), LoginError> {
        self.header.algorithm(false)?;
        self.header.critical()?;
        let signature = self
            .signature
            .as_slice()
            .try_into()
            .map_err(|_| LoginError::Signature(p384::ecdsa::Error::new()))?;
        verify(self.signing_input(), signature)
    }

    /// Checks P384 scalar ranges and the exact signed representation before payload deserialization.
    fn verify(&self, public: &VerifyingKey) -> Result<(), LoginError> {
        self.verify_with(|input, signature| {
            let signature = Signature::from_slice(signature).map_err(LoginError::Signature)?;
            public
                .verify(input, &signature)
                .map_err(LoginError::Signature)
        })
    }

    /// Borrows the already selected authentication bytes without changing signed JSON.
    fn signing_input(&self) -> &[u8] {
        &self.input
    }
}

/// Decodes a client-supplied PKIX ECDSA key through the existing exchange-key owner.
pub(super) fn key(value: &str) -> Result<ClientExchangeKey, LoginError> {
    ClientExchangeKey::parse(&decode(value, false)?).ok_or(LoginError::Authentication)
}

/// Decodes Go standard or raw URL base64 with CR/LF and nonzero unused-bit tolerance.
fn decode(value: &str, url: bool) -> Result<Vec<u8>, LoginError> {
    if url {
        return decode_compact(value).map(|(bytes, _)| bytes);
    }
    let clean = if value.contains(['\r', '\n']) {
        Cow::Owned(value.replace(['\r', '\n'], ""))
    } else {
        Cow::Borrowed(value)
    };
    GeneralPurpose::new(
        &alphabet::STANDARD,
        GeneralPurposeConfig::new()
            .with_decode_allow_trailing_bits(true)
            .with_decode_padding_mode(DecodePaddingMode::RequireCanonical),
    )
    .decode(clean.as_bytes())
    .map_err(LoginError::Base64)
}

/// Accepts Go raw URL base64 while identifying canonical input without extra normal-path allocation.
fn decode_compact(value: &str) -> Result<(Vec<u8>, bool), LoginError> {
    if let Ok(bytes) = URL_SAFE_NO_PAD.decode(value) {
        return Ok((bytes, true));
    }
    let clean = if value.contains(['\r', '\n']) {
        Cow::Owned(value.replace(['\r', '\n'], ""))
    } else {
        Cow::Borrowed(value)
    };
    let engine = GeneralPurpose::new(
        &alphabet::URL_SAFE,
        GeneralPurposeConfig::new()
            .with_decode_allow_trailing_bits(true)
            .with_decode_padding_mode(DecodePaddingMode::RequireNone),
    );
    engine
        .decode(clean.as_bytes())
        .map(|bytes| (bytes, false))
        .map_err(LoginError::Base64)
}

/// Builds canonical base64 from original bytes, borrowing ordinary encoded authentication input.
fn authentication_input<'a>(
    wire: &'a str,
    protected: &[u8],
    payload: &[u8],
    encoded: bool,
    canonical: bool,
) -> Cow<'a, [u8]> {
    if encoded && canonical {
        return Cow::Borrowed(wire.as_bytes());
    }
    let mut input = String::with_capacity(wire.len());
    URL_SAFE_NO_PAD.encode_string(protected, &mut input);
    input.push('.');
    if encoded {
        URL_SAFE_NO_PAD.encode_string(payload, &mut input);
        Cow::Owned(input.into_bytes())
    } else {
        let mut input = input.into_bytes();
        input.extend_from_slice(payload);
        Cow::Owned(input)
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Returns a compact framing fixture; signature verification is separate from this memory check.
    fn compact(header: &[u8]) -> String {
        format!(
            "{}.{}.{}",
            URL_SAFE_NO_PAD.encode(header),
            URL_SAFE_NO_PAD.encode(b"{}"),
            URL_SAFE_NO_PAD.encode([0; 96])
        )
    }

    #[test]
    fn canonical_authentication_input_is_borrowed() {
        for header in [
            br#"{"alg":"ES384"}"#.as_slice(),
            br#"{"alg":"ES384","b64":true}"#,
            br#"{"alg":"ES384","b64":null}"#,
            br#"{"alg":"ES384","b64":17}"#,
        ] {
            let wire = compact(header);
            let parsed = Token::parse(&wire, wire.len(), false).unwrap();
            assert!(matches!(parsed.input, Cow::Borrowed(_)));
            assert_eq!(
                parsed.signing_input(),
                wire.rsplit_once('.').unwrap().0.as_bytes()
            );
        }
        let wire = compact(br#"{"alg":"ES384"}"#);
        let mut signature_crlf = wire.clone();
        signature_crlf.push_str("\r\n");
        let parsed = Token::parse(&signature_crlf, signature_crlf.len(), false).unwrap();
        assert!(matches!(parsed.input, Cow::Borrowed(_)));
    }

    #[test]
    fn canonicalization_preserves_original_header_and_raw_payload_bytes() {
        let header = b" { \"alg\" : \"ES384\", \"b64\":false } ";
        let mut wire = compact(header);
        wire.insert_str(2, "\r\n");
        let parsed = Token::parse(&wire, wire.len(), false).unwrap();
        let expected = [URL_SAFE_NO_PAD.encode(header).as_bytes(), b".", b"{}"].concat();
        assert_eq!(parsed.signing_input(), expected);
        assert!(matches!(parsed.input, Cow::Owned(_)));
    }

    #[test]
    fn metadata_header_x5u_is_generic_and_never_selects_a_key() {
        for value in ["17", "false", "{}", "[]", "null", r#""untrusted""#] {
            let wire = compact(format!(r#"{{"alg":"ES384","x5u":{value}}}"#).as_bytes());
            assert!(Token::parse(&wire, wire.len(), false).is_ok(), "{value}");
            assert!(verify_server(&wire, wire.len()).is_err(), "{value}");
        }
        for value in ["1e400", r#"{"a":1,"a":2}"#] {
            let wire = compact(format!(r#"{{"alg":"ES384","x5u":{value}}}"#).as_bytes());
            assert!(Token::parse(&wire, wire.len(), false).is_err(), "{value}");
        }
    }

    #[test]
    fn jose_generic_header_values_keep_their_own_depth_policy() {
        let value = format!("{}0{}", "[".repeat(15_000), "]".repeat(15_000));
        for field in ["b64", "x5u"] {
            let wire = compact(format!(r#"{{"alg":"ES384","{field}":{value}}}"#).as_bytes());
            assert!(Token::parse(&wire, wire.len(), false).is_ok(), "{field}");
        }
    }
}
