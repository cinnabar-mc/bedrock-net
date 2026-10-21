//! Embedded public JWK shapes; these keys never replace the Login-selected signer.

use super::{ClientExchangeKey, Object, PublicKey, certificate, decode, url};
use num_bigint::BigUint;
use serde_json::value::RawValue;
use sha1::Digest as _;
use sha2::Digest as _;
use std::collections::BTreeMap;

/// Decodes the JWK and certificate binding required by JOSE's embedded-public-key gate.
pub(super) fn parse(raw: &RawValue) -> Option<PublicKey> {
    let object = Object::parse(raw.get().as_bytes()).ok()?;
    for name in ["use", "kty", "kid", "crv", "alg", "x5u", "x5t", "x5t#S256"] {
        object.text(name).ok()?;
    }
    let mut bytes = BTreeMap::new();
    for name in ["k", "x", "y", "n", "e", "d", "p", "q", "dp", "dq", "qi"] {
        if let Some(value) = object.text(name).ok()? {
            bytes.insert(name, decode(&value, true).ok()?);
        }
    }
    // JOSE rejects symmetric/private embedded keys after decoding, even in unverified mode.
    if bytes.contains_key("d") {
        return None;
    }
    let key = match object.text("kty").ok()?.as_deref()? {
        "EC" => ec(&object.text("crv").ok()??, bytes.get("x")?, bytes.get("y")?)?,
        "RSA" => {
            let n = BigUint::from_bytes_be(bytes.get("n")?);
            let e = bytes.get("e")?;
            let mut low = [0u8; 8];
            let suffix = &e[e.len().saturating_sub(8)..];
            low[8 - suffix.len()..].copy_from_slice(suffix);
            let e = i64::from_be_bytes(low);
            if e == 0 {
                return None;
            }
            PublicKey::Rsa(n, e)
        }
        "OKP" if object.text("crv").ok()?.as_deref() == Some("Ed25519") => {
            let source = bytes.get("x")?;
            let mut key = [0; 32];
            let length = source.len().min(32);
            key[..length].copy_from_slice(&source[..length]);
            PublicKey::Ed(key)
        }
        _ => return None,
    };
    if let Some(address) = object.text("x5u").ok()?
        && url::parse(&address).is_none()
    {
        return None;
    }
    let certificates = match object.exact("x5c") {
        Some(raw) => certificate::chain(raw)?,
        None => Vec::new(),
    };
    if let Some(leaf) = certificates.first()
        && let Some(cert_key) = certificate::key(leaf)?
        && key != cert_key
    {
        return None;
    }
    for (name, width) in [("x5t", 20), ("x5t#S256", 32)] {
        let mut hash = decode(&object.text(name).ok()?.unwrap_or_default(), true).ok()?;
        if hash.len() == width * 2 {
            if !hash.iter().all(u8::is_ascii_hexdigit) {
                return None;
            }
            hash = hash
                .as_chunks::<2>()
                .0
                .iter()
                .map(|pair| {
                    let text = std::str::from_utf8(pair).ok()?;
                    u8::from_str_radix(text, 16).ok()
                })
                .collect::<Option<Vec<_>>>()?;
        }
        if !hash.is_empty() && hash.len() != width {
            return None;
        }
        if !hash.is_empty()
            && let Some(leaf) = certificates.first()
        {
            let expected = if width == 20 {
                sha1::Sha1::digest(leaf).to_vec()
            } else {
                sha2::Sha256::digest(leaf).to_vec()
            };
            if hash != expected {
                return None;
            }
        }
    }
    Some(key)
}

/// Validates exact coordinate widths and curve membership through the existing PKIX key owner.
fn ec(curve: &str, x: &[u8], y: &[u8]) -> Option<PublicKey> {
    let (width, oid): (usize, &[u8]) = match curve {
        "P-256" => (32, b"\x2a\x86\x48\xce\x3d\x03\x01\x07"),
        "P-384" => (48, b"\x2b\x81\x04\x00\x22"),
        "P-521" => (66, b"\x2b\x81\x04\x00\x23"),
        _ => return None,
    };
    if x.len() != width || y.len() != width {
        return None;
    }
    let algorithm = [der(6, b"\x2a\x86\x48\xce\x3d\x02\x01"), der(6, oid)].concat();
    let bits = [&[0, 4][..], x, y].concat();
    let spki = der(0x30, &[der(0x30, &algorithm), der(3, &bits)].concat());
    let key = ClientExchangeKey::parse(&spki)?;
    Some(PublicKey::Ec(key.public_key_der().into()))
}

/// Encodes the small definite-length DER fields used to hand existing EC parsing a JWK point.
fn der(tag: u8, contents: &[u8]) -> Vec<u8> {
    let mut result = vec![tag];
    if contents.len() < 128 {
        result.push(contents.len() as u8);
    } else {
        result.extend([0x81, contents.len() as u8]);
    }
    result.extend_from_slice(contents);
    result
}
