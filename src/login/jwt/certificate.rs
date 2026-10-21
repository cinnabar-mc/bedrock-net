//! Untrusted X.509 syntax and public-key decoding; certificates grant no issuer authority.

use super::{ClientExchangeKey, decode};
use num_bigint::BigUint;
use serde_json::value::RawValue;

mod der;
mod extensions;
mod names;
mod validity;

/// Decodes every certificate, including unused intermediates, without checking signatures or time.
pub(super) fn chain(raw: &RawValue) -> Option<Vec<Vec<u8>>> {
    strings(raw)?
        .into_iter()
        .map(|value| {
            let bytes = decode(&value, false).ok()?;
            let _ = key(&bytes)?;
            Some(bytes)
        })
        .collect()
}

/// Checks certificate framing and returns the parsed public key for optional JWK equality.
pub(super) fn key(bytes: &[u8]) -> Option<Option<PublicKey>> {
    let raw = der::certificate(bytes)?;
    let mut input = raw;
    let mut spki = der::take(&mut input, 0x30)?;
    let (oid, parameters) = der::algorithm(der::take(&mut spki, 0x30)?)?;
    let bits = der::take(&mut spki, 3)?;
    der::bits(bits)?;
    let (&unused, data) = bits.split_first()?;
    let mut bits = data.to_vec();
    if unused > 0 {
        let mut previous = 0;
        for byte in &mut bits {
            let current = *byte;
            *byte = (current >> unused) | (previous << (8 - unused));
            previous = current;
        }
    }
    let mut data = bits.as_slice();
    let key = match oid {
        b"\x2a\x86\x48\xce\x3d\x02\x01" => {
            PublicKey::Ec(ClientExchangeKey::parse(raw)?.public_key_der().into())
        }
        b"\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01" => {
            if parameters != b"\x05\x00" {
                return None;
            }
            let mut sequence = der::take(&mut data, 0x30)?;
            let n = positive(der::take(&mut sequence, 2)?)?;
            let e = der::signed(der::take(&mut sequence, 2)?)?;
            if e <= 0 {
                return None;
            }
            PublicKey::Rsa(n, e)
        }
        b"\x2b\x65\x70" => {
            if !parameters.is_empty() || bits.len() != 32 {
                return None;
            }
            PublicKey::Ed(bits.try_into().ok()?)
        }
        b"\x2a\x86\x48\xce\x38\x04\x01" => {
            positive(der::take(&mut data, 2)?)?;
            let mut parameters = parameters;
            let mut sequence = der::take(&mut parameters, 0x30)?;
            for _ in 0..3 {
                positive(der::take(&mut sequence, 2)?)?;
            }
            PublicKey::Other
        }
        _ => return Some(None),
    };
    Some(Some(key))
}

/// Requires the positive ASN.1 integers used by parsed certificate public keys.
fn positive(bytes: &[u8]) -> Option<BigUint> {
    let bytes = der::integer(bytes)?;
    if bytes[0] & 128 != 0 {
        return None;
    }
    let value = BigUint::from_bytes_be(bytes);
    (value != BigUint::from(0u8)).then_some(value)
}

/// Decodes null-defaulted certificate string elements without inventing a trusted chain.
fn strings(raw: &RawValue) -> Option<Vec<String>> {
    let values: Option<Vec<Option<String>>> = serde_json::from_str(raw.get()).ok()?;
    Some(
        values
            .unwrap_or_default()
            .into_iter()
            .map(Option::unwrap_or_default)
            .collect(),
    )
}

#[derive(PartialEq)]
pub(super) enum PublicKey {
    Ec(Box<[u8]>),
    Rsa(num_bigint::BigUint, i64),
    Ed([u8; 32]),
    Other,
}
