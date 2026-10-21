//! Signed client key updates with Go-compatible PKIX ECDSA curve acceptance.
// PKIX parsing follows Go's BSD-licensed crypto/x509 package; see LICENSE-GO.

use super::LoginError;
use num_bigint::BigUint;
use p384::{ecdsa::VerifyingKey, pkcs8::EncodePublicKey};

mod verification;

/// Validated client public key for offline metadata signing or final key exchange.
/// A signed key update does not prove possession of the new private key.
pub struct ClientExchangeKey {
    der: Box<[u8]>,
    p384: Option<VerifyingKey>,
    point_width: usize,
}

impl ClientExchangeKey {
    /// Borrows the canonical uncompressed PKIX public key, including accepted non-P384 curves.
    pub fn public_key_der(&self) -> &[u8] {
        &self.der
    }

    /// Borrows the key when it can participate in this stack's existing P384 exchange.
    /// Go Parse accepts other ECDSA curves, but its P384 ECDH continuation rejects them.
    pub fn as_p384(&self) -> Option<&VerifyingKey> {
        self.p384.as_ref()
    }

    /// Starts the final exchange with the provider-bound signing key when no update is present.
    pub(super) fn from_signer(key: &VerifyingKey) -> Result<Self, LoginError> {
        let der = key.to_public_key_der().map_err(LoginError::PublicKey)?;
        Ok(Self {
            der: der.as_bytes().into(),
            p384: Some(*key),
            point_width: 48,
        })
    }

    /// Retains the same validated public key when the final exchange key does not rotate.
    pub(super) fn duplicate(&self) -> Self {
        Self {
            der: self.der.clone(),
            p384: self.p384,
            point_width: self.point_width,
        }
    }

    /// Verifies SHA384 with this validated NIST point and the fixed ES384 integer encoding.
    pub(super) fn verify_es384(
        &self,
        input: &[u8],
        signature: &[u8; 96],
    ) -> Result<(), LoginError> {
        use p384::ecdsa::{Signature, signature::Verifier};
        if let Some(key) = &self.p384 {
            let signature = Signature::from_slice(signature).map_err(LoginError::Signature)?;
            return key.verify(input, &signature).map_err(LoginError::Signature);
        }
        // Canonical DER ends with the already validated, uncompressed public point.
        let point = &self.der[self.der.len() - (1 + 2 * self.point_width)..];
        verification::verify(point, input, signature).map_err(LoginError::Signature)
    }

    /// Validates a signed PKIX ECDSA point and retains its canonical representation.
    pub(in crate::login) fn parse(bytes: &[u8]) -> Option<Self> {
        let mut outer = bytes;
        let mut sequence = take(&mut outer, 0x30)?;
        if !outer.is_empty() {
            return None;
        }
        let mut algorithm = take(&mut sequence, 0x30)?;
        if take(&mut algorithm, 0x06)? != b"\x2a\x86\x48\xce\x3d\x02\x01" {
            return None;
        }
        let curve = take(&mut algorithm, 0x06)?;
        let bits = take(&mut sequence, 0x03)?;
        let (&unused, encoded) = bits.split_first()?;
        if unused > 7 || encoded.is_empty() || encoded.last()? & ((1u8 << unused) - 1) != 0 {
            return None;
        }
        let mut point = encoded.to_vec();
        if unused != 0 {
            let mut previous = 0;
            for byte in &mut point {
                let current = *byte;
                *byte = (current >> unused) | (previous << (8 - unused));
                previous = current;
            }
        }
        // Go's ASN.1 struct decoder ignores additional sequence fields. The required fields above
        // still use definite, minimally encoded DER lengths and exact primitive tags.
        let (width, prime, b) = match curve {
            b"\x2b\x81\x04\x00\x21" => (
                28,
                "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF000000000000000000000001",
                "B4050A850C04B3ABF54132565044B0B7D7BFD8BA270B39432355FFB4",
            ),
            b"\x2a\x86\x48\xce\x3d\x03\x01\x07" => (
                32,
                "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF",
                "5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B",
            ),
            b"\x2b\x81\x04\x00\x22" => (48, "", ""),
            b"\x2b\x81\x04\x00\x23" => (
                66,
                "1FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
                "51953EB9618E1C9A1F929A21A0B68540EEA2DA725B99B315F3B8B489918EF109E156193951EC7E937B1652C0BD3BB1BF073573DF883D2C34F1EF451FD46B503F00",
            ),
            _ => return None,
        };
        if point.len() != 1 + 2 * width || point[0] != 4 {
            return None;
        }
        let p384 = if width == 48 {
            Some(VerifyingKey::from_sec1_bytes(&point).ok()?)
        } else {
            if !on_curve(&point[1..], width, prime, b) {
                return None;
            }
            None
        };
        let mut algorithm = der(0x06, b"\x2a\x86\x48\xce\x3d\x02\x01");
        algorithm.extend(der(0x06, curve));
        let mut contents = der(0x30, &algorithm);
        let mut bits = vec![0];
        bits.extend(point);
        contents.extend(der(0x03, &bits));
        Some(Self {
            der: der(0x30, &contents).into_boxed_slice(),
            p384,
            point_width: width,
        })
    }
}

/// Reads one required DER field while leaving ASN.1 struct extension fields to its caller.
fn take<'a>(bytes: &mut &'a [u8], tag: u8) -> Option<&'a [u8]> {
    if *bytes.first()? != tag {
        return None;
    }
    let first = *bytes.get(1)?;
    let mut header = 2;
    let length = if first < 128 {
        usize::from(first)
    } else {
        let count = usize::from(first & 127);
        if count == 0 || *bytes.get(2)? == 0 {
            return None;
        }
        header += count;
        let mut length = 0usize;
        for b in bytes.get(2..header)? {
            length = length.checked_mul(256)?.checked_add(usize::from(*b))?;
        }
        if length < 128 {
            return None;
        }
        length
    };
    let end = header.checked_add(length)?;
    let value = bytes.get(header..end)?;
    *bytes = bytes.get(end..)?;
    Some(value)
}

/// Encodes the small canonical PKIX fields for the supported NIST public points.
fn der(tag: u8, body: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    if body.len() < 128 {
        out.push(body.len() as u8);
    } else {
        out.extend([0x81, body.len() as u8]);
    }
    out.extend_from_slice(body);
    out
}

/// Checks public coordinates on a NIST curve with a=-3; no private scalar uses this variable-time math.
fn on_curve(point: &[u8], width: usize, prime: &str, b: &str) -> bool {
    let p = BigUint::parse_bytes(prime.as_bytes(), 16).expect("constant NIST prime");
    let b = BigUint::parse_bytes(b.as_bytes(), 16).expect("constant NIST coefficient");
    let x = BigUint::from_bytes_be(&point[..width]);
    let y = BigUint::from_bytes_be(&point[width..]);
    if x >= p || y >= p {
        return false;
    }
    (&y * &y) % &p == ((&x * &x * &x) + b + (&p * 3u8) - (&x * 3u8)) % p
}
