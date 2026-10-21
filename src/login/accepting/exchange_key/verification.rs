//! Verification for offline NIST signers using SHA384 and fixed-width JOSE integers.

use p384::ecdsa::{Error, signature::hazmat::PrehashVerifier};
use sha2::{Digest, Sha384};

/// Converts ES384's two integers to the curve's scalar width without losing nonzero bytes.
fn scalars<const N: usize>(signature: &[u8; 96]) -> Result<([u8; N], [u8; N]), Error> {
    let mut r = [0; N];
    let mut s = [0; N];
    for (source, dest) in signature.as_chunks::<48>().0.iter().zip([&mut r, &mut s]) {
        if N < 48 {
            if source[..48 - N].iter().any(|byte| *byte != 0) {
                return Err(Error::new());
            }
            dest.copy_from_slice(&source[48 - N..]);
        } else {
            dest[N - 48..].copy_from_slice(source);
        }
    }
    Ok((r, s))
}

/// Verifies with the already validated uncompressed point; no private scalar is used here.
pub(super) fn verify(point: &[u8], input: &[u8], signature: &[u8; 96]) -> Result<(), Error> {
    let digest = Sha384::digest(input);
    match point.len() {
        57 => {
            use p224::ecdsa::signature::hazmat::PrehashVerifier as _;
            let (r, s) = scalars::<28>(signature)?;
            let signature = p224::ecdsa::Signature::from_scalars(r, s).map_err(|_| Error::new())?;
            p224::ecdsa::VerifyingKey::from_sec1_bytes(point)
                .map_err(|_| Error::new())?
                .verify_prehash(&digest, &signature)
                .map_err(|_| Error::new())
        }
        65 => {
            let (r, s) = scalars::<32>(signature)?;
            let signature = p256::ecdsa::Signature::from_scalars(r, s)?;
            p256::ecdsa::VerifyingKey::from_sec1_bytes(point)?.verify_prehash(&digest, &signature)
        }
        133 => {
            let (r, s) = scalars::<66>(signature)?;
            let signature = p521::ecdsa::Signature::from_scalars(r, s)?;
            p521::ecdsa::VerifyingKey::from_sec1_bytes(point)?.verify_prehash(&digest, &signature)
        }
        _ => Err(Error::new()),
    }
}
