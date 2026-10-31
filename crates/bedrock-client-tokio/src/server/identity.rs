//! One durable proof for signed signaling and the accepting Bedrock handshake.

use nethernet_tokio::ServerIdentity;
use p384::ecdsa::SigningKey;
use std::{io, path::Path, sync::Arc};
use zeroize::Zeroizing;

/// Loads or durably creates one saved key for both signaling and accepting Login.
/// Supply the returned identity to the listener and its matching key to `from_nether`.
pub async fn load_identity(
    path: impl AsRef<Path>,
    domain: impl Into<String>,
) -> io::Result<(Arc<SigningKey>, Arc<ServerIdentity>)> {
    let identity = nethernet_tokio::util::identity::from_pem_or_create(path, domain)
        .await
        .map_err(crate::connect::transport_error)?;
    let pem = Zeroizing::new(
        identity
            .to_pem()
            .map_err(|error| crate::connect::transport_error(error.into()))?,
    );
    let key = p384::SecretKey::from_pem(&pem).map_err(io::Error::other)?;
    Ok((Arc::new(key.into()), Arc::new(identity)))
}
