//! Errors from Login request formatting and server key exchange.

/// A failure before a Login request or cipher pair can be published.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum LoginError {
    /// The input or encoded request exceeds the caller's byte ceiling.
    #[error("login byte limit exceeded ({limit})")]
    LimitExceeded {
        /// Maximum permitted bytes.
        limit: usize,
    },
    /// The caller's UTC time or validity window cannot be represented.
    #[error("login validity time is out of range")]
    InvalidTime,
    /// A Login field cannot be represented by its wire length prefix.
    #[error("login field length is out of range")]
    InvalidLength,
    /// Client data is valid JSON but is not an object.
    #[error("login client data must be a JSON object")]
    InvalidClientData,
    /// Authenticated Login requires a nonempty previously acquired credential.
    #[error("login authentication token is empty")]
    EmptyAuthenticationToken,
    /// JSON could not be encoded or decoded.
    #[error("invalid login JSON")]
    Json(#[source] serde_json::Error),
    /// A server token is not a compact JWS.
    #[error("invalid server handshake token framing")]
    MalformedToken,
    /// The token asks for an unsupported signature algorithm or critical extension.
    #[error("unsupported server handshake token header")]
    UnsupportedHeader,
    /// A token segment or salt is not valid base64.
    #[error("invalid server handshake base64")]
    Base64(#[source] base64::DecodeError),
    /// The server's key is not a DER P-384 public key.
    #[error("invalid server handshake public key")]
    PublicKey(#[source] p384::pkcs8::spki::Error),
    /// A signature could not be created, parsed or verified.
    #[error("invalid login signature")]
    Signature(#[source] p384::ecdsa::Error),
}
