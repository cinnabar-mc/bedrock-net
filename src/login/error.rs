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
    /// Only modern authenticated provider Login is implemented by the accepting owner.
    #[error("unsupported login authentication mode")]
    UnsupportedAuthentication,
    /// The configured provider rejected this credential or returned an invalid identity.
    #[error("login provider authentication failed")]
    Authentication,
    /// Revalidation changed the original provider-authenticated account or proof key.
    #[error("login identity changed before admission")]
    IdentityChanged,
    /// Local JSON could not be encoded. Peer decoding uses the redacted [`Self::MalformedJson`].
    #[error("invalid login JSON")]
    Json(#[source] serde_json::Error),
    /// Peer JSON is malformed or has an invalid/ambiguous recognized field.
    /// No raw serde diagnostic retains input values in Debug or the source chain.
    #[error("invalid login JSON")]
    MalformedJson,
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

impl LoginError {
    /// Removes value-bearing JSON causes returned by an external verifier at the peer boundary.
    pub(super) fn redact_peer(self) -> Self {
        match self {
            Self::Json(_) => Self::MalformedJson,
            error => error,
        }
    }
}
