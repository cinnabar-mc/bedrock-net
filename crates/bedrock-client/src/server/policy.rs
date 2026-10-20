//! Sealed revalidation policy for the exact retained Login capability.

use super::{AuthenticatedLogin, LoginError, LoginVerifier, VerifyingKey};
use std::time::SystemTime;

/// Revalidates the original Login without changing its capability type.
///
/// Only library policies implement this interface. Provider-authenticated Login
/// always uses the caller's configured provider verifier, including after waits.
///
/// ```compile_fail
/// struct Bypass;
/// impl bedrock_client::server::LoginPolicy<bedrock_net::login::AuthenticatedLogin> for Bypass {
///     fn revalidate(&self, _: &bedrock_net::login::AuthenticatedLogin,
///         _: std::time::SystemTime) -> Result<(), bedrock_net::login::LoginError> { Ok(()) }
/// }
/// ```
pub trait LoginPolicy<L>: sealed::Sealed<L> {
    /// Rechecks the same retained capability under its admission policy and caller UTC.
    ///
    /// # Errors
    /// Provider policies reject revoked, expired or changed credentials without a fallback.
    fn revalidate(&self, login: &L, utc: SystemTime) -> Result<(), LoginError>;
}

impl<V: LoginVerifier> LoginPolicy<AuthenticatedLogin> for V {
    fn revalidate(&self, login: &AuthenticatedLogin, utc: SystemTime) -> Result<(), LoginError> {
        login.revalidate(self, utc)
    }
}

pub(super) mod sealed {
    /// Restricts revalidation implementations to the library's supported policies.
    pub trait Sealed<L> {}
    impl<V: super::LoginVerifier> Sealed<super::AuthenticatedLogin> for V {}
}

/// Parses and binds a supported Login capability under an explicit library policy.
/// The sealed parent policy prevents a caller from substituting a different capability type.
pub trait HandshakePolicy<L>: LoginPolicy<L> {
    /// Parses the bounded request under this exact admission policy.
    ///
    /// # Errors
    /// Rejects invalid framing, policy, signature, client data or required cached resolution.
    fn parse(&self, request: &[u8], utc: SystemTime, limit: usize) -> Result<L, LoginError>;

    /// Borrows the final P384 exchange key, returning None for another supported parse curve.
    fn exchange_key<'a>(&self, login: &'a L) -> Option<&'a VerifyingKey>;
}

impl<V: LoginVerifier> HandshakePolicy<AuthenticatedLogin> for V {
    fn parse(
        &self,
        request: &[u8],
        utc: SystemTime,
        limit: usize,
    ) -> Result<AuthenticatedLogin, LoginError> {
        bedrock_net::login::verify_authenticated_request(request, self, utc, limit)
    }

    fn exchange_key<'a>(&self, login: &'a AuthenticatedLogin) -> Option<&'a VerifyingKey> {
        login.exchange_key().as_p384()
    }
}
