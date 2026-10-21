//! Sealed revalidation policy for the exact retained Login capability.

use super::{AuthenticatedLogin, LoginError, LoginVerifier};
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
    /// Rechecks the same retained capability at caller-supplied provider UTC.
    ///
    /// # Errors
    /// Rejects revoked, expired or changed provider credentials without a fallback.
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
