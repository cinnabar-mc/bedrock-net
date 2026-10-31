//! Explicit unauthenticated accepting policy with cached client-address resolution.

use super::{HandshakePolicy, LoginPolicy, VerifyingKey, policy::sealed};
use bedrock_net::login::{LoginError, OfflineLogin, parse_offline_request};
use std::time::SystemTime;

/// Explicit offline admission policy; account claims remain untrusted throughout accepting.
///
/// The callback supplies cached UDP resolution with no blocking or network I/O.
/// Return `LoginError::AddressResolutionRequired` on a cache miss, acquire that
/// result asynchronously, then retry the same bounded request before submitting
/// it to a consuming Login continuation. Literal addresses need no callback.
///
/// The original deadline and explicit caller authorization still bound every
/// accepting transition. Legacy time checks run once during parsing; modern
/// identity signature, expiry and audience are unverified in this policy.
///
/// Offline sessions keep their distinct capability at the final handoff:
/// ```compile_fail
/// use bedrock_client::server::session::AcceptedSession;
/// use bedrock_net::login::{AuthenticatedLogin, OfflineLogin};
/// fn promote(session: AcceptedSession<(), OfflineLogin>) -> AuthenticatedLogin {
///     session.into_parts().0
/// }
/// ```
pub struct OfflinePolicy<R> {
    resolve: R,
}

impl<R: Fn(&str) -> Result<(), LoginError>> OfflinePolicy<R> {
    /// Retains the caller's pure cached-resolution lookup for offline Login parsing.
    pub fn new(resolve: R) -> Self {
        Self { resolve }
    }
}

impl<R> sealed::Sealed<OfflineLogin> for OfflinePolicy<R> {}

impl<R: Fn(&str) -> Result<(), LoginError>> LoginPolicy<OfflineLogin> for OfflinePolicy<R> {
    /// Keeps provider revalidation absent for an already parsed offline capability.
    fn revalidate(&self, _: &OfflineLogin, _: SystemTime) -> Result<(), LoginError> {
        // Offline admission has no provider credential; the engine checks its original deadline.
        Ok(())
    }
}

impl<R: Fn(&str) -> Result<(), LoginError>> HandshakePolicy<OfflineLogin> for OfflinePolicy<R> {
    /// Parses through the one shared signed metadata owner with this cached resolver.
    fn parse(
        &self,
        request: &[u8],
        utc: SystemTime,
        limit: usize,
    ) -> Result<OfflineLogin, LoginError> {
        parse_offline_request(request, utc, limit, &self.resolve)
    }

    /// Borrows the final signed key for the existing transport boundary.
    fn exchange_key<'a>(&self, login: &'a OfflineLogin) -> Option<&'a VerifyingKey> {
        login.exchange_key().as_p384()
    }
}
