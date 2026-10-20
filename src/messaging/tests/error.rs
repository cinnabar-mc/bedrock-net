//! Explicit cause inspection must not make ordinary error formatting disclose peer data.

use super::Error;
use nethernet_tokio::{NetherError, error::SignalErrorCode};
use std::{error::Error as _, io, sync::Arc};

/// Every string-bearing transport category stays redacted while the same cause remains inspectable.
#[test]
fn connection_cause_is_retained_without_disclosing_sensitive_diagnostics() {
    const PRIVATE: &str = "dummy-private-token-sdp-url-and-identity";
    for cause in [
        NetherError::Ice(PRIVATE.into()),
        NetherError::Dtls(PRIVATE.into()),
        NetherError::Sctp(PRIVATE.into()),
        NetherError::Protocol(nethernet::error::ProtocolError::Other(PRIVATE.into())),
        NetherError::Identity(nethernet::identity::error::IdentityError::Untrusted(
            PRIVATE.into(),
        )),
        NetherError::Signaling(nethernet_tokio::error::SignalingError::SendFailed(
            PRIVATE.into(),
        )),
        NetherError::Io(io::Error::new(io::ErrorKind::PermissionDenied, PRIVATE)),
        NetherError::PendingCountExceeded(PRIVATE.into()),
        NetherError::DataChannel(PRIVATE.into()),
        NetherError::MessageParse(PRIVATE.into()),
        NetherError::InvalidState(PRIVATE.into()),
        NetherError::Other(PRIVATE.into()),
    ] {
        let cause = Arc::new(cause);
        let error = Error::Connection(Arc::clone(&cause));
        assert!(!error.to_string().contains(PRIVATE));
        assert_eq!(format!("{error:?}"), error.to_string());
        assert_eq!(format!("{error:#?}"), error.to_string());
        assert_eq!(error.source().unwrap().to_string(), cause.to_string());
        let Error::Connection(cloned) = error.clone() else {
            panic!("cloning changed the connection error category");
        };
        assert!(Arc::ptr_eq(&cause, &cloned));
    }
}

/// Safe signal and I/O context exposes typed facts without rendering arbitrary source text.
#[test]
fn connection_context_preserves_signal_and_io_categories() {
    let signaled = Error::Connection(Arc::new(NetherError::Signaled(
        SignalErrorCode::NotLoggedIn,
    )));
    assert_eq!(
        signaled.to_string(),
        "messaging transport connection failed: signaled (NotLoggedIn, 25)"
    );
    for cause in [
        io::Error::new(io::ErrorKind::PermissionDenied, "dummy-private-io-detail"),
        io::Error::from_raw_os_error(13),
    ] {
        let expected = format!(
            "messaging transport connection failed: I/O ({:?}, os={:?})",
            cause.kind(),
            cause.raw_os_error()
        );
        let error = Error::Connection(Arc::new(NetherError::Io(cause)));
        assert_eq!(error.to_string(), expected);
        assert_eq!(format!("{error:?}"), expected);
    }
    assert!(Error::Transport.source().is_none());
    assert_eq!(Error::Transport.to_string(), "messaging transport failed");
}
