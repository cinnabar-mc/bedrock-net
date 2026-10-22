// SPDX-License-Identifier: MIT

//! Final packet IO must finish the same connection's original physical transport.

use super::*;
use std::{io, net::UdpSocket, task::Poll};

#[derive(Debug)]
pub(super) struct Observation {
    initially_pending: bool,
    socket_held_on_first_poll: bool,
    finish: Option<io::ErrorKind>,
    socket_released_at_completion: bool,
    cleanup: Option<io::ErrorKind>,
    socket_released_after_cleanup: bool,
}

/// Probes generic trait dispatch while retaining the original connection through physical cleanup.
pub(super) async fn observe(
    connection: &mut Connection,
    address: std::net::SocketAddr,
) -> Observation {
    let (initially_pending, socket_held_on_first_poll, finish) = {
        let mut finish = std::pin::pin!(PacketIo::finish_close(connection));
        let first = futures::poll!(finish.as_mut());
        // No actor can run between the first poll and this synchronous socket probe.
        let held =
            UdpSocket::bind(address).is_err_and(|error| error.kind() == io::ErrorKind::AddrInUse);
        let (pending, result) = match first {
            Poll::Pending => (true, finish.await),
            Poll::Ready(result) => (false, result),
        };
        (pending, held, result.err().map(|error| error.kind()))
    };
    let socket_released_at_completion = UdpSocket::bind(address).is_ok();
    // The original final transport operation rescues the request-only baseline before assertions.
    let cleanup = connection
        .transport_mut()
        .finish_close()
        .await
        .err()
        .map(|error| error.kind());
    let socket_released_after_cleanup = UdpSocket::bind(address).is_ok();
    Observation {
        initially_pending,
        socket_held_on_first_poll,
        finish,
        socket_released_at_completion,
        cleanup,
        socket_released_after_cleanup,
    }
}

/// Successful generic final close releases the actual original media socket before returning.
#[tokio::test]
async fn generic_packet_io_final_close_waits_for_the_original_connection_socket() {
    let observed = pack_effects_with_retirement(true).await.unwrap();
    assert_eq!(observed.finish, None, "{observed:?}");
    assert_eq!(observed.cleanup, None, "{observed:?}");
    assert!(observed.socket_held_on_first_poll, "{observed:?}");
    assert!(observed.socket_released_after_cleanup, "{observed:?}");
    assert!(
        observed.initially_pending && observed.socket_released_at_completion,
        "generic final close returned before its original transport retired: {observed:?}"
    );
}
