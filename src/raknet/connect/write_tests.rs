//! One injected send result on a real public connection attempt, with original UDP/core owners.

use std::io;
use std::sync::{Arc, Mutex, PoisonError};

use ::raknet::prelude::{
    Established, RakPriority, RakReliability, RakServer, RakServerConfig, RakServerInput,
    RakServerOutput, RakSession, RakSessionInput, RakSessionOutput, RakSessionState,
};
use bytes::Bytes;
use tokio::sync::oneshot;

use super::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Phase {
    Probe,
    OfflineRequest2,
    Connected,
}

struct Fault {
    phase: Option<Phase>,
    kind: io::ErrorKind,
    local: Option<SocketAddr>,
    changed_socket: bool,
    injections: usize,
    probes: usize,
    requests: usize,
    connected: usize,
}

tokio::task_local! {
    /// Exists only while this one original public connect future is polled.
    static WRITE_FAULT: Arc<Mutex<Fault>>;
}

/// Rejects one selected actual send boundary; every later call uses the original socket.
pub(super) fn reject_write(socket: &UdpSocket, phase: Phase) -> io::Result<Option<io::Error>> {
    match WRITE_FAULT.try_with(|fault| {
        let local = socket.local_addr()?;
        let mut fault = fault.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(original) = fault.local {
            fault.changed_socket |= original != local;
        } else {
            fault.local = Some(local);
        }
        match phase {
            Phase::Probe => fault.probes += 1,
            Phase::OfflineRequest2 => fault.requests += 1,
            Phase::Connected => fault.connected += 1,
        }
        Ok(if fault.phase == Some(phase) && fault.injections == 0 {
            fault.injections += 1;
            Some(io::Error::new(
                fault.kind,
                "one injected handshake write failure",
            ))
        } else {
            None
        })
    }) {
        Ok(result) => result,
        Err(_) => Ok(None),
    }
}

#[derive(Default)]
struct PeerFacts {
    datagrams: usize,
    accepted: bool,
    echoed: usize,
}

/// Drives the existing public server/session over the same owned loopback UDP endpoint.
async fn serve(socket: &UdpSocket, mut retired: oneshot::Receiver<()>) -> io::Result<PeerFacts> {
    let now = Instant::now().into_std();
    let mut server = RakServer::new(
        RakServerConfig::default(),
        socket.local_addr()?,
        RakClock::new(now),
        now,
    )
    .map_err(io::Error::other)?;
    let mut session: Option<RakSession<Established>> = None;
    let mut facts = PeerFacts::default();
    let mut buffer = [0; UDP_BUFFER_BYTES];
    loop {
        let (length, from) = tokio::select! {
            biased;
            _ = &mut retired => return Ok(facts),
            received = socket.recv_from(&mut buffer) => received?,
        };
        let now = Instant::now().into_std();
        facts.datagrams += 1;
        server
            .handle(RakServerInput::Datagram(buffer[..length].into(), from, now))
            .map_err(io::Error::other)?;
        while let Some(output) = server.poll() {
            match output {
                RakServerOutput::SocketDatagram(bytes, peer) => {
                    socket.send_to(&bytes, peer).await?;
                }
                RakServerOutput::SessionConnected(accepted) => {
                    if session.is_some() {
                        return Err(io::Error::other(
                            "one attempt produced a second server session",
                        ));
                    }
                    facts.accepted = true;
                    session = Some(accepted);
                }
                RakServerOutput::SessionDatagram(bytes, id) => {
                    let session = session.as_mut().ok_or_else(|| {
                        io::Error::other("session datagram preceded its actual accepted owner")
                    })?;
                    if session.id() != id {
                        return Err(io::Error::other(
                            "datagram changed the original session identity",
                        ));
                    }
                    session
                        .handle(RakSessionInput::Datagram(bytes, now))
                        .map_err(io::Error::other)?;
                }
                RakServerOutput::SessionClosing(_) => {
                    return Err(io::Error::other(
                        "fresh server negotiation closed before handoff",
                    ));
                }
            }
        }
        if let Some(session) = &mut session {
            if session.state() != RakSessionState::Disconnected {
                session.tick(now).map_err(io::Error::other)?;
            }
            while let Some(output) = session.poll() {
                match output {
                    RakSessionOutput::Datagram(bytes, peer) => {
                        socket.send_to(&bytes, peer).await?;
                    }
                    RakSessionOutput::Packet(packet) => {
                        facts.echoed += 1;
                        session
                            .send(
                                packet,
                                RakReliability::ReliableOrdered,
                                RakPriority::Normal,
                                now,
                            )
                            .map_err(io::Error::other)?;
                        session.tick(now).map_err(io::Error::other)?;
                    }
                    RakSessionOutput::Disconnected(..) | RakSessionOutput::Wait(_) => {}
                }
            }
        }
    }
}

struct Outcome {
    exchange: Result<Bytes, RakNetError>,
    close: Option<Result<(), RakNetError>>,
    peer: PeerFacts,
    injections: usize,
    changed_socket: bool,
    probes: usize,
    requests: usize,
    connected: usize,
}

/// Retires both original socket owners even when the baseline returns the injected error.
async fn attempt(phase: Option<Phase>, kind: io::ErrorKind) -> Outcome {
    let options = RakNetOptions::default();
    let watchdog = options.connect_timeout + options.close_timeout;
    tokio::time::timeout(watchdog, async {
        let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let peer_address = socket.local_addr().unwrap();
        let fault = Arc::new(Mutex::new(Fault {
            phase,
            kind,
            local: None,
            changed_socket: false,
            injections: 0,
            probes: 0,
            requests: 0,
            connected: 0,
        }));
        let (retire, retired) = oneshot::channel();
        let serving = serve(&socket, retired);
        let connecting = async {
            let connection = WRITE_FAULT
                .scope(
                    Arc::clone(&fault),
                    RakNetConnection::connect(peer_address, options),
                )
                .await;
            let result = match connection {
                Ok(mut connection) => {
                    let exchange = async {
                        connection.queue_send(Bytes::from_static(b"\xfeoffline-write-marker"))?;
                        connection.flush().await?;
                        connection.recv().await
                    }
                    .await;
                    let close = match connection.begin_close() {
                        Ok(mut closing) => {
                            let result = closing.finish_close().await;
                            drop(closing);
                            result
                        }
                        Err(error) => {
                            let (closing, cause) = error.into_parts();
                            drop(closing);
                            Err(cause)
                        }
                    };
                    (exchange, Some(close))
                }
                Err(error) => (Err(error), None),
            };
            let _ = retire.send(());
            result
        };
        let (peer, (exchange, close)) = tokio::join!(serving, connecting);
        drop(socket);
        let local = fault.lock().unwrap_or_else(PoisonError::into_inner).local;
        // Both original drivers and socket owners have retired before any target verdict.
        drop(UdpSocket::bind(peer_address).await.unwrap());
        drop(
            UdpSocket::bind(local.expect("the actual attempt reached its send boundary"))
                .await
                .unwrap(),
        );
        let fault = fault.lock().unwrap_or_else(PoisonError::into_inner);
        let peer = peer.expect("original loopback server failed outside the injected write");
        Outcome {
            exchange,
            close,
            peer,
            injections: fault.injections,
            changed_socket: fault.changed_socket,
            probes: fault.probes,
            requests: fault.requests,
            connected: fault.connected,
        }
    })
    .await
    .expect("finite public handshake/send/retirement fixture stalled")
}

#[tokio::test]
async fn handshake_write_other_probe_error_keeps_the_original_attempt_and_echo_owner() {
    let outcome = attempt(Some(Phase::Probe), io::ErrorKind::Other).await;
    assert_eq!(outcome.injections, 1);
    assert!(!outcome.changed_socket);
    let echoed = outcome
        .exchange
        .expect("one non-size Request1 write error aborted the original negotiation");
    assert_eq!(echoed, Bytes::from_static(b"\xfeoffline-write-marker"));
    outcome
        .close
        .expect("actual connection was established")
        .unwrap();
    assert!(outcome.peer.accepted);
    assert_eq!(outcome.peer.echoed, 1);
    assert!(outcome.probes >= 2);
    assert!(outcome.requests >= 1);
    assert!(outcome.connected >= 1);
}

#[tokio::test]
async fn handshake_write_refused_request2_keeps_the_original_attempt_and_echo_owner() {
    let outcome = attempt(
        Some(Phase::OfflineRequest2),
        io::ErrorKind::ConnectionRefused,
    )
    .await;
    assert_eq!(outcome.injections, 1);
    assert!(!outcome.changed_socket);
    let echoed = outcome
        .exchange
        .expect("one Request2 write error aborted the original negotiation");
    assert_eq!(echoed, Bytes::from_static(b"\xfeoffline-write-marker"));
    outcome
        .close
        .expect("actual connection was established")
        .unwrap();
    assert!(outcome.peer.accepted);
    assert_eq!(outcome.peer.echoed, 1);
    assert!(outcome.probes >= 1);
    assert!(outcome.requests >= 2);
    assert!(outcome.connected >= 1);
}

#[tokio::test]
async fn handshake_write_connected_error_remains_fatal_after_offline_socket_progress() {
    let outcome = attempt(Some(Phase::Connected), io::ErrorKind::PermissionDenied).await;
    assert_eq!(outcome.injections, 1);
    assert!(!outcome.changed_socket);
    assert!(outcome.probes >= 1);
    assert!(outcome.requests >= 1);
    assert_eq!(outcome.connected, 1);
    assert!(outcome.peer.datagrams >= 2);
    assert_eq!(outcome.peer.echoed, 0);
    assert!(outcome.close.is_none());
    assert!(matches!(
        outcome.exchange,
        Err(RakNetError::Io(error)) if error.kind() == io::ErrorKind::PermissionDenied
    ));
}

#[tokio::test]
async fn handshake_write_uninjected_public_attempt_uses_the_same_real_echo_and_close() {
    let outcome = attempt(None, io::ErrorKind::Other).await;
    assert_eq!(outcome.injections, 0);
    assert!(!outcome.changed_socket);
    assert_eq!(
        outcome.exchange.unwrap(),
        Bytes::from_static(b"\xfeoffline-write-marker")
    );
    outcome
        .close
        .expect("actual connection was established")
        .unwrap();
    assert!(outcome.peer.accepted);
    assert_eq!(outcome.peer.echoed, 1);
    assert!(outcome.probes >= 1);
    assert!(outcome.requests >= 1);
    assert!(outcome.connected >= 1);
}
