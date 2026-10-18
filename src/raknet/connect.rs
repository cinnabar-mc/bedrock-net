use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use ::raknet::prelude::{
    ClientGuid, RakClient, RakClientConfig, RakClientError, RakClientInput, RakClientOutput,
    RakClock, RakSessionConfig, Sans, canonical_socket_addr, is_mtu_probe_size_error,
    is_transient_udp_read_error,
};
use tokio::net::UdpSocket;
use tokio::time::{Instant, sleep_until, timeout_at};

use super::{Engine, RakNetConnection, RakNetError, RakNetOptions, SessionSlot, UDP_BUFFER_BYTES};

const MAX_INITIAL_READ_ERRORS: usize = 10;

/// Shares the endpoint uptime origin across connection attempts in this process.
fn endpoint_clock() -> RakClock {
    static CLOCK: std::sync::OnceLock<RakClock> = std::sync::OnceLock::new();
    *CLOCK.get_or_init(|| RakClock::new(Instant::now().into_std()))
}

impl RakNetConnection {
    /// Completes a transport handshake, spawning no background tasks.
    ///
    /// Uses an ephemeral local port of the peer's address family. Cancelling the
    /// future closes the socket and drops all partial handshake state.
    ///
    /// # Errors
    /// Returns invalid option, socket, identity generation, handshake or overall timeout errors.
    pub async fn connect(peer: SocketAddr, options: RakNetOptions) -> Result<Self, RakNetError> {
        if options.receive_buffer_bytes == 0 || options.receive_buffer_messages == 0 {
            return Err(RakNetError::InvalidOption(
                "receive capacity must be positive",
            ));
        }
        let engine_send_limit = usize::try_from(RakSessionConfig::default().max_outbound_bytes)
            .expect("default RakNet outbound bound is positive");
        if options.send_buffer_bytes == 0 || options.send_buffer_bytes > engine_send_limit {
            return Err(RakNetError::InvalidOption(
                "send capacity must fit the engine limit",
            ));
        }
        let config = RakClientConfig {
            max_mtu_size: options.max_mtu,
            max_handshake_bytes: options.receive_buffer_bytes,
            max_handshake_messages: options.receive_buffer_messages,
            conn_attempt_timeout: options.connect_timeout,
            ..RakClientConfig::default()
        };
        config.validate()?;
        let deadline = Instant::now()
            .checked_add(options.connect_timeout)
            .ok_or(RakNetError::InvalidOption("connect timeout is too large"))?;
        let result = timeout_at(deadline, Self::handshake(peer, options, config))
            .await
            .map_err(|_| RakNetError::ConnectTimeout)?;
        // The engine can observe the shared deadline before Tokio polls its timer.
        if Instant::now() >= deadline
            && matches!(
                &result,
                Err(RakNetError::Handshake(
                    ::raknet::prelude::RakClientError::ConnectionFailed
                ))
            )
        {
            Err(RakNetError::ConnectTimeout)
        } else {
            result
        }
    }

    /// Drives the pinned engine until it transfers the connected protocol state.
    async fn handshake(
        peer: SocketAddr,
        options: RakNetOptions,
        config: RakClientConfig,
    ) -> Result<Self, RakNetError> {
        let peer = canonical_socket_addr(peer);
        let local_ip = if peer.is_ipv6() {
            IpAddr::V6(Ipv6Addr::UNSPECIFIED)
        } else {
            IpAddr::V4(Ipv4Addr::UNSPECIFIED)
        };
        let socket = UdpSocket::bind(SocketAddr::new(local_ip, 0)).await?;
        socket.connect(peer).await?;
        let local = socket.local_addr()?;
        let guid = ClientGuid::generate()?;
        let mut client = RakClient::new(config, endpoint_clock())?
            .connect(peer, local, guid, Instant::now().into_std())
            .map_err(|error| {
                let (_, cause) = error.into_parts();
                RakNetError::Handshake(cause)
            })?;
        let mut buffer = vec![0; UDP_BUFFER_BYTES];
        let mut next_tick = Instant::now();
        let mut initial_read_errors = 0;
        loop {
            while let Some(output) = client.poll() {
                match output {
                    RakClientOutput::MtuProbe { id, datagram, .. } => {
                        let started = Instant::now();
                        let result = socket.send(&datagram).await;
                        let elapsed = started.elapsed();
                        let too_large = result.as_ref().is_err_and(is_mtu_probe_size_error);
                        client.handle(RakClientInput::MtuProbeResult {
                            id,
                            now: Instant::now().into_std(),
                            elapsed,
                            too_large,
                        })?;
                        match result {
                            Ok(sent) if sent != datagram.len() => {
                                return Err(std::io::Error::new(
                                    std::io::ErrorKind::WriteZero,
                                    "partial UDP MTU probe send",
                                )
                                .into());
                            }
                            Err(error) if !too_large => return Err(error.into()),
                            _ => {}
                        }
                    }
                    RakClientOutput::SocketDatagram(datagram, _) => {
                        let sent = socket.send(&datagram).await?;
                        if sent != datagram.len() {
                            return Err(std::io::Error::new(
                                std::io::ErrorKind::WriteZero,
                                "partial UDP handshake send",
                            )
                            .into());
                        }
                    }
                    RakClientOutput::Wait(duration) => {
                        next_tick = Instant::now()
                            .checked_add(duration)
                            .ok_or(RakNetError::InvalidOption("handshake timer is too large"))?;
                    }
                    RakClientOutput::SessionConnected(session) => {
                        return Ok(Self {
                            engine: Box::new(Engine {
                                socket: Some(socket),
                                local,
                                peer,
                                session: Some(SessionSlot::Established(session)),
                                options,
                                incoming: Default::default(),
                                incoming_bytes: 0,
                                pending_datagram: None,
                                receive_buffer: buffer,
                                next_tick: Instant::now(),
                                close_deadline: None,
                                failure: None,
                            }),
                        });
                    }
                    RakClientOutput::SessionClosing(_) => {
                        return Err(RakClientError::ConnectionFailed.into());
                    }
                    RakClientOutput::SessionDatagram(_) | RakClientOutput::Pong { .. } => {}
                }
            }
            let input = tokio::select! {
                received = socket.recv(&mut buffer) => {
                    match received {
                        Ok(length) => RakClientInput::Datagram(buffer[..length].into(), peer, Instant::now().into_std()),
                        Err(error) if client.is_offline_negotiating()
                            && initial_read_errors < MAX_INITIAL_READ_ERRORS
                            && is_transient_udp_read_error(&error) => {
                                initial_read_errors += 1;
                                RakClientInput::Update(Instant::now().into_std())
                            }
                        Err(error) => return Err(error.into()),
                    }
                }
                _ = sleep_until(next_tick) => RakClientInput::Update(Instant::now().into_std()),
            };
            client.handle(input)?;
        }
    }
}
