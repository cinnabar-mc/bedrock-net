use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use ::raknet::prelude::{
    RakClient, RakClientConfig, RakClientInput, RakClientOutput, RakSessionConfig, Sans,
};
use tokio::net::UdpSocket;
use tokio::time::{Instant, sleep_until, timeout_at};

use super::{RakNetConnection, RakNetError, RakNetOptions, UDP_BUFFER_BYTES};

impl RakNetConnection {
    /// Completes a transport handshake, spawning no background tasks.
    ///
    /// Uses an ephemeral local port of the peer's address family. Cancelling the
    /// future closes the socket and drops all partial handshake state.
    ///
    /// # Errors
    /// Returns invalid option, socket, handshake or overall timeout errors.
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
        let deadline = Instant::now()
            .checked_add(options.connect_timeout)
            .ok_or(RakNetError::InvalidOption("connect timeout is too large"))?;
        timeout_at(deadline, Self::dial(peer, options))
            .await
            .map_err(|_| RakNetError::ConnectTimeout)?
    }

    /// Drives the pinned engine until it transfers the connected protocol state.
    async fn dial(peer: SocketAddr, options: RakNetOptions) -> Result<Self, RakNetError> {
        let local_ip = if peer.is_ipv6() {
            IpAddr::V6(Ipv6Addr::UNSPECIFIED)
        } else {
            IpAddr::V4(Ipv4Addr::UNSPECIFIED)
        };
        let socket = UdpSocket::bind(SocketAddr::new(local_ip, 0)).await?;
        socket.connect(peer).await?;
        let local = socket.local_addr()?;
        let mut client = RakClient::new(RakClientConfig {
            conn_attempt_timeout: options.connect_timeout,
            ..RakClientConfig::default()
        });
        client.handle(RakClientInput::Connect(peer, std::time::SystemTime::now()))?;
        let mut buffer = vec![0; UDP_BUFFER_BYTES];
        let mut next_tick = Instant::now();
        loop {
            while let Some(output) = client.poll() {
                match output {
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
                            socket: Some(socket),
                            local,
                            peer,
                            session: Some(session),
                            options,
                            incoming: Default::default(),
                            incoming_bytes: 0,
                            pending_datagram: None,
                            receive_buffer: buffer,
                            next_tick: Instant::now(),
                            close_deadline: None,
                            failure: None,
                        });
                    }
                    RakClientOutput::SessionDatagram(_) | RakClientOutput::Pong(..) => {}
                }
            }
            let input = tokio::select! {
                received = socket.recv(&mut buffer) => {
                    let length = received?;
                    RakClientInput::Datagram(buffer[..length].into(), peer, std::time::SystemTime::now())
                }
                _ = sleep_until(next_tick) => RakClientInput::Update(std::time::SystemTime::now()),
            };
            client.handle(input)?;
        }
    }
}
