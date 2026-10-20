// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

#![doc = include_str!("../README.md")]

use bytes::Bytes;
use std::io;

#[cfg(any(feature = "raknet", feature = "nethernet"))]
pub mod connection;
pub mod error;
#[cfg(any(feature = "raknet", feature = "nethernet"))]
pub mod handshake;
#[cfg(any(feature = "raknet", feature = "nethernet"))]
pub mod packs;
pub mod rtt;
#[cfg(any(feature = "raknet", feature = "nethernet"))]
pub mod transport;
use rtt::RoundTripTime;

/// Exclusive packet I/O consumed by a caller's session pump.
pub trait PacketIo: Send + 'static {
    /// Observes the original transport without retaining its lifecycle capability.
    fn observe_rtt(&self) -> Option<RoundTripTime> {
        None
    }
    /// Sends one complete batch without cancelling cipher or transport progress.
    fn send_body(
        &mut self,
        body: Bytes,
    ) -> impl std::future::Future<Output = io::Result<()>> + Send;
    /// Retains partial input when its caller cancels a receive wait.
    fn recv_body(&mut self) -> impl std::future::Future<Output = io::Result<Bytes>> + Send;
    /// Progresses control work while accepted payloads remain staged for ordinary reads.
    fn maintain(&mut self) -> impl std::future::Future<Output = ()> + Send {
        std::future::pending()
    }
    /// Flushes accepted output and ends the original connection.
    fn close(&mut self) -> impl std::future::Future<Output = io::Result<()>> + Send;
}
