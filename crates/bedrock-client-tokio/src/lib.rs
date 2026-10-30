// SPDX-License-Identifier: MIT

#![doc = include_str!("../README.md")]

use bytes::Bytes;
use std::io;

#[cfg(feature = "nethernet")]
pub mod connect;
#[cfg(feature = "nethernet")]
pub mod connection;
pub mod error;
#[cfg(feature = "nethernet")]
pub mod handshake;
#[cfg(feature = "nethernet")]
pub mod packs;
pub mod rtt;
#[cfg(feature = "nethernet")]
pub mod server;
#[cfg(feature = "nethernet")]
pub mod transport;
use rtt::RoundTripTime;

/// Batch I/O for an application's session loop.
///
/// Implement this trait to use another transport with that loop. Each body is one
/// complete batch; implementations retain partial receive progress across canceled
/// waits. The application supplies the runtime and closing deadline.
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
    /// Finalizes teardown after the caller has finished consuming transport input.
    /// Implementors with distinct close-request and drain lifetimes override this hook.
    /// The default preserves the existing close behavior and the caller owns its deadline.
    fn finish_close(&mut self) -> impl std::future::Future<Output = io::Result<()>> + Send {
        self.close()
    }
}
