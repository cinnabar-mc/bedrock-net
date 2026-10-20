//! Caller-driven Player Messaging for an existing bounded NetherNet listener.
//!
//! The application acquires the protected SDK socket and supplies signed answer identity,
//! offer trust, and any accepting ICE endpoints through `ConnectionConfig`. This adapter
//! neither publishes a world nor authorizes Minecraft Login. Continue polling `accept` or
//! `maintain` while accepted peers are in use. No task or runtime is added by this adapter;
//! the existing NetherNet listener retains its own bounded transport workers.
//!
//! STUN/TURN acquisition and renewal remain caller policy. Supplied `ServerIceConfig`
//! keeps its original credential expirations: the transport checks them for each new
//! offer. Updating ICE never renews an already admitted peer's allocation.

use super::{Error, TurnRefresh, driver::Driver};
use bedrock_services::signaling::{TurnCredentials, websocket::MessagingSocket};
use futures::future::pending;
use nethernet::identity::{SdpIdentity, TokenTrust};
use nethernet_tokio::{
    AcceptedSession, CallerServerSignaling, CallerServerSignalingConfig, ConnectionConfig,
    NetherServer, ServerIceConfig,
};
use std::{sync::Arc, time::Instant};

/// A protected service socket before accepting transport admission exists.
/// The network ID must be the exact value supplied at the socket's original upgrade.
#[must_use]
pub struct PreparedMessagingServer {
    socket: MessagingSocket,
    local_network_id: u64,
}

impl PreparedMessagingServer {
    /// Moves an already upgraded SDK socket into one exclusive accepting setup owner.
    pub fn new(socket: MessagingSocket, local_network_id: u64) -> Self {
        Self {
            socket,
            local_network_id,
        }
    }

    /// Binds the existing bounded listener with explicit signaling and transport limits.
    ///
    /// Signed answers and an explicit offer trust policy are required. The application
    /// remains responsible for authenticating Login and admitting the selected world.
    /// Caller-supplied ICE credentials retain their original absolute lifetime. Setup
    /// cancellation drops this socket and any listener created by this future.
    ///
    /// # Errors
    /// Returns configuration, elapsed original deadline or listener startup failures.
    pub async fn bind(
        self,
        config: ConnectionConfig,
        signaling: CallerServerSignalingConfig,
        deadline: Instant,
    ) -> Result<MessagingServer, Error> {
        if Instant::now() >= deadline {
            return Err(Error::TimedOut);
        }
        if self.socket.legacy_network_id().is_some()
            || config.identity.is_none()
            || config.token_trust.is_none()
            || config.allow_unsigned_answers
        {
            return Err(Error::Configuration);
        }
        if config.cancel_token.is_cancelled() {
            return Err(Error::Closed);
        }
        let cancellation = config.cancel_token.clone().cancelled_owned();
        let (caller, caller_driver) =
            CallerServerSignaling::new(self.local_network_id.to_string(), signaling)
                .map_err(|_| Error::Configuration)?;
        let server = NetherServer::bind_with(caller, config)
            .await
            .map_err(|_| Error::Transport)?;
        if Instant::now() >= deadline {
            drop(server);
            return Err(Error::TimedOut);
        }
        Ok(MessagingServer {
            server: Box::new(server),
            driver: Driver::server(
                self.socket,
                caller_driver,
                signaling.signaling.send_timeout,
                cancellation,
            ),
            local_network_id: self.local_network_id,
        })
    }
}

/// One actual listener and its exclusive caller-polled protected signaling owner.
/// Construction is available only through `PreparedMessagingServer::bind`.
#[must_use = "drive accepting signaling and explicitly close the listener"]
pub struct MessagingServer {
    server: Box<NetherServer>,
    driver: Driver,
    local_network_id: u64,
}

impl MessagingServer {
    /// Returns the original upgrade's transport ID for application-owned route metadata.
    /// This value alone proves neither a published activity nor game Login authority.
    pub fn local_network_id(&self) -> u64 {
        self.local_network_id
    }

    /// Waits for an actual established transport while driving service receipts and controls.
    /// Cancellation preserves this owner, partial socket frames and original pending routes.
    /// A transport transferred in the same turn as a service failure is returned once;
    /// subsequent calls report that first service failure. Its accepted FIFO stays owned
    /// by the returned session even if signaling then retires.
    ///
    /// # Errors
    /// Returns the first signaling/service failure or listener retirement.
    pub async fn accept(&mut self) -> Result<AcceptedSession, Error> {
        let accepted = self.driver.run(self.server.accept()).await?;
        match accepted {
            Ok(accepted) => Ok(accepted),
            Err(_) => {
                self.driver.close();
                Err(Error::Transport)
            }
        }
    }

    /// Drives service heartbeats, late signals and receipts beside application peer I/O.
    /// Does not consume an accepted game message or start an application task.
    ///
    /// # Errors
    /// Completes only when the retained service driver fails or closes.
    pub async fn maintain(&mut self) -> Result<(), Error> {
        self.driver.run(pending::<()>()).await
    }

    /// Admits one fresh TURN request on this server's original JSON-RPC service socket.
    /// No request is retried automatically. Finish or cancel the receipt, or close this server before
    /// requesting another refresh; a canceled finish wait keeps the original request owned.
    ///
    /// # Errors
    /// Refuses an elapsed deadline, closed service, existing refresh or unavailable local capacity.
    pub fn begin_turn_refresh(&mut self, deadline: Instant) -> Result<TurnRefresh, Error> {
        self.driver.begin_turn_refresh(deadline)
    }

    /// Drives the original request while signaling, heartbeats and receipts continue progressing.
    /// Returns the actual zeroizing SDK credential owner once, with its receipt-anchored expiry.
    /// Cancellation preserves partial writes, the original deadline and any completed result.
    /// The caller resolves and installs these endpoints explicitly; this does not update ICE
    /// or renew an already admitted peer. A receipt from another server is refused before I/O.
    ///
    /// # Errors
    /// Returns wrong/consumed receipt, original deadline, correlated service response or driver errors.
    pub async fn finish_turn_refresh(
        &mut self,
        receipt: &TurnRefresh,
    ) -> Result<TurnCredentials, Error> {
        self.driver.finish_turn_refresh(receipt).await
    }

    /// Retires this server's exact refresh request and immediately drops its owned result.
    /// An unsent frame is removed; an admitted partial write stays owned and may reach the
    /// service. Late responses are ignored. This performs no I/O, retry or remote acknowledgment.
    /// Other cached credentials, signaling routes and the original service error stay unchanged.
    ///
    /// # Errors
    /// Rejects a wrong, consumed or already canceled receipt before any state mutation.
    pub fn cancel_turn_refresh(&mut self, receipt: &TurnRefresh) -> Result<(), Error> {
        self.driver.cancel_turn_refresh(receipt)
    }

    /// Supplies the caller's freshly qualified answer identity for later offers on this listener.
    /// Pending and accepted peers retain their original signer and transport lifetimes.
    /// This performs no mint, signaling refresh or change to offer trust.
    pub fn set_identity(&self, identity: Arc<dyn SdpIdentity>) {
        self.server.set_identity(identity);
    }

    /// Supplies explicit caller-qualified trust for later offers on this same listener.
    /// Present identities keep their original token and fingerprint verification requirements.
    /// This does not replace answer identity or authenticate Minecraft Login.
    pub fn set_token_trust(&self, trust: TokenTrust) {
        self.server.set_token_trust(Some(trust));
    }

    /// Supplies freshly acquired caller-owned ICE configuration for later offers only.
    /// This forwards original absolute credential lifetimes without extending them.
    pub fn set_server_ice(&self, ice: Option<ServerIceConfig>) {
        self.server.set_server_ice(ice);
    }

    /// Consumes accepting capability and synchronously closes the original service routes.
    /// Retains the same service socket for its bounded close handshake. Existing accepted
    /// session receivers remain with their callers; no queue is moved here.
    ///
    /// ```compile_fail
    /// fn accept_after_close(server: bedrock_net::messaging::server::MessagingServer) {
    ///     let mut closing = server.begin_close();
    ///     let _ = closing.accept();
    /// }
    /// ```
    pub fn begin_close(mut self) -> ClosingMessagingServer {
        self.driver.begin_close();
        ClosingMessagingServer {
            server: self.server,
            driver: Box::new(self.driver),
            service: None,
            joined: false,
        }
    }
}

/// Local accepting permission ended; the original service close and listener join remain owned.
#[must_use = "finish retiring the original listener or explicitly drop it"]
pub struct ClosingMessagingServer {
    server: Box<NetherServer>,
    driver: Box<Driver>,
    service: Option<Result<(), Error>>,
    joined: bool,
}

impl ClosingMessagingServer {
    /// Drives the original bounded service close and joins the listener and its unaccepted workers.
    /// Cancellation retains both operations, their completed results and the first close cutoff.
    /// Previously returned session receivers and their accepted data remain caller-owned.
    ///
    /// # Errors
    /// Returns the first service failure or listener retirement failure after attempting both owners.
    pub async fn finish_close(&mut self) -> Result<(), Error> {
        let Self {
            server,
            driver,
            service,
            joined,
        } = self;
        let (service, listener) = tokio::join!(
            async {
                if service.is_none() {
                    *service = Some(driver.finish_close().await);
                }
                service.clone().expect("completed original service close")
            },
            async {
                if !*joined {
                    server.close().await.map_err(|_| Error::Transport)?;
                    *joined = true;
                }
                Ok(())
            },
        );
        service.and(listener)
    }

    /// Consumes this owner only after the service socket retired and listener join completed.
    /// Retirement does not change an error previously reported by `finish_close` into success.
    pub fn try_finish(self) -> Result<ClosedMessagingServer, Self> {
        if self.service.is_some() && self.joined {
            Ok(ClosedMessagingServer { _private: () })
        } else {
            Err(self)
        }
    }
}

/// The original accepting service and listener retired, without transport capability.
pub struct ClosedMessagingServer {
    _private: (),
}

#[cfg(test)]
mod tests;
