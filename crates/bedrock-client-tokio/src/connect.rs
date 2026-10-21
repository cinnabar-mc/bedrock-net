// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! Concrete setup over explicit candidates and caller-prepared admission/configuration.

#[cfg(feature = "nethernet")]
pub mod http;
#[cfg(feature = "nethernet")]
pub mod lan;
#[cfg(feature = "raknet")]
pub mod raknet;

use futures::{StreamExt, stream::FuturesUnordered};
use std::{collections::HashSet, future::Future, io, net::SocketAddr, time::Instant};

/// Connects only explicit compatible addresses, optionally racing independent owners.
/// Serial attempts drop the completed future before allocating its alternative.
async fn resolved<T, R>(
    addresses: impl Iterator<Item = SocketAddr>,
    ipv4_only: bool,
    parallel: bool,
    deadline: tokio::time::Instant,
    mut connect: impl FnMut(SocketAddr) -> T,
) -> io::Result<R>
where
    T: Future<Output = io::Result<R>>,
{
    before_deadline(deadline, async {
        let mut candidates = FuturesUnordered::new();
        let mut seen = HashSet::new();
        let mut addresses = addresses.filter(|address| {
            address.port() != 0 && (!ipv4_only || address.is_ipv4()) && seen.insert(*address)
        });
        let mut failure = io::Error::new(
            io::ErrorKind::AddrNotAvailable,
            "native endpoint has no compatible resolved address",
        );
        loop {
            for address in addresses.by_ref() {
                candidates.push(connect(address));
                if !parallel {
                    break;
                }
            }
            let Some(result) = candidates.next().await else {
                break;
            };
            match result {
                Ok(transport) => return Ok(transport),
                Err(error) => failure = error,
            }
        }
        Err(failure)
    })
    .await
}

/// Keeps a ready result at the original cutoff from escaping with a new owner.
async fn before_deadline<T>(
    deadline: tokio::time::Instant,
    operation: impl Future<Output = io::Result<T>>,
) -> io::Result<T> {
    check(deadline, None)?;
    let result = tokio::time::timeout_at(deadline, operation)
        .await
        .map_err(|_| timed_out())?;
    check(deadline, None)?;
    result
}

/// Credential expiry retains its typed authentication cause even at a simultaneous timeout.
fn check(deadline: tokio::time::Instant, expires: Option<Instant>) -> io::Result<()> {
    if expires.is_some_and(|expires| Instant::now() >= expires) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            crate::transport::ExpiredAdmission,
        ));
    }
    if tokio::time::Instant::now() >= deadline {
        return Err(timed_out());
    }
    Ok(())
}

/// Keeps endpoint and proof values out of finite setup failures.
fn timed_out() -> io::Error {
    io::Error::new(io::ErrorKind::TimedOut, "native join timed out")
}

#[cfg(all(test, feature = "raknet", feature = "nethernet"))]
mod tests;
