// SPDX-License-Identifier: MIT

//! Read-only original transport estimates, without lifecycle authority.

use std::time::Duration;

/// A copied observation handle; retirement permanently withdraws its estimate.
#[derive(Clone, Debug)]
pub struct RoundTripTime {
    #[cfg(any(feature = "raknet", feature = "nethernet"))]
    source: Source,
}

#[cfg(any(feature = "raknet", feature = "nethernet"))]
#[derive(Clone, Debug)]
enum Source {
    #[cfg(feature = "raknet")]
    RakNet(bedrock_net::raknet::RttObservation),
    #[cfg(feature = "nethernet")]
    NetherNet(nethernet_tokio::RttObservation),
}

impl RoundTripTime {
    /// Returns the latest positive full estimate, or `None` if unmeasured or retired.
    pub fn get(&self) -> Option<Duration> {
        #[cfg(not(any(feature = "raknet", feature = "nethernet")))]
        {
            None
        }
        #[cfg(any(feature = "raknet", feature = "nethernet"))]
        match &self.source {
            #[cfg(feature = "raknet")]
            Source::RakNet(source) => source.get(),
            #[cfg(feature = "nethernet")]
            Source::NetherNet(source) => source.get(),
        }
    }
    #[cfg(feature = "raknet")]
    pub(super) fn raknet(source: bedrock_net::raknet::RttObservation) -> Self {
        Self {
            source: Source::RakNet(source),
        }
    }
    #[cfg(feature = "nethernet")]
    pub(super) fn nethernet(source: nethernet_tokio::RttObservation) -> Self {
        Self {
            source: Source::NetherNet(source),
        }
    }
}
