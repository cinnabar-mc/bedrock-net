// SPDX-License-Identifier: MIT

//! Read-only original transport estimates, without lifecycle authority.

use std::time::Duration;

/// A copied observation handle; retirement permanently withdraws its estimate.
#[derive(Clone, Debug)]
pub struct RoundTripTime {
    #[cfg(feature = "nethernet")]
    source: nethernet_tokio::RttObservation,
}

impl RoundTripTime {
    /// Returns the latest positive full estimate, or `None` if unmeasured or retired.
    pub fn get(&self) -> Option<Duration> {
        #[cfg(not(feature = "nethernet"))]
        {
            None
        }
        #[cfg(feature = "nethernet")]
        {
            self.source.get()
        }
    }
    #[cfg(feature = "nethernet")]
    pub(super) fn nethernet(source: nethernet_tokio::RttObservation) -> Self {
        Self { source }
    }
}
