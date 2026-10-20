// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! Weak observations of actual received allocations for integration fixtures.

use bytes::Bytes;
/// Weak observations of actual socket input allocations; never retains the bytes being measured.
#[cfg(any(test, feature = "test-support"))]
pub type BatchLifetimes = std::sync::Arc<std::sync::Mutex<Vec<(usize, std::sync::Weak<()>)>>>;

#[cfg(any(test, feature = "test-support"))]
tokio::task_local! {
    /// Scopes existing weak batch observations to an actual public connection future.
    pub static OBSERVE_BATCHES: BatchLifetimes;
}

/// Field order releases the real input allocation before its observation becomes expired.
#[cfg(any(test, feature = "test-support"))]
pub(super) struct ObservedBatch {
    pub(super) bytes: Bytes,
    pub(super) _lifetime: std::sync::Arc<()>,
}

#[cfg(any(test, feature = "test-support"))]
impl AsRef<[u8]> for ObservedBatch {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}
