// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! Typed driver failures that contain no packet or account content.

/// The retained encoded startup prefix exceeded its caller-owned byte limit.
#[derive(Debug, thiserror::Error)]
#[error("deferred packet prefix exceeds its byte limit")]
pub struct DeferredLimit {
    /// Required aggregate encoded bytes, including each original length prefix.
    pub actual: usize,
    /// The caller's original aggregate bound.
    pub maximum: usize,
}
