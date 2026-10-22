// SPDX-License-Identifier: MIT

//! Compact original raw frames charged to one aggregate startup prefix.

use bedrock_protocol::wire;
use bytes::Bytes;
use std::io;

pub(super) struct DeferredFrames {
    frames: Vec<wire::RawFrame>,
    bytes: usize,
    maximum: usize,
}

use super::super::error::DeferredLimit;

impl DeferredFrames {
    pub(super) fn new(maximum: usize) -> Self {
        Self {
            frames: Vec::new(),
            bytes: 0,
            maximum,
        }
    }
    /// Restores only the length prefix; header high bits and payload bytes remain unchanged.
    pub(super) fn push(&mut self, bytes: Bytes) -> io::Result<()> {
        let mut frame = Vec::new();
        wire::Writer::with_limit(&mut frame, self.maximum)
            .write_len_var_u32(bytes.len())
            .map_err(io::Error::other)?;
        let retained = frame.len().saturating_add(bytes.len());
        let actual = self.bytes.saturating_add(retained);
        if actual > self.maximum {
            return Err(io::Error::other(DeferredLimit {
                actual,
                maximum: self.maximum,
            }));
        }
        frame.extend_from_slice(&bytes);
        let raw = wire::Frames::new(Bytes::from(frame), 1)
            .next()
            .expect("one original packet was framed")
            .map_err(io::Error::other)?;
        self.bytes = actual;
        self.frames.push(raw.compact());
        Ok(())
    }
    pub(super) fn as_slice(&self) -> &[wire::RawFrame] {
        &self.frames
    }
    pub(super) fn take(&mut self) -> Vec<wire::RawFrame> {
        self.bytes = 0;
        std::mem::take(&mut self.frames)
    }
}

/// Shares the original header and body, removing only the already validated frame length.
pub(super) fn encoded(frame: &wire::RawFrame) -> Bytes {
    let entry = frame.frame();
    let mut reader = wire::Reader::from_shared(entry);
    reader.read_var_u32().expect("retained original length");
    entry.slice(reader.position()..)
}
