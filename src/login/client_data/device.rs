//! Explicit, reusable device claims applied before Login signing.

use super::{RawClientData, schema_generated};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::io;

/// Caller-supplied hardware metadata; keep the ID stable across joins from the same installation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DeviceProfile {
    /// Numeric Login device OS, including unknown values supplied by the caller.
    pub os: i64,
    /// Hardware model reported by the caller.
    pub model: String,
    /// Stable device identifier reported by the caller.
    pub id: String,
}

impl DeviceProfile {
    /// Applies device/default-input claims, defaulting Android's zero platform category to mobile.
    /// Preserves current input, explicit nonzero platform categories and unrelated raw claims.
    pub fn apply(&self, data: &mut RawClientData) -> io::Result<()> {
        if self.os == 1 && data.integer("PlatformType")?.unwrap_or(0) == 0 {
            data.insert_ordered("PlatformType", json!(1))?;
        }
        data.insert_ordered("DefaultInputMode", json!(default_input_mode(self.os)))?;
        data.insert_ordered("DeviceId", json!(self.id))?;
        data.insert_ordered("DeviceModel", json!(self.model))?;
        data.insert_ordered("DeviceOS", json!(self.os))
    }
}

/// Returns the OS's default input mode, using the generated defaults from the pinned Go owner.
pub fn default_input_mode(os: i64) -> i64 {
    schema_generated::device_input_mode(os)
}
