//! Admission semantics for the extensions interpreted by Go's certificate decoder.

use super::{der, names};
use std::collections::BTreeSet;

/// Interprets only known extension values; unknown critical or malformed opaque values stay opaque.
pub(super) fn valid(oid: &[u8], critical: bool, value: &[u8]) -> Option<()> {
    let mut data = value;
    match oid {
        b"\x55\x1d\x0e" => {
            if critical {
                return None;
            }
            der::take(&mut data, 4)?;
        }
        b"\x55\x1d\x0f" => der::bits(der::take(&mut data, 3)?)?,
        b"\x55\x1d\x11" => names::san(value)?,
        b"\x55\x1d\x13" => {
            let mut sequence = der::take(&mut data, 0x30)?;
            if sequence.first() == Some(&1) {
                der::boolean(der::take(&mut sequence, 1)?)?;
            }
            if sequence.first() == Some(&2) {
                let path = der::signed(der::take(&mut sequence, 2)?)?;
                if path < 0 {
                    return None;
                }
            }
        }
        b"\x55\x1d\x1e" => names::constraints(value)?,
        b"\x55\x1d\x1f" => distribution_points(value)?,
        b"\x55\x1d\x20" => {
            let mut policies = der::take(&mut data, 0x30)?;
            let mut seen = BTreeSet::new();
            while !policies.is_empty() {
                let mut policy = der::take(&mut policies, 0x30)?;
                let oid = der::take(&mut policy, 6)?;
                der::oid(oid, false)?;
                if !seen.insert(oid) {
                    return None;
                }
            }
        }
        b"\x55\x1d\x21" => {
            let mut mappings = der::take(&mut data, 0x30)?;
            while !mappings.is_empty() {
                let mut pair = der::take(&mut mappings, 0x30)?;
                // This owner retains raw OID contents instead of decoding their components.
                der::take(&mut pair, 6)?;
                der::take(&mut pair, 6)?;
            }
        }
        b"\x55\x1d\x23" => {
            if critical {
                return None;
            }
            let mut sequence = der::take(&mut data, 0x30)?;
            if sequence.first() == Some(&0x80) {
                der::take(&mut sequence, 0x80)?;
            }
        }
        b"\x55\x1d\x24" => {
            let mut sequence = der::take(&mut data, 0x30)?;
            for tag in [0x80, 0x81] {
                if sequence.first() == Some(&tag) {
                    der::signed(der::take(&mut sequence, tag)?)?;
                }
            }
        }
        b"\x55\x1d\x25" => {
            let mut usages = der::take(&mut data, 0x30)?;
            while !usages.is_empty() {
                der::oid(der::take(&mut usages, 6)?, true)?;
            }
        }
        b"\x55\x1d\x36" => {
            der::signed(der::take(&mut data, 2)?)?;
        }
        b"\x2b\x06\x01\x05\x05\x07\x01\x01" => {
            if critical {
                return None;
            }
            let mut descriptions = der::take(&mut data, 0x30)?;
            while !descriptions.is_empty() {
                let mut description = der::take(&mut descriptions, 0x30)?;
                der::oid(der::take(&mut description, 6)?, true)?;
                if description.first() == Some(&0x86) {
                    der::take(&mut description, 0x86)?;
                }
            }
        }
        _ => {}
    }
    Some(())
}

/// Reads the distribution-point locations selected by the decoder, leaving other fields uninterpreted.
fn distribution_points(value: &[u8]) -> Option<()> {
    let mut data = value;
    let mut points = der::take(&mut data, 0x30)?;
    while !points.is_empty() {
        let mut point = der::take(&mut points, 0x30)?;
        if point.first() != Some(&0xa0) {
            continue;
        }
        let mut name = der::take(&mut point, 0xa0)?;
        let mut full = der::take(&mut name, 0xa0)?;
        while full.first() == Some(&0x86) {
            der::take(&mut full, 0x86)?;
        }
    }
    Some(())
}
