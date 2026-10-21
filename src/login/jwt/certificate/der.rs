//! Selective DER checks for interpreted certificate fields; opaque contents are never traversed.

use super::{extensions, names, validity};

/// Reads one definite, minimally encoded, low-tag-number DER element.
pub(super) fn any<'a>(input: &mut &'a [u8]) -> Option<(u8, &'a [u8])> {
    let tag = *input.first()?;
    if tag & 31 == 31 {
        return None;
    }
    let first = *input.get(1)?;
    let (header, length) = if first < 128 {
        (2, usize::from(first))
    } else {
        let count = usize::from(first & 127);
        if count == 0 || count > 4 || *input.get(2)? == 0 {
            return None;
        }
        let mut length = 0usize;
        for byte in input.get(2..2 + count)? {
            length = length.checked_mul(256)?.checked_add(usize::from(*byte))?;
        }
        if length < 128 {
            return None;
        }
        (2 + count, length)
    };
    let end = header.checked_add(length)?;
    if end > u32::MAX as usize {
        return None;
    }
    let data = input.get(header..end)?;
    *input = input.get(end..)?;
    Some((tag, data))
}

/// Reads a required tag without validating the contents of an opaque element.
pub(super) fn take<'a>(input: &mut &'a [u8], tag: u8) -> Option<&'a [u8]> {
    let (actual, data) = any(input)?;
    (actual == tag).then_some(data)
}

/// Checks canonical signed INTEGER contents, including empty and redundant-sign encodings.
pub(super) fn integer(data: &[u8]) -> Option<&[u8]> {
    let first = *data.first()?;
    if data.len() > 1 && ((first == 0 && data[1] < 128) || (first == 255 && data[1] >= 128)) {
        return None;
    }
    Some(data)
}

/// Decodes the signed 64-bit range used by interpreted policy values.
pub(super) fn signed(data: &[u8]) -> Option<i64> {
    let data = integer(data)?;
    if data.len() > 8 {
        return None;
    }
    let mut bytes = [if data[0] >= 128 { 255 } else { 0 }; 8];
    bytes[8 - data.len()..].copy_from_slice(data);
    Some(i64::from_be_bytes(bytes))
}

/// Requires DER Boolean encodings rather than treating every nonzero byte as true.
pub(super) fn boolean(data: &[u8]) -> Option<bool> {
    match data {
        [0] => Some(false),
        [255] => Some(true),
        _ => None,
    }
}

/// Validates OID subidentifiers, optionally enforcing Go's decoded int32 component range.
pub(super) fn oid(data: &[u8], bounded: bool) -> Option<()> {
    if data.is_empty() || data.last()? & 128 != 0 {
        return None;
    }
    let mut start = true;
    let mut value = 0u64;
    for &byte in data {
        if start && byte == 128 {
            return None;
        }
        if bounded {
            value = value.checked_mul(128)?.checked_add(u64::from(byte & 127))?;
            if value > i32::MAX as u64 {
                return None;
            }
        }
        start = byte < 128;
        if start {
            value = 0;
        }
    }
    Some(())
}

/// Checks BIT STRING padding without interpreting key-usage bits or requiring a signature.
pub(super) fn bits(data: &[u8]) -> Option<()> {
    let (&unused, value) = data.split_first()?;
    if unused > 7
        || (value.is_empty() && unused != 0)
        || value.last().is_some_and(|b| b & ((1u8 << unused) - 1) != 0)
    {
        return None;
    }
    Some(())
}

/// Borrows a required element including its original tag and length octets.
pub(super) fn element<'a>(input: &mut &'a [u8], tag: u8) -> Option<&'a [u8]> {
    let original = *input;
    take(input, tag)?;
    Some(&original[..original.len() - input.len()])
}

/// Reads an algorithm OID and its first opaque parameter, ignoring later fields.
pub(super) fn algorithm(mut data: &[u8]) -> Option<(&[u8], &[u8])> {
    let id = take(&mut data, 6)?;
    oid(id, true)?;
    let parameters = data;
    if !data.is_empty() {
        any(&mut data)?;
    }
    Some((id, &parameters[..parameters.len() - data.len()]))
}

/// Validates the fields consumed by the certificate owner and borrows the original SPKI element.
pub(super) fn certificate(bytes: &[u8]) -> Option<&[u8]> {
    let mut input = bytes;
    let mut outer = take(&mut input, 0x30)?;
    if !input.is_empty() {
        return None;
    }
    let mut tbs = take(&mut outer, 0x30)?;
    let mut version = 0;
    if tbs.first() == Some(&0xa0) {
        let mut field = take(&mut tbs, 0xa0)?;
        version = signed(take(&mut field, 2)?)?;
        if !field.is_empty() || version < 0 {
            return None;
        }
    }
    // Go increments its signed version before comparing it with three.
    version = version.wrapping_add(1);
    if version > 3 || integer(take(&mut tbs, 2)?)?[0] >= 128 {
        return None;
    }
    let signature = take(&mut tbs, 0x30)?;
    if signature != take(&mut outer, 0x30)? {
        return None;
    }
    algorithm(signature)?;
    names::distinguished(take(&mut tbs, 0x30)?)?;
    validity::valid(take(&mut tbs, 0x30)?)?;
    names::distinguished(take(&mut tbs, 0x30)?)?;
    let spki = element(&mut tbs, 0x30)?;
    if version > 1 {
        for tag in [0x81, 0x82] {
            if tbs.first() == Some(&tag) {
                take(&mut tbs, tag)?;
            }
        }
    }
    if version == 3 && tbs.first() == Some(&0xa3) {
        let mut field = take(&mut tbs, 0xa3)?;
        let mut records = take(&mut field, 0x30)?;
        let mut seen = std::collections::BTreeSet::new();
        while !records.is_empty() {
            let mut record = take(&mut records, 0x30)?;
            let id = take(&mut record, 6)?;
            oid(id, true)?;
            if !seen.insert(id) {
                return None;
            }
            let critical = if record.first() == Some(&1) {
                boolean(take(&mut record, 1)?)?
            } else {
                false
            };
            extensions::valid(id, critical, take(&mut record, 4)?)?;
        }
    }
    bits(take(&mut outer, 3)?)?;
    Some(spki)
}
