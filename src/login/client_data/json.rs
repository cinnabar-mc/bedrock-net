// SPDX-License-Identifier: MIT
//! Bounded raw metadata and decoded-skin JSON without constructing a recursive Value tree.

use super::{invalid, json_generated::MAX_NESTING_DEPTH};
use serde::{
    Deserialize, Deserializer,
    de::{IgnoredAny, Visitor},
};
use serde_json::{Value, value::RawValue};
use std::{fmt, io};

/// Projects consumed strings through Go's surrogate replacement without rewriting retained values.
pub(super) fn decode<'de, T: Deserialize<'de>>(raw: &'de RawValue) -> io::Result<T> {
    if raw.get().starts_with('"') {
        let GoString(string) = serde_json::from_str(raw.get()).map_err(|_| invalid())?;
        T::deserialize(Value::String(string)).map_err(|_| invalid())
    } else {
        serde_json::from_str(raw.get()).map_err(|_| invalid())
    }
}

/// A consumed JSON string or object key; serde still owns framing, escapes and surrogate pairing.
pub(super) struct GoString(pub(super) String);

impl<'de> Deserialize<'de> for GoString {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct StringVisitor;
        impl<'de> Visitor<'de> for StringVisitor {
            type Value = GoString;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a JSON string")
            }

            fn visit_bytes<E: serde::de::Error>(self, mut bytes: &[u8]) -> Result<GoString, E> {
                let mut string = String::with_capacity(bytes.len());
                loop {
                    match std::str::from_utf8(bytes) {
                        Ok(text) => {
                            string.push_str(text);
                            return Ok(GoString(string));
                        }
                        Err(error) => {
                            let (valid, rest) = bytes.split_at(error.valid_up_to());
                            string.push_str(
                                std::str::from_utf8(valid)
                                    .map_err(|_| E::custom("invalid JSON string encoding"))?,
                            );
                            // serde's byte decoder emits lone UTF16 surrogates as WTF8 triples.
                            // Go replaces each surrogate, rather than each of its three bytes.
                            if !matches!(rest, [0xed, 0xa0..=0xbf, 0x80..=0xbf, ..]) {
                                return Err(E::custom("invalid JSON string encoding"));
                            }
                            string.push(char::REPLACEMENT_CHARACTER);
                            bytes = &rest[3..];
                        }
                    }
                }
            }
        }
        deserializer.deserialize_bytes(StringVisitor)
    }
}

/// Validates consumed map bytes; ignored strings need no UTF8 representation or value allocation.
/// Serde owns byte grammar, including escapes, after the shared depth/number bound.
pub(super) fn object_or_null(decoded: &[u8]) -> bool {
    let root = decoded
        .iter()
        .copied()
        .find(|byte| !matches!(*byte, b' ' | b'\t' | b'\n' | b'\r'));
    matches!(root, Some(b'{' | b'n'))
        && within_limits(decoded, true)
        && serde_json::from_slice::<IgnoredAny>(decoded).is_ok()
}

/// Bounds every container, including opaque claims, without interpreting their scalar values.
/// The raw parser remains responsible for JSON grammar and exact value lexemes.
pub(super) fn within_nesting_limit(input: &str) -> bool {
    within_limits(input.as_bytes(), false)
}

/// Counts unquoted containers and optionally checks consumed float values before JSON parsing.
fn within_limits(bytes: &[u8], finite_numbers: bool) -> bool {
    let mut index = 0;
    let mut depth = 0usize;
    let mut quoted = false;
    let mut escaped = false;
    while let Some(&byte) = bytes.get(index) {
        index += 1;
        if quoted {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                quoted = false;
            }
            continue;
        }
        match byte {
            b'"' => quoted = true,
            b'[' | b'{' => {
                depth += 1;
                if depth > MAX_NESTING_DEPTH {
                    return false;
                }
            }
            b']' | b'}' => {
                let Some(parent) = depth.checked_sub(1) else {
                    return false;
                };
                depth = parent;
            }
            b'-' | b'0'..=b'9' if finite_numbers => {
                let start = index - 1;
                while bytes.get(index).is_some_and(|byte| {
                    matches!(byte, b'0'..=b'9' | b'.' | b'e' | b'E' | b'+' | b'-')
                }) {
                    index += 1;
                }
                if !std::str::from_utf8(&bytes[start..index]).is_ok_and(|number| {
                    number.parse::<f64>().is_ok_and(|number| number.is_finite())
                }) {
                    return false;
                }
            }
            _ => {}
        }
    }
    true
}

#[cfg(test)]
mod tests;
