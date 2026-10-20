// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Bounded raw metadata and decoded-skin JSON without constructing a recursive Value tree.

use super::json_generated::MAX_NESTING_DEPTH;
use serde_json::value::RawValue;

/// Keeps serde's iterative raw parser as the sole JSON grammar owner after bounding its scratch.
pub(super) fn object_or_null(decoded: &[u8]) -> bool {
    let Ok(input) = std::str::from_utf8(decoded) else {
        return false;
    };
    if !within_limits(input, true) {
        return false;
    }
    serde_json::from_str::<&RawValue>(input)
        .is_ok_and(|raw| raw.get() == "null" || raw.get().starts_with('{'))
}

/// Bounds every container, including opaque claims, without interpreting their scalar values.
/// The raw parser remains responsible for JSON grammar and exact value lexemes.
pub(super) fn within_nesting_limit(input: &str) -> bool {
    within_limits(input, false)
}

/// Counts unquoted containers and optionally checks consumed float values before raw parsing.
fn within_limits(input: &str, finite_numbers: bool) -> bool {
    let bytes = input.as_bytes();
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
                if !input[start..index]
                    .parse::<f64>()
                    .is_ok_and(|number| number.is_finite())
                {
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
