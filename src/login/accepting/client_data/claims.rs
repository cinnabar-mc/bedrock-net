//! Ordered struct decoding and generic JSON checks for client-signed claims.

use serde::de::{MapAccess, Visitor};
use serde::{Deserialize, Deserializer};
use serde_json::{Value, value::RawValue};
use std::{borrow::Cow, collections::BTreeMap, fmt};

#[derive(Clone, Copy)]
pub(super) struct Schema {
    pub(super) strings: &'static [&'static str],
    pub(super) integers: &'static [&'static str],
    pub(super) booleans: &'static [&'static str],
    pub(super) arrays: &'static [&'static str],
    pub(super) key_update: bool,
    pub(super) floats: &'static [&'static str],
}

#[derive(Default)]
pub(super) struct Claims {
    key_update: Option<Box<RawValue>>,
    scalars: BTreeMap<&'static str, Value>,
    arrays: BTreeMap<&'static str, Slice>,
}

#[derive(Default)]
struct Slice {
    backing: Vec<Claims>,
    length: usize,
}

struct Members(Vec<(String, Box<RawValue>)>);

impl<'de> Deserialize<'de> for Members {
    /// Retains member order and raw values instead of sorting or collapsing aliases.
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Fields;
        impl<'de> Visitor<'de> for Fields {
            type Value = Members;
            /// Describes the expected JSON shape without exposing peer data.
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a client metadata object")
            }
            /// Collects each occurrence so earlier type errors cannot be overwritten.
            fn visit_map<M: MapAccess<'de>>(self, mut map: M) -> Result<Members, M::Error> {
                let mut members = Vec::new();
                while let Some(name) = map.next_key()? {
                    members.push((name, map.next_value()?));
                }
                Ok(Members(members))
            }
        }
        deserializer.deserialize_map(Fields)
    }
}

impl Claims {
    /// Applies Go struct null and slice-reuse rules before final semantic validation.
    pub(super) fn merge(&mut self, raw: &str, schema: Schema) -> Option<()> {
        if raw == "null" {
            return Some(());
        }
        let Members(members) = serde_json::from_str(raw).ok()?;
        for (key, raw) in members {
            if schema.key_update && key == "identityPublicKey" {
                self.key_update = Some(raw);
                continue;
            }
            let Some(&name) = schema
                .strings
                .iter()
                .chain(schema.integers)
                .chain(schema.booleans)
                .chain(schema.arrays)
                .chain(schema.floats)
                .find(|name| super::super::fields::matches_field(&key, name))
            else {
                continue;
            };
            let raw = raw.get();
            if schema.arrays.contains(&name) {
                if name == "Colors" {
                    if raw != "null" {
                        let colors: Vec<Box<RawValue>> = serde_json::from_str(raw).ok()?;
                        for color in colors.iter().take(4) {
                            if color.get() != "null" {
                                serde_json::from_str::<String>(color.get()).ok()?;
                            }
                        }
                    }
                    continue;
                }
                let slice = self.arrays.entry(name).or_default();
                if raw == "null" {
                    *slice = Slice::default();
                    continue;
                }
                let elements: Vec<Box<RawValue>> = serde_json::from_str(raw).ok()?;
                if elements.is_empty() {
                    *slice = Slice::default();
                    continue;
                }
                slice.length = elements.len();
                slice
                    .backing
                    .resize_with(slice.backing.len().max(elements.len()), Claims::default);
                for (entry, raw) in slice.backing.iter_mut().zip(elements) {
                    entry.merge(raw.get(), super::array_schema(name))?;
                }
            } else if raw != "null" {
                let value = if schema.strings.contains(&name) {
                    Value::String(serde_json::from_str(raw).ok()?)
                } else if schema.integers.contains(&name) {
                    Value::Number(raw.parse::<i64>().ok()?.into())
                } else if schema.booleans.contains(&name) {
                    Value::Bool(serde_json::from_str(raw).ok()?)
                } else {
                    Value::Number(serde_json::Number::from_f64(raw.parse::<f64>().ok()?)?)
                };
                self.scalars.insert(name, value);
            }
        }
        Some(())
    }

    /// Borrows the exact generic-map key update, including a present null or wrong type.
    pub(super) fn key_update(&self) -> Option<&RawValue> {
        self.key_update.as_deref()
    }

    /// Borrows the last non-null string, or the absent field's empty default.
    pub(super) fn text(&self, name: &str) -> &str {
        self.scalars
            .get(name)
            .and_then(Value::as_str)
            .unwrap_or_default()
    }

    /// Returns the last non-null integer, or the absent field's zero default.
    pub(super) fn number(&self, name: &str) -> i64 {
        self.scalars
            .get(name)
            .and_then(Value::as_i64)
            .unwrap_or_default()
    }

    /// Borrows only active slice elements while retaining truncated elements for later aliases.
    pub(super) fn entries(&self, name: &str) -> &[Self] {
        self.arrays
            .get(name)
            .map_or(&[], |slice| &slice.backing[..slice.length])
    }
}

/// Replaces unmatched escaped UTF-16 surrogates for interpretation, retaining signed JSON separately.
pub(super) fn normalize(raw: &str) -> Option<Cow<'_, str>> {
    if !raw.contains("\\u") {
        return Some(Cow::Borrowed(raw));
    }
    let bytes = raw.as_bytes();
    let mut normalized = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] != b'\\' {
            normalized.push(bytes[index]);
            index += 1;
            continue;
        }
        if bytes.get(index + 1) != Some(&b'u') {
            normalized.extend_from_slice(bytes.get(index..index + 2)?);
            index += 2;
            continue;
        }
        let unit = u16::from_str_radix(
            std::str::from_utf8(bytes.get(index + 2..index + 6)?).ok()?,
            16,
        )
        .ok()?;
        if (0xd800..=0xdbff).contains(&unit) && bytes.get(index + 6..index + 8) == Some(b"\\u") {
            let next = u16::from_str_radix(
                std::str::from_utf8(bytes.get(index + 8..index + 12)?).ok()?,
                16,
            )
            .ok()?;
            if (0xdc00..=0xdfff).contains(&next) {
                normalized.extend_from_slice(&bytes[index..index + 12]);
                index += 12;
                continue;
            }
        }
        if (0xd800..=0xdfff).contains(&unit) {
            normalized.extend_from_slice(b"\\ufffd");
        } else {
            normalized.extend_from_slice(&bytes[index..index + 6]);
        }
        index += 6;
    }
    if normalized == bytes {
        Some(Cow::Borrowed(raw))
    } else {
        String::from_utf8(normalized).ok().map(Cow::Owned)
    }
}

/// Checks float64 numbers, decoded-key uniqueness and Go's depth limit without recursive values.
pub(super) fn json_values(raw: &RawValue, reject_duplicates: bool) -> bool {
    use std::collections::BTreeSet;
    struct Object {
        keys: BTreeSet<String>,
        key: bool,
    }
    let bytes = raw.get().as_bytes();
    let mut stack: Vec<Option<Object>> = Vec::new();
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'{' => {
                stack.push(Some(Object {
                    keys: BTreeSet::new(),
                    key: true,
                }));
                index += 1;
            }
            b'[' => {
                stack.push(None);
                index += 1;
            }
            b'}' | b']' => {
                stack.pop();
                index += 1;
            }
            b':' => {
                if let Some(Some(object)) = stack.last_mut() {
                    object.key = false;
                }
                index += 1;
            }
            b',' => {
                if let Some(Some(object)) = stack.last_mut() {
                    object.key = true;
                }
                index += 1;
            }
            b'"' => {
                let start = index;
                index += 1;
                while index < bytes.len() && bytes[index] != b'"' {
                    index += if bytes[index] == b'\\' { 2 } else { 1 };
                }
                index += 1;
                if reject_duplicates
                    && let Some(Some(object)) = stack.last_mut()
                    && object.key
                {
                    let Ok(key) = serde_json::from_str(&raw.get()[start..index]) else {
                        return false;
                    };
                    if !object.keys.insert(key) {
                        return false;
                    }
                }
            }
            b'-' | b'0'..=b'9' => {
                let start = index;
                while index < bytes.len()
                    && !matches!(
                        bytes[index],
                        b',' | b'}' | b']' | b' ' | b'\t' | b'\r' | b'\n'
                    )
                {
                    index += 1;
                }
                if !raw.get()[start..index]
                    .parse::<f64>()
                    .is_ok_and(f64::is_finite)
                {
                    return false;
                }
            }
            _ => index += 1,
        }
        if stack.len() > 10_000 {
            return false;
        }
    }
    true
}
