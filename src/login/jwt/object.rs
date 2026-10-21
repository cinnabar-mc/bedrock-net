//! Ordered JSON fields with explicit JOSE and standard envelope matching policies.

use super::{LoginError, client_data};
use serde::{
    Deserialize, Deserializer,
    de::{MapAccess, Visitor},
};
use serde_json::value::RawValue;
use std::fmt;

#[derive(Default)]
pub(in crate::login) struct Object(Vec<(String, Box<RawValue>)>, bool);

impl<'de> Deserialize<'de> for Object {
    /// Retains order so an earlier invalid typed field cannot be hidden by a later alias.
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Fields;
        impl<'de> Visitor<'de> for Fields {
            type Value = Object;
            /// Describes the required JSON shape without retaining peer values in errors.
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a Login object")
            }
            /// Keeps every field occurrence and its original JSON value.
            fn visit_map<M: MapAccess<'de>>(self, mut map: M) -> Result<Object, M::Error> {
                let mut entries = Vec::new();
                while let Some(name) = map.next_key()? {
                    entries.push((name, map.next_value()?));
                }
                Ok(Object(entries, false))
            }
        }
        deserializer.deserialize_map(Fields)
    }
}

impl Object {
    /// Reuses Go-compatible UTF-8 and surrogate interpretation without rebuilding signed data.
    pub(in crate::login) fn parse(bytes: &[u8]) -> Result<Self, LoginError> {
        Self::decode(bytes, false)
    }

    /// Separates standard outer JSON decoding from JOSE's exact names and duplicate rejection.
    fn decode(bytes: &[u8], folded: bool) -> Result<Self, LoginError> {
        let raw = client_data::parse_json(bytes)?;
        let normalized = client_data::normalize(raw.get()).ok_or(LoginError::MalformedJson)?;
        let mut object = serde_json::from_str::<Option<Self>>(&normalized)
            .map(Option::unwrap_or_default)
            .map_err(|_| LoginError::MalformedJson)?;
        object.1 = folded;
        let mut seen = std::collections::BTreeSet::new();
        if !folded && object.0.iter().any(|(key, _)| !seen.insert(key)) {
            return Err(LoginError::MalformedJson);
        }
        Ok(object)
    }

    /// Decodes matching fields in order, retaining a previous non-null scalar.
    fn scalar<T: serde::de::DeserializeOwned>(&self, name: &str) -> Result<Option<T>, LoginError> {
        let mut value = None;
        for (key, raw) in &self.0 {
            if self.matches(key, name) && raw.get() != "null" {
                value =
                    Some(serde_json::from_str(raw.get()).map_err(|_| LoginError::MalformedJson)?);
            }
        }
        Ok(value)
    }

    /// Matches only envelope fields using Go's case folding; JOSE names remain exact.
    fn matches(&self, key: &str, name: &str) -> bool {
        key == name || (self.1 && crate::login::fields::matches_field(key, name))
    }

    /// Borrows the last exact generic-map member, including null key changes.
    pub(in crate::login) fn exact(&self, name: &str) -> Option<&RawValue> {
        self.0
            .iter()
            .rev()
            .find(|(key, _)| key == name)
            .map(|(_, raw)| raw.as_ref())
    }

    /// Borrows every decoded member without collapsing names or decoding generic values.
    pub(in crate::login) fn members(&self) -> impl Iterator<Item = (&str, &RawValue)> {
        self.0
            .iter()
            .map(|(name, raw)| (name.as_str(), raw.as_ref()))
    }

    /// Decodes a Go string field without accepting a number or boolean.
    pub(in crate::login) fn text(&self, name: &str) -> Result<Option<String>, LoginError> {
        self.scalar(name)
    }

    /// Reuses outer chain backing strings across aliases, resetting only for null/empty arrays.
    pub(in crate::login) fn strings(&self, name: &str) -> Result<Option<Vec<String>>, LoginError> {
        let mut backing = Vec::new();
        let mut length = 0;
        let mut present = false;
        for (key, raw) in &self.0 {
            if self.matches(key, name) {
                let value: Option<Vec<Option<String>>> =
                    serde_json::from_str(raw.get()).map_err(|_| LoginError::MalformedJson)?;
                present = value.is_some();
                let elements = value.unwrap_or_default();
                length = elements.len();
                if elements.is_empty() {
                    backing.clear();
                } else {
                    backing.resize_with(backing.len().max(length), String::new);
                    for (slot, element) in backing.iter_mut().zip(elements) {
                        if let Some(text) = element {
                            *slot = text;
                        }
                    }
                }
            }
        }
        backing.truncate(length);
        Ok(present.then_some(backing))
    }
}
