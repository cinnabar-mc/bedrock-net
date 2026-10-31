//! Typed offline identity claims, kept separate from authenticated player identity.

use super::{LoginError, Object, client_data};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Clone, Default)]
pub(super) struct Registered {
    issuer: String,
    dates: [Option<i64>; 3],
}

impl Registered {
    /// Checks registered claim types even when modern time and audience policy is disabled.
    pub(super) fn merge(&mut self, object: &Object) -> Result<(), LoginError> {
        if let Some(issuer) = object.text("iss")? {
            self.issuer = issuer;
        }
        for name in ["sub", "jti"] {
            object.text(name)?;
        }
        for (name, raw) in object.members() {
            if name == "aud" {
                let value: serde_json::Value =
                    serde_json::from_str(raw.get()).map_err(|_| LoginError::MalformedJson)?;
                if !(value.is_string()
                    || value
                        .as_array()
                        .is_some_and(|a| a.iter().all(|v| v.is_string())))
                {
                    return Err(LoginError::MalformedJson);
                }
            }
            for (index, field) in ["exp", "nbf", "iat"].iter().enumerate() {
                if name != *field {
                    continue;
                }
                self.dates[index] = if raw.get() == "null" {
                    None
                } else {
                    let number: f64 = raw.get().parse().map_err(|_| LoginError::MalformedJson)?;
                    if !number.is_finite() {
                        return Err(LoginError::MalformedJson);
                    }
                    Some(if number >= i64::MAX as f64 || number < i64::MIN as f64 {
                        i64::MIN
                    } else {
                        number as i64
                    })
                };
            }
        }
        Ok(())
    }

    /// Checks legacy issuer and the one-minute Go time leeway using only caller UTC.
    pub(super) fn validate(&self, now: SystemTime, require_issuer: bool) -> Result<(), LoginError> {
        let now = match now.duration_since(UNIX_EPOCH) {
            Ok(d) => d.as_nanos() as i128,
            Err(e) => -(e.duration().as_nanos() as i128),
        };
        let second = 1_000_000_000i128;
        let now = go_time(now);
        if (require_issuer && self.issuer != "Mojang")
            || self.dates[0].is_some_and(|d| go_shift(now, -60) > go_time(i128::from(d) * second))
            || self.dates[1..]
                .iter()
                .flatten()
                .any(|d| go_shift(now, 60) < go_time(i128::from(*d) * second))
        {
            return Err(LoginError::Authentication);
        }
        Ok(())
    }
}

pub(super) use super::Claims as Identity;

impl Identity {
    /// Decodes and validates modern claimed identity without invoking a trusted constructor.
    pub(super) fn modern(object: &Object) -> Result<Self, LoginError> {
        object.text("ipt")?;
        object.text("cpk")?;
        let mut identity = Self {
            name: object.text("xname")?.unwrap_or_default(),
            xuid: object.text("xid")?.unwrap_or_default(),
            uuid: object.text("leguuid")?.unwrap_or_default(),
            playfab_id: object.text("mid")?.unwrap_or_default(),
            playfab_title_id: object.text("tid")?.unwrap_or_default(),
            ..Self::default()
        };
        identity.projected_uuid = if identity.uuid.is_empty() && !identity.xuid.is_empty() {
            crate::login::identity::xuid_uuid(&identity.xuid).to_string()
        } else {
            identity.uuid.clone()
        };
        identity.validate()?;
        Ok(identity)
    }

    /// Merges legacy extraData objects and preserves their untrusted identity text.
    pub(super) fn legacy(object: &Object) -> Result<Self, LoginError> {
        object.text("identityPublicKey")?;
        let extra = object
            .exact("extraData")
            .map(|raw| Object::parse(raw.get().as_bytes()))
            .transpose()?
            .unwrap_or_default();
        extra.text("titleId")?;
        let uuid = extra.text("identity")?.unwrap_or_default();
        let identity = Self {
            name: extra.text("displayName")?.unwrap_or_default(),
            xuid: extra.text("XUID")?.unwrap_or_default(),
            projected_uuid: uuid.clone(),
            uuid,
            ..Self::default()
        };
        identity.validate()?;
        Ok(identity)
    }

    /// Checks all account-claim shapes before any application projection or name override.
    fn validate(&self) -> Result<(), LoginError> {
        let name = &self.name;
        if self.xuid.is_empty() {
            return Ok(());
        }
        if self.xuid.parse::<i64>().is_err()
            || client_data::parse_uuid(&self.projected_uuid).is_none_or(|id| id.is_nil())
            || name.is_empty()
            || name.len() > 15
            || name.starts_with(' ')
            || name.ends_with(' ')
            || name.as_bytes()[0].is_ascii_digit()
            || name.contains("  ")
            || !name.bytes().any(|b| b.is_ascii_alphanumeric() || b == b' ')
        {
            return Err(LoginError::Authentication);
        }
        Ok(())
    }
}

/// Converts Unix nanoseconds through Go's signed seconds relative to year 1.
fn go_time(unix_nanos: i128) -> i128 {
    let second = 1_000_000_000;
    let seconds = (unix_nanos.div_euclid(second) as i64).wrapping_add(62_135_596_800);
    i128::from(seconds) * second + unix_nanos.rem_euclid(second)
}

/// Applies exact-second leeway with Go's saturating internal-second addition.
fn go_shift(time: i128, seconds: i64) -> i128 {
    let second = 1_000_000_000;
    let sum = time.div_euclid(second) + i128::from(seconds);
    let seconds = if sum < i128::from(i64::MIN) {
        i64::MIN + 1
    } else if sum > i128::from(i64::MAX) {
        i64::MAX
    } else {
        sum as i64
    };
    i128::from(seconds) * second + time.rem_euclid(second)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registered_dates_require_numeric_json_values() {
        for field in ["exp", "nbf", "iat"] {
            let mut claims = Registered::default();
            claims
                .merge(&Object::parse(format!(r#"{{"{field}":1060}}"#).as_bytes()).unwrap())
                .unwrap();
            assert!(
                claims
                    .merge(&Object::parse(format!(r#"{{"{field}":"1060"}}"#).as_bytes()).unwrap())
                    .is_err()
            );
        }
    }
}
