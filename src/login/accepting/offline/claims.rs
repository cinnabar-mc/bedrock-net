//! Typed offline identity claims, kept separate from authenticated player identity.

use super::{LoginError, Object, client_data};

#[derive(Default)]
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
