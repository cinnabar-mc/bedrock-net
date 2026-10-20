// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
use super::*;
use crate::login::client_data::schema_generated::{Kind, Record};

#[derive(Deserialize)]
struct StringCase {
    name: String,
    token: String,
    accepted: bool,
    decoded: Option<String>,
}

/// The actual Go oracle checks these same tokens; generated fields share one string contract.
#[test]
fn shared_go_string_boundaries_preserve_raw_values_and_scalar_views() {
    let cases: Vec<StringCase> = serde_json::from_str(include_str!(
        "../../../../tests/fixtures/native-client-data-string-boundaries.json"
    ))
    .unwrap();
    let records = std::iter::once((Record::Client, None)).chain(
        Record::Client.fields().iter().filter_map(|field| {
            if let Kind::Slice(record) = field.kind {
                Some((record, Some(field.name)))
            } else {
                None
            }
        }),
    );
    let mut failures = Vec::new();
    for (record, parent) in records {
        for field in record.fields() {
            for case in &cases {
                let value = match field.kind {
                    Kind::String => case.token.clone(),
                    Kind::Strings(_) => format!("[{}]", case.token),
                    _ => continue,
                };
                let entry = format!("{{{}:{value}}}", serde_json::to_string(field.name).unwrap());
                let object = match parent {
                    Some(parent) => {
                        format!("{{{}:[{entry}]}}", serde_json::to_string(parent).unwrap())
                    }
                    None => entry,
                };
                let raw = RawValue::from_string(object.clone()).unwrap();
                match RawClientData::from_raw(&raw) {
                    Ok(data) if case.accepted => {
                        assert_eq!(serde_json::to_string(&data).unwrap(), object);
                        if parent.is_none() && matches!(field.kind, Kind::String) {
                            let decoded = data.read::<String>(field.name).ok().flatten();
                            if decoded != case.decoded {
                                failures
                                    .push(format!("{}.{} scalar {}", case.name, field.name, value));
                            }
                        }
                    }
                    Err(_) if !case.accepted => {}
                    _ => failures.push(format!("{}.{} type {}", case.name, field.name, value)),
                }
            }
        }
    }
    for case in &cases {
        if !case.accepted {
            continue;
        }
        let object = format!(
            "{{\"DeviceModel\":\"before\",\"devicemodel\":{},\"DeviceModel\":null,\"Unknown\":1e999}}",
            case.token
        );
        let raw = RawValue::from_string(object.clone()).unwrap();
        match RawClientData::from_raw(&raw) {
            Ok(data) => {
                assert_eq!(serde_json::to_string(&data).unwrap(), object);
                let wanted = case.decoded.as_deref().unwrap_or("before");
                if data.read::<String>("DeviceModel").ok().flatten().as_deref() != Some(wanted) {
                    failures.push(format!("{} folded duplicate scalar", case.name));
                }
            }
            Err(_) => failures.push(format!("{} folded duplicate admission", case.name)),
        }
        if let Some(decoded) = &case.decoded {
            let raw = RawValue::from_string(format!("{{{}:1e999}}", case.token)).unwrap();
            match RawClientData::from_raw(&raw) {
                Ok(data) => {
                    let entries: Vec<_> = data.entries().collect();
                    if entries.len() != 1
                        || entries[0].0 != decoded
                        || entries[0].1.get() != "1e999"
                    {
                        failures.push(format!("{} decoded object key", case.name));
                    }
                }
                _ => failures.push(format!("{} decoded object key", case.name)),
            }
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

/// Both validators consume the same locale cases, including region and transform-language phases.
#[test]
fn shared_go_locale_boundaries_reach_full_metadata_validation() {
    #[derive(Deserialize)]
    struct Case {
        locale: String,
        accepted: bool,
    }
    let cases: Vec<Case> = serde_json::from_str(include_str!(
        "../../../../tests/fixtures/native-client-data-locale-boundaries.json"
    ))
    .unwrap();
    let mut failures = Vec::new();
    for case in cases {
        let raw = RawClientData::from_value(&json!({
            "GameVersion":"1.26.50", "DeviceOS":1, "LanguageCode":case.locale,
            "ThirdPartyName":"Fixture", "SkinId":"fixture"
        }))
        .unwrap();
        if raw.validate(7, 7, "1.26.50").is_ok() != case.accepted {
            failures.push(case.locale);
        }
    }
    assert!(
        failures.is_empty(),
        "locale admission differs: {failures:?}"
    );
}
