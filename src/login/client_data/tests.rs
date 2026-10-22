// SPDX-License-Identifier: MIT
use super::*;
use serde_json::json;

mod boundaries;

/// The same bounded cases exercise the actual pinned Go decoder without claiming full validation.
#[test]
fn raw_fields_match_the_actual_go_decoder_cases() {
    #[derive(Deserialize)]
    struct Case {
        name: String,
        client_data: RawClientData,
        random_id: i64,
        display_name: String,
        self_signed_id: String,
        opaque: String,
    }
    let cases: Vec<Case> = serde_json::from_str(include_str!(
        "../../../tests/fixtures/native-client-data.json"
    ))
    .unwrap();
    for case in cases {
        assert_eq!(
            case.client_data.random_id().unwrap(),
            Some(case.random_id),
            "{}",
            case.name
        );
        assert_eq!(
            case.client_data.display_name().unwrap().as_deref(),
            Some(case.display_name.as_str()),
            "{}",
            case.name
        );
        assert_eq!(
            case.client_data
                .read::<String>("SelfSignedId")
                .unwrap()
                .unwrap_or_default(),
            case.self_signed_id,
            "{}",
            case.name
        );
        assert_eq!(
            case.client_data
                .entries
                .iter()
                .find(|(name, _)| name == "Unknown")
                .unwrap()
                .1
                .get(),
            case.opaque,
            "{}",
            case.name
        );
    }
}

/// Checks JSON types before semantic refusal, preserving ordered values and existing scalar views.
#[test]
fn raw_type_admission_matches_the_actual_ordered_go_decoder_corpus() {
    #[derive(Deserialize)]
    struct Entry {
        name: String,
        value: Box<RawValue>,
    }
    #[derive(Deserialize)]
    struct Case {
        name: String,
        entries: Vec<Entry>,
        outcome: String,
        #[serde(default)]
        observed: std::collections::BTreeMap<String, Box<RawValue>>,
    }
    let cases: Vec<Case> = serde_json::from_str(include_str!(
        "../../../tests/fixtures/native-client-data-decoder.json"
    ))
    .unwrap();
    assert!(!cases.is_empty());
    let baseline =
        serde_json::to_string(&json!({"ThirdPartyName":"Fixture","ClientRandomId":-7})).unwrap();
    let mut failures = Vec::new();
    for case in cases {
        // Raw entries retain duplicate keys, integer spelling and opaque overflow values.
        let mut object = baseline.clone();
        assert_eq!(object.pop(), Some('}'));
        for entry in case.entries {
            object.push(',');
            object.push_str(&serde_json::to_string(&entry.name).unwrap());
            object.push(':');
            object.push_str(entry.value.get());
        }
        object.push('}');
        let raw = RawValue::from_string(object.clone()).unwrap();
        // Every generic outcome in this decoder corpus is a known-field type failure.
        // Invalid names pass this type gate; later semantic validation owns their refusal.
        let accepted = match case.outcome.as_str() {
            "accepted" | "invalid_name" => true,
            "generic" => false,
            other => panic!("unclassified decoder outcome {other:?} in {}", case.name),
        };
        let data = match RawClientData::from_raw(&raw) {
            Ok(data) if accepted => data,
            Ok(_) => {
                failures.push(format!("{}: accepted a Go JSON type failure", case.name));
                continue;
            }
            Err(_) if !accepted => continue,
            Err(error) => {
                failures.push(format!(
                    "{}: rejected type-valid metadata: {error}",
                    case.name
                ));
                continue;
            }
        };
        assert_eq!(
            serde_json::to_string(&data).unwrap(),
            object,
            "{}",
            case.name
        );
        if let Some(wanted) = case.observed.get("ThirdPartyName") {
            let wanted: String = serde_json::from_str(wanted.get()).unwrap();
            match data.display_name() {
                Ok(Some(actual)) if actual == wanted => {}
                actual => failures.push(format!(
                    "{}: display_name returned {actual:?}, want {wanted:?}",
                    case.name
                )),
            }
        }
        if let Some(wanted) = case.observed.get("ClientRandomId") {
            let wanted: i64 = serde_json::from_str(wanted.get()).unwrap();
            match data.random_id() {
                Ok(Some(actual)) if actual == wanted => {}
                actual => failures.push(format!(
                    "{}: random_id returned {actual:?}, want {wanted}",
                    case.name
                )),
            }
        }
        // Record observations belong to later semantic projection, not raw value normalization.
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

/// A public overlay cannot bypass the generated type gate or partially change retained metadata.
#[test]
fn raw_overlay_rejects_known_type_mismatch_before_mutation() {
    let mut raw = RawClientData::from_value(&json!({"DeviceOS":1,"Unknown":"retained"})).unwrap();
    let original = raw.clone();
    assert!(raw.insert("DeviceOS", json!("wrong-type")).is_err());
    assert_eq!(raw, original);
    raw.insert("DeviceOS", json!(2)).unwrap();
    assert_eq!(raw.integer("DeviceOS").unwrap(), Some(2));
}
