// SPDX-License-Identifier: MIT
use super::MAX_NESTING_DEPTH;
use crate::login::client_data::RawClientData;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde::Deserialize;
use serde_json::value::RawValue;

#[derive(Deserialize)]
struct Case {
    name: String,
    prefix: String,
    bytes: Vec<u8>,
    suffix: String,
    extra_depth: Option<usize>,
    accepted: bool,
}

impl Case {
    /// Builds literal byte samples or the original generated container boundary around one string.
    fn decoded(&self) -> Vec<u8> {
        let (prefix, suffix) = match self.extra_depth {
            Some(extra) => {
                let depth = MAX_NESTING_DEPTH - 1 + extra;
                (
                    format!("{{\"nested\":{}\"", "[".repeat(depth)),
                    format!("\"{}}}", "]".repeat(depth)),
                )
            }
            None => (self.prefix.clone(), self.suffix.clone()),
        };
        let mut decoded = prefix.into_bytes();
        decoded.extend_from_slice(&self.bytes);
        decoded.extend_from_slice(suffix.as_bytes());
        decoded
    }
}

/// Go checks the same bytes; both skin projections preserve the original opaque outer claims.
#[test]
fn decoded_skin_byte_admission_matches_shared_go_corpus() {
    let cases: Vec<Case> = serde_json::from_str(include_str!(
        "../../../../../tests/fixtures/native-client-data-json-bytes.json"
    ))
    .unwrap();
    let mut failures = Vec::new();
    for case in cases {
        let encoded = serde_json::to_string(&STANDARD.encode(case.decoded())).unwrap();
        for field in ["SkinGeometryData", "SkinResourcePatch"] {
            let object = format!(
                "{{\"GameVersion\":\"1.26.50\",\"DeviceOS\":1,\"LanguageCode\":\"en_US\",\"ThirdPartyName\":\"Fixture\",\"SkinId\":\"fixture\",\"Unknown\":1e999,\"{field}\":{encoded}}}"
            );
            let raw = RawValue::from_string(object.clone()).unwrap();
            let data = RawClientData::from_raw(&raw).unwrap();
            assert_eq!(serde_json::to_string(&data).unwrap(), object);
            if data.validate(7, 7, "1.26.50").is_ok() != case.accepted {
                failures.push(format!("{}:{field}", case.name));
            }
        }
    }
    assert!(
        failures.is_empty(),
        "decoded skin byte admission differs from Go: {failures:?}"
    );
}
