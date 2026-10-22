// SPDX-License-Identifier: MIT
use super::{locale_generated as locale, unicode_generated as unicode};
use crate::login::client_data::schema_generated;

/// Rust source pins share one actual generated identity; Go's owning test verifies the actual data.
#[test]
fn generated_semantic_data_matches_the_selected_go_sources() {
    assert_eq!(
        [
            unicode::CLIENT_MODULE,
            unicode::CLIENT_VERSION,
            unicode::CLIENT_SUM
        ],
        [
            schema_generated::SOURCE_MODULE,
            schema_generated::SOURCE_VERSION,
            schema_generated::SOURCE_SUM
        ],
    );
    assert_eq!(
        [
            unicode::CLIENT_MODULE,
            unicode::CLIENT_VERSION,
            unicode::CLIENT_SUM,
            unicode::LOCALE_MODULE,
            unicode::LOCALE_VERSION,
            unicode::LOCALE_SUM,
            unicode::UNICODE_VERSION
        ],
        [
            locale::CLIENT_MODULE,
            locale::CLIENT_VERSION,
            locale::CLIENT_SUM,
            locale::LOCALE_MODULE,
            locale::LOCALE_VERSION,
            locale::LOCALE_SUM,
            locale::UNICODE_VERSION
        ],
    );
    let module = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tools/go-oracle/go.mod"
    ));
    assert_eq!(
        module
            .lines()
            .filter(|line| {
                let line = line.split_once("//").map_or(*line, |(code, _)| code);
                let fields = line.split_whitespace().collect::<Vec<_>>();
                fields == [locale::LOCALE_MODULE, locale::LOCALE_VERSION]
                    || fields == ["require", locale::LOCALE_MODULE, locale::LOCALE_VERSION]
            })
            .count(),
        1,
        "generated locale source differs from the unique oracle requirement",
    );
    let sums = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tools/go-oracle/go.sum"
    ));
    assert_eq!(
        sums.lines()
            .filter(|line| line.split_whitespace().eq([
                locale::LOCALE_MODULE,
                locale::LOCALE_VERSION,
                locale::LOCALE_SUM,
            ]))
            .count(),
        1,
        "generated locale checksum differs from tools/go-oracle/go.sum",
    );
}

/// Metadata validity uses the caller's title boundary and preserves distinct refusal categories.
#[test]
fn metadata_validation_retains_version_and_independent_refusals() {
    use super::{RawClientData, ValidationError};
    use serde_json::json;
    let baseline = json!({
        "GameVersion":"fixture-version", "DeviceOS":1, "LanguageCode":"en_US",
        "ServerAddress":"127.0.0.1:19132", "ThirdPartyName":"Fixture", "SkinId":"fixture"
    });
    let accepted = RawClientData::from_value(&baseline)
        .unwrap()
        .validate(7, 7, "fixture-version")
        .unwrap();
    assert_eq!(accepted.requested_name(), "Fixture");
    assert_eq!(
        accepted.into_raw(),
        RawClientData::from_value(&baseline).unwrap()
    );
    for (protocol, version, expected) in [
        (6, "fixture-version", ValidationError::OutdatedClient),
        (8, "fixture-version", ValidationError::OutdatedServer),
        (7, "another-version", ValidationError::OutdatedClient),
    ] {
        assert!(matches!(
            RawClientData::from_value(&baseline).unwrap().validate(protocol, 7, version),
            Err(actual) if actual == expected
        ));
    }
    for (name, value, expected) in [
        ("SkinId", json!(""), ValidationError::InvalidSkin),
        (
            "ThirdPartyName",
            json!("12345"),
            ValidationError::InvalidName,
        ),
        (
            "LanguageCode",
            json!("unregistered-locale"),
            ValidationError::Generic,
        ),
    ] {
        let mut data = baseline.clone();
        data[name] = value;
        assert!(matches!(
            RawClientData::from_value(&data).unwrap().validate(7, 7, "fixture-version"),
            Err(actual) if actual == expected
        ));
    }
    let mut both = baseline;
    both["SkinId"] = json!("");
    both["ThirdPartyName"] = json!("12345");
    assert!(matches!(
        RawClientData::from_value(&both)
            .unwrap()
            .validate(7, 7, "fixture-version"),
        Err(ValidationError::Generic)
    ));
}
