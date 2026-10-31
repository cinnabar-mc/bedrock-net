//! Actual Go comparisons for offline JOSE shapes and retained outer chain arrays.

#[cfg(feature = "login")]
use base64::{Engine as _, engine::general_purpose::STANDARD};
#[cfg(feature = "login")]
use bedrock_net::login::parse_offline_request;
#[cfg(feature = "login")]
use serde_json::{Value, json};
#[cfg(feature = "login")]
use std::time::{Duration, UNIX_EPOCH};

#[cfg(feature = "login")]
#[path = "support/oracle.rs"]
mod oracle_support;

/// Compares every case in the selected independent shape group and reports all mismatches.
#[cfg(feature = "login")]
fn compare(group: &str) {
    let Some(mut oracle) = oracle_support::Oracle::configured() else {
        return;
    };
    let response: Value = oracle.call(json!({"op":"offline_shapes"}));
    let fixtures = response.as_array().expect("Go shape fixture array");
    oracle.finish().expect("finish Go shape oracle");
    assert!(
        fixtures
            .iter()
            .all(|case| matches!(case["group"].as_str(), Some("chain" | "header")))
    );
    let mut mismatches = Vec::new();
    let mut count = 0;
    for case in fixtures.iter().filter(|case| case["group"] == group) {
        count += 1;
        let request = STANDARD.decode(case["request"].as_str().unwrap()).unwrap();
        let result = parse_offline_request(
            &request,
            UNIX_EPOCH + Duration::from_secs(1_800_000_000),
            request.len(),
            |_| panic!("numeric address"),
        );
        if result.is_ok() != case["accepted"].as_bool().unwrap() {
            mismatches.push(format!("{}: {:?}", case["name"], result.as_ref().err()));
        }
        if let Ok(login) = result {
            assert_eq!(login.display_name(), "MetadataName");
        }
    }
    assert_eq!(count, if group == "chain" { 24 } else { 129 });
    assert!(mismatches.is_empty(), "{group} mismatches: {mismatches:?}");
}

/// Folded aliases reuse prior string slots through truncation and re-extension.
#[cfg(feature = "login")]
#[test]
fn chain_arrays_match_go() {
    compare("chain");
}

/// Modern headers still decode JOSE types while skipping signature and critical policy.
#[cfg(feature = "login")]
#[test]
fn jose_headers_match_go() {
    compare("header");
}

#[cfg(not(feature = "login"))]
#[test]
fn required_fixtures_need_login_support() {
    assert!(
        std::env::var_os("BEDROCK_NET_REQUIRE_FIXTURES").is_none(),
        "required Go comparisons need the login feature"
    );
}
