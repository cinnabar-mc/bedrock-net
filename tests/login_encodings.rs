//! Compact JWT and header comparisons across offline, authenticated and server roles.
#![cfg(feature = "login")]

use base64::{Engine as _, engine::general_purpose::STANDARD};
use bedrock_net::login::{
    LoginError, LoginVerifier, TrustedIdentity, finish_key_exchange, parse_offline_request,
    verify_authenticated_request,
};
use p384::ecdsa::{SigningKey, VerifyingKey};
use serde_json::{Value, json};
use std::{
    io::{Read, Write},
    process::{Command, Stdio},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

/// Fetches independently anchored cases through one Go oracle and waits for its clean exit.
fn fixtures(op: &str) -> Option<Vec<Value>> {
    let Some(binary) = std::env::var_os("BEDROCK_NET_GO_ORACLE") else {
        assert!(
            std::env::var_os("BEDROCK_NET_REQUIRE_FIXTURES").is_none(),
            "missing Go oracle"
        );
        return None;
    };
    let mut child = Command::new(binary)
        .arg("serve")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let body = serde_json::to_vec(&json!({"op":op})).unwrap();
    let mut input = child.stdin.take().unwrap();
    input.write_all(&(body.len() as u32).to_le_bytes()).unwrap();
    input.write_all(&body).unwrap();
    drop(input);
    let mut output = child.stdout.take().unwrap();
    let mut length = [0; 4];
    output.read_exact(&mut length).unwrap();
    let length = u32::from_le_bytes(length) as usize;
    assert!(length < 2_000_000);
    let mut body = vec![0; length];
    output.read_exact(&mut body).unwrap();
    assert!(child.wait().unwrap().success());
    let data: Value = serde_json::from_slice(&body).unwrap();
    assert!(data.get("error").is_none(), "{data}");
    Some(data.as_array().unwrap().clone())
}

struct Provider(VerifyingKey);
impl LoginVerifier for Provider {
    /// Binds the synthetic credential to its fixed test key, independently of client headers.
    fn verify(&self, token: &str, _: SystemTime) -> Result<TrustedIdentity, LoginError> {
        assert_eq!(token, "synthetic-provider");
        TrustedIdentity::new("123".into(), self.0)
    }
}

#[test]
fn compact_jwt_encodings_match_go_in_both_directions() {
    let Some(fixtures) = fixtures("offline_encoding_fixtures") else {
        return;
    };
    assert_eq!(fixtures.len(), 33);
    let mut scalar = [0; 48];
    scalar[47] = 7;
    let key = SigningKey::from_slice(&scalar).unwrap();
    let provider = Provider(*key.verifying_key());
    let now = UNIX_EPOCH + Duration::from_secs(1_800_000_000);
    let mut accepted = 0;
    let mut mismatches = Vec::new();
    for fixture in fixtures {
        let name = fixture["name"].as_str().unwrap();
        let expected = fixture["accepted"].as_bool().unwrap();
        let payload = STANDARD
            .decode(fixture["payload"].as_str().unwrap())
            .unwrap();
        for role in ["request", "legacy"] {
            let bytes = STANDARD.decode(fixture[role].as_str().unwrap()).unwrap();
            let result =
                parse_offline_request(&bytes, now, bytes.len(), |_| panic!("numeric address"));
            let expected = if role == "legacy" {
                fixture["legacy_accepted"].as_bool().unwrap()
            } else {
                expected
            };
            if result.is_ok() != expected {
                mismatches.push(format!("{name}/{role}: {:?}", result.as_ref().err()));
            }
            if let Ok(login) = result {
                assert_eq!(
                    login.client_data_json_bytes(),
                    payload.trim_ascii(),
                    "{name}/{role}"
                );
                assert_eq!(login.nonce(), "nonce", "{name}/{role}");
            }
            assert!(
                matches!(
                    parse_offline_request(&bytes, now, bytes.len() - 1, |_| panic!("byte cap")),
                    Err(LoginError::LimitExceeded { .. })
                ),
                "{name}/{role}"
            );
        }
        let bytes = STANDARD
            .decode(fixture["authenticated"].as_str().unwrap())
            .unwrap();
        let result = verify_authenticated_request(&bytes, &provider, now, bytes.len());
        if result.is_ok() != expected {
            mismatches.push(format!("{name}/authenticated: {:?}", result.as_ref().err()));
        }
        if let Ok(login) = result {
            assert_eq!(
                login.client_data_json_bytes(),
                payload.trim_ascii(),
                "{name}"
            );
            assert_eq!(login.signing_key(), key.verifying_key(), "{name}");
            assert_eq!(login.xuid(), "123", "{name}");
        }
        let token = fixture["server"].as_str().unwrap();
        let result = finish_key_exchange(&key, token, token.len());
        if result.is_ok() != fixture["server_accepted"].as_bool().unwrap() {
            mismatches.push(format!("{name}/server: {:?}", result.as_ref().err()));
        }
        assert!(
            matches!(
                finish_key_exchange(&key, token, token.len() - 1),
                Err(LoginError::LimitExceeded { .. })
            ),
            "{name}/server"
        );
        accepted += usize::from(expected);
    }
    assert!(
        mismatches.is_empty(),
        "JWT encoding mismatches: {mismatches:?}"
    );
    assert_eq!(accepted, 21);
}

#[test]
fn shared_jose_headers_match_go_for_each_role() {
    let Some(fixtures) = fixtures("jose_headers") else {
        return;
    };
    assert_eq!(fixtures.len(), 37);
    let mut scalar = [0; 48];
    scalar[47] = 7;
    let key = SigningKey::from_slice(&scalar).unwrap();
    let provider = Provider(*key.verifying_key());
    let now = UNIX_EPOCH + Duration::from_secs(1_800_000_000);
    let mut mismatches = Vec::new();
    for fixture in fixtures {
        let name = fixture["name"].as_str().unwrap();
        let requests = fixture["requests"].as_object().unwrap();
        assert_eq!(requests.len(), 5);
        assert_eq!(fixture["accepted"].as_object().unwrap().len(), 6);
        for role in ["modern", "metadata", "legacy", "linked", "authenticated"] {
            let request = STANDARD.decode(requests[role].as_str().unwrap()).unwrap();
            let expected = fixture["accepted"][role].as_bool().unwrap();
            let actual = if role == "authenticated" {
                verify_authenticated_request(&request, &provider, now, request.len()).map(|login| {
                    assert_eq!(login.signing_key(), key.verifying_key());
                    assert_eq!(login.xuid(), "123");
                })
            } else {
                parse_offline_request(&request, now, request.len(), |_| panic!("numeric address"))
                    .map(|login| {
                        assert_eq!(login.signing_key().as_p384(), Some(key.verifying_key()));
                        assert_eq!(login.display_name(), "MetadataName");
                    })
            };
            if actual.is_ok() != expected {
                mismatches.push(format!("{name}/{role}: {:?}", actual.err()));
            }
        }
        let token = fixture["server"].as_str().unwrap();
        let result = finish_key_exchange(&key, token, token.len());
        if result.is_ok() != fixture["accepted"]["server"].as_bool().unwrap() {
            mismatches.push(format!("{name}/server: {:?}", result.err()));
        }
    }
    assert!(
        mismatches.is_empty(),
        "shared header mismatches: {mismatches:?}"
    );
}

#[test]
fn certificate_and_reference_shapes_match_go() {
    let Some(cases) = fixtures("jose_admission") else {
        return;
    };
    assert_eq!(cases.len(), 630);
    let mut scalar = [0; 48];
    scalar[47] = 7;
    let key = SigningKey::from_slice(&scalar).unwrap();
    let provider = Provider(*key.verifying_key());
    let now = UNIX_EPOCH + Duration::from_secs(1_800_000_000);
    let mut count = 0;
    let mut mismatches = Vec::new();
    for case in cases {
        count += 1;
        let expected = case["accepted"].as_bool().unwrap();
        let request = STANDARD.decode(case["request"].as_str().unwrap()).unwrap();
        let result = verify_authenticated_request(&request, &provider, now, request.len());
        if result.is_ok() != expected {
            mismatches.push(format!("{}/metadata: {:?}", case["name"], result.err()));
        }
        let token = case["server"].as_str().unwrap();
        let result = finish_key_exchange(&key, token, token.len());
        if result.is_ok() != expected {
            mismatches.push(format!("{}/server: {:?}", case["name"], result.err()));
        }
    }
    assert_eq!(count, 630);
    assert!(
        mismatches.is_empty(),
        "Certificate admission mismatches: {mismatches:?}"
    );
}
