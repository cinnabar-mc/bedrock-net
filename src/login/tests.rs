use super::*;
use std::io::Write;
use std::process::{Command, Stdio};
use std::time::Duration;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use p384::ecdsa::Signature;
use p384::ecdsa::signature::Signer;
use serde::Deserialize;
use serde_json::{Value, json};

const LIMIT: usize = 64 * 1024;
const UUID: &str = "00000000-0000-4000-8000-000000000001";
const CLIENT_DATA: &str = r#"{"DeviceOS":7,"GameVersion":"1.0.0","LanguageCode":"en_US","ServerAddress":"127.0.0.1:19132","SkinId":"synthetic","ThirdPartyName":"Probe","ClientRandomId":0,"ProfileHash":""}"#;

/// Creates a synthetic signing key from a small scalar.
fn key(scalar: u8) -> SigningKey {
    let mut bytes = [0; 48];
    bytes[47] = scalar;
    SigningKey::from_slice(&bytes).unwrap()
}

/// Supplies explicit caller-owned identity claims; no account defaults are inferred.
fn identity() -> OfflineIdentity<'static> {
    OfflineIdentity {
        display_name: "Probe",
        identity: UUID,
        xuid: "",
        playfab_id: "",
        playfab_title_id: "",
    }
}

/// Signs a synthetic server token, including critical-header variants.
fn server_token(key: &SigningKey, mut header: Value, claims: Value) -> String {
    let public = key.verifying_key().to_public_key_der().unwrap();
    header["alg"] = "ES384".into();
    header["x5u"] = STANDARD.encode(public.as_bytes()).into();
    let encoded_header = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap());
    let payload = serde_json::to_vec(&claims).unwrap();
    let encoded_payload = URL_SAFE_NO_PAD.encode(&payload);
    let mut signing_input = encoded_header.as_bytes().to_vec();
    signing_input.push(b'.');
    if header["b64"] == false {
        signing_input.extend_from_slice(&payload);
    } else {
        signing_input.extend_from_slice(encoded_payload.as_bytes());
    }
    let signature: Signature = key.try_sign(&signing_input).unwrap();
    format!(
        "{encoded_header}.{encoded_payload}.{}",
        URL_SAFE_NO_PAD.encode(signature.to_bytes())
    )
}

#[derive(Deserialize)]
struct Oracle {
    auth_claims: Value,
    client_json: String,
    server_token: String,
    name: String,
    uuid: String,
}

#[test]
fn go_verifies_both_login_modes_with_the_same_connection_key() {
    let Some(binary) = std::env::var_os("BEDROCK_NET_LOGIN_ORACLE") else {
        // CI sets BEDROCK_NET_REQUIRE_FIXTURES so a dropped helper fails instead of skipping.
        assert!(
            std::env::var_os("BEDROCK_NET_REQUIRE_FIXTURES").is_none(),
            "missing fixture: BEDROCK_NET_LOGIN_ORACLE; build tools/go-oracle/cmd/login-check"
        );
        eprintln!(
            "missing fixture: BEDROCK_NET_LOGIN_ORACLE; build tools/go-oracle/cmd/login-check"
        );
        return;
    };
    let server = key(197);
    let now = UNIX_EPOCH + Duration::from_secs(10_000);
    let client = key(1);
    let client_data = RawValue::from_string(CLIENT_DATA.into()).unwrap();
    let offline = encode_offline_request(&client, &identity(), &client_data, now, LIMIT).unwrap();
    let length = u32::from_le_bytes(offline[..4].try_into().unwrap()) as usize;
    let envelope: Value = serde_json::from_slice(&offline[4..4 + length]).unwrap();
    let token = envelope["Token"].as_str().unwrap();
    for authenticated in [false, true] {
        let request = if authenticated {
            encode_authenticated_request(&client, token, &client_data, LIMIT).unwrap()
        } else {
            offline.clone()
        };
        let input = serde_json::to_vec(&json!({
            "request": STANDARD.encode(&request),
            "authentication_type": if authenticated { 0 } else { 2 },
            "client_scalar": STANDARD.encode(client.to_bytes()),
            "server_scalar": STANDARD.encode(server.to_bytes()),
            "salt": STANDARD.encode((0_u8..16).collect::<Vec<_>>()),
        }))
        .unwrap();
        let mut child = Command::new(&binary)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("start the synthetic Login oracle");
        let written = child.stdin.take().unwrap().write_all(&input);
        let output = child.wait_with_output().expect("reap the Login oracle");
        written.expect("write the oracle request");
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let oracle: Oracle = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(oracle.name, identity().display_name);
        assert_eq!(oracle.uuid, UUID);
        assert_eq!(oracle.auth_claims["aud"], MULTIPLAYER_AUDIENCE);
        assert_eq!(oracle.auth_claims["exp"], 10_000 + OFFLINE_VALIDITY_SECONDS);
        assert_eq!(oracle.auth_claims["nbf"], 10_000 - OFFLINE_VALIDITY_SECONDS);
        for name in ["ipt", "mid", "tid", "xid"] {
            assert_eq!(oracle.auth_claims[name], "");
        }
        assert_eq!(
            STANDARD.decode(oracle.client_json).unwrap(),
            format!("{CLIENT_DATA}\n").as_bytes()
        );
        verify_server_handshake(&oracle.server_token, LIMIT).unwrap();
    }
}

#[test]
fn server_tokens_verify_and_ignore_unused_registered_claims() {
    let server = key(197);
    for (header, claims) in [
        (
            json!({}),
            json!({"salt":"AQI======", "exp":"unused", "nbf":{}, "aud":null}),
        ),
        (json!({"crit":["b64"],"b64":true}), json!({"salt":""})),
        (json!({"crit":["b64"],"b64":false}), json!({})),
        (json!({}), json!({"salt":null})),
    ] {
        let token = server_token(&server, header, claims);
        assert!(verify_server_handshake(&token, LIMIT).is_ok());
        let (input, signature) = token.rsplit_once('.').unwrap();
        let mut signature = URL_SAFE_NO_PAD.decode(signature).unwrap();
        signature[0] ^= 1;
        let tampered = format!("{input}.{}", URL_SAFE_NO_PAD.encode(signature));
        assert!(matches!(
            verify_server_handshake(&tampered, LIMIT),
            Err(LoginError::Signature(_))
        ));
        assert!(matches!(
            verify_server_handshake(&token, token.len() - 1),
            Err(LoginError::LimitExceeded { .. })
        ));
    }
    for token in [
        "not.a.valid.token".to_owned(),
        server_token(&server, json!({"crit":["unknown"]}), json!({"salt":""})),
        server_token(&server, json!({}), json!({"salt":"!"})),
    ] {
        assert!(verify_server_handshake(&token, LIMIT).is_err());
    }
}

#[test]
fn request_limits_are_exact_and_utc_validity_handles_pre_epoch_seconds() {
    let client = key(1);
    let client_data = RawValue::from_string(CLIENT_DATA.into()).unwrap();
    let non_object = RawValue::from_string("[]".into()).unwrap();
    assert!(matches!(
        encode_offline_request(&client, &identity(), &non_object, UNIX_EPOCH, LIMIT),
        Err(LoginError::InvalidClientData)
    ));
    // Windows SystemTime stores 100 ns intervals; keep the fraction representable.
    let now = UNIX_EPOCH - Duration::from_micros(1);
    let request = encode_offline_request(&client, &identity(), &client_data, now, LIMIT).unwrap();
    assert_eq!(
        encode_offline_request(&client, &identity(), &client_data, now, request.len()).unwrap(),
        request
    );
    for limit in [0, CLIENT_DATA.len(), request.len() - 1] {
        assert!(matches!(
            encode_offline_request(&client, &identity(), &client_data, now, limit),
            Err(LoginError::LimitExceeded { .. })
        ));
    }
    let length = u32::from_le_bytes(request[..4].try_into().unwrap()) as usize;
    let envelope: Value = serde_json::from_slice(&request[4..4 + length]).unwrap();
    let token = envelope["Token"].as_str().unwrap();
    let authenticated = encode_authenticated_request(&client, token, &client_data, LIMIT).unwrap();
    assert_eq!(
        encode_authenticated_request(&client, token, &client_data, authenticated.len()).unwrap(),
        authenticated
    );
    for limit in [0, token.len() - 1, authenticated.len() - 1] {
        assert!(matches!(
            encode_authenticated_request(&client, token, &client_data, limit),
            Err(LoginError::LimitExceeded { .. })
        ));
    }
    assert!(matches!(
        encode_authenticated_request(&client, "", &client_data, LIMIT),
        Err(LoginError::EmptyAuthenticationToken)
    ));
    assert!(matches!(
        encode_authenticated_request(&client, token, &non_object, LIMIT),
        Err(LoginError::InvalidClientData)
    ));
    let payload = token.split('.').nth(1).unwrap();
    let claims: Value = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload).unwrap()).unwrap();
    assert_eq!(claims["exp"], OFFLINE_VALIDITY_SECONDS - 1);
    assert_eq!(claims["nbf"], -OFFLINE_VALIDITY_SECONDS - 1);
}

#[test]
fn server_salt_accepts_raw_standard_base64_spellings() {
    let server = key(197);
    for salt in ["AR", "A\r\nQ", "AR=====", "A\r\nQ=="] {
        let token = server_token(&server, json!({}), json!({"salt":salt}));
        verify_server_handshake(&token, LIMIT).unwrap();
    }
}

#[test]
fn server_address_checks_bracketed_ip_literals() {
    for (input, host) in [
        ("http://[::1]:19132", b"::1".as_slice()),
        ("http://[::1%25eth0]:19132", b"::1%eth0"),
    ] {
        assert_eq!(
            split_server_address(input),
            Some((host.to_vec(), 19132)),
            "{input}"
        );
    }
    for input in [
        "http://[v1.example]:19132",
        "http://[::1%25]:19132",
        "http://[::1:19132",
        "http://[::1]bad:19132",
    ] {
        assert!(split_server_address(input).is_none());
    }
}
