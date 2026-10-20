// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Provider admission controls using original synthetic signing keys.
use super::*;
use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use nethernet::identity::MINECRAFT_AUDIENCE;
use p384::{ecdsa::SigningKey, pkcs8::EncodePublicKey};
use rsa::{
    RsaPrivateKey, pkcs1v15,
    sha2::Sha256,
    signature::{SignatureEncoding, Signer},
    traits::PublicKeyParts,
};
use serde_json::{Value, json, value::RawValue};
use std::{
    sync::OnceLock,
    time::{Duration, UNIX_EPOCH},
};
const ISSUER: &str = "https://synthetic.example/tenant/";
const XUID: &str = "123";
const SERVICE_SECONDS: u64 = 1_900_000_000;

/// Generates an original synthetic issuer once; no real credential or private fixture is loaded.
fn issuer() -> &'static pkcs1v15::SigningKey<Sha256> {
    static ISSUER: OnceLock<pkcs1v15::SigningKey<Sha256>> = OnceLock::new();
    ISSUER.get_or_init(|| {
        pkcs1v15::SigningKey::new(RsaPrivateKey::new(&mut rand::rng(), 1024).unwrap())
    })
}

/// The connection key is independent of the issuer key.
fn key() -> SigningKey {
    SigningKey::from_slice(&[1; 48]).unwrap()
}

/// Publishes the original synthetic issuer's public key under one stable key ID.
fn published_keys() -> Value {
    let public = issuer().as_ref();
    json!({"keys":[{"kty":"RSA","kid":"synthetic",
        "n":URL_SAFE_NO_PAD.encode(public.n().to_be_bytes()), "e":URL_SAFE_NO_PAD.encode(public.e().to_be_bytes())}]})
}

/// Builds bounded trusted public metadata from the synthetic issuer, retaining a non-retail issuer.
fn verifier() -> ProviderVerifier {
    let keys = serde_json::to_vec(&published_keys()).unwrap();
    ProviderVerifier::new(ISSUER.into(), &["RS256".into()], &keys).unwrap()
}

/// Keeps subject distinct from Xbox identity: the configured verifier does not equate these claims.
fn claims() -> Value {
    json!({"iss":ISSUER,"aud":MINECRAFT_AUDIENCE,"sub":"synthetic-subject","xid":XUID,
        "xname":"Synthetic","iat":SERVICE_SECONDS,"exp":SERVICE_SECONDS+3600,
        "cpk":STANDARD.encode(key().verifying_key().to_public_key_der().unwrap().as_bytes())})
}

/// Signs original public test claims through the existing RSA primitive.
fn signed(claims: Value, kid: &str) -> String {
    signed_header(claims, json!({"alg":"RS256","kid":kid}))
}

/// Signs issuer-authentic header-policy violations without conflating them with invalid signatures.
fn signed_header(claims: Value, header: Value) -> String {
    signed_payload(&serde_json::to_vec(&claims).unwrap(), header)
}

/// Preserves exact JSON number spelling while signing through the existing synthetic issuer.
fn signed_payload(payload: &[u8], header: Value) -> String {
    let header = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap());
    let payload = URL_SAFE_NO_PAD.encode(payload);
    let input = format!("{header}.{payload}");
    let signature: pkcs1v15::Signature = issuer().sign(input.as_bytes());
    format!("{input}.{}", URL_SAFE_NO_PAD.encode(signature.to_vec()))
}

/// Replaces one temporal claim without normalizing its decimal or exponent representation.
fn signed_temporal_claim(field: &str, value: &str) -> String {
    let mut claims = claims()
        .as_object()
        .unwrap()
        .iter()
        .map(|(name, value)| {
            (
                name.clone(),
                serde_json::value::to_raw_value(value).unwrap(),
            )
        })
        .collect::<std::collections::BTreeMap<_, _>>();
    claims.insert(field.into(), RawValue::from_string(value.into()).unwrap());
    signed_payload(
        &serde_json::to_vec(&claims).unwrap(),
        json!({"alg":"RS256","kid":"synthetic"}),
    )
}

/// A matching key ID cannot make malformed RSA material a successful cached verifier.
#[test]
fn native_provider_rejects_malformed_matching_key_before_cache_admission() {
    let token = signed(claims(), "synthetic");
    assert!(verifier().recognizes(&token).unwrap());
    for (field, value) in [("n", "***"), ("e", "***"), ("n", ""), ("e", "")] {
        let mut keys = published_keys();
        keys["keys"][0][field] = json!(value);
        let result = ProviderVerifier::new(
            ISSUER.into(),
            &["RS256".into()],
            &serde_json::to_vec(&keys).unwrap(),
        );
        assert!(result.is_err(), "admitted malformed RSA {field}");
    }
}

/// NumericDate compatibility must retain controlled rejection of invalid values and time bounds.
#[test]
fn native_provider_numeric_dates_reject_invalid_values_and_time_bounds() {
    let now = UNIX_EPOCH + Duration::from_secs(SERVICE_SECONDS);
    let verifier = verifier();
    for field in ["exp", "iat", "nbf"] {
        let boundary = SERVICE_SECONDS + if field == "exp" { 0 } else { 61 };
        for value in [
            "\"invalid\"".into(),
            "true".into(),
            "{}".into(),
            "[]".into(),
            "1e100".into(),
            "-1e100".into(),
            "9223372036854775808".into(),
            "-9223372036854775809".into(),
            format!("{boundary}.9"),
            format!("{boundary}9e-1"),
        ] {
            let result = verifier.verify_bound(
                &signed_temporal_claim(field, &value),
                key().verifying_key(),
                XUID,
                now,
            );
            assert!(
                matches!(result, Err(error) if error.kind() == io::ErrorKind::PermissionDenied),
                "accepted invalid {field}={value}"
            );
        }
    }
}

/// Signature, issuer, account/key identity and temporal claims are all part of the real handoff.
#[test]
fn native_provider_rejects_untrusted_identity_and_temporal_contracts() {
    let now = UNIX_EPOCH + Duration::from_secs(SERVICE_SECONDS);
    let verifier = verifier();
    for (field, value) in [
        ("iss", json!("https://another.example/")),
        ("aud", json!("another-service")),
        ("aud", json!([MINECRAFT_AUDIENCE, 7])),
        ("sub", json!("")),
        ("sub", Value::Null),
        ("xid", json!("456")),
        ("cpk", json!("not-a-key")),
        ("exp", json!(SERVICE_SECONDS)),
        ("exp", Value::Null),
        ("nbf", json!(SERVICE_SECONDS + 61)),
        ("iat", json!(SERVICE_SECONDS + 61)),
        ("leguuid", json!("invalid")),
        ("xname", json!("1Invalid")),
    ] {
        let mut claims = claims();
        claims[field] = value;
        let result = verifier.verify_bound(
            &signed(claims, "synthetic"),
            key().verifying_key(),
            XUID,
            now,
        );
        assert!(result.is_err(), "accepted invalid {field}");
    }
    let token = signed(claims(), "not-published");
    assert!(!verifier.recognizes(&token).unwrap());
    assert!(
        verifier
            .verify_bound(&token, key().verifying_key(), XUID, now)
            .is_err()
    );
    let token = signed(claims(), "synthetic");
    let (input, signature) = token.rsplit_once('.').unwrap();
    let mut bytes = URL_SAFE_NO_PAD.decode(signature).unwrap();
    bytes[0] ^= 1;
    let untrusted = format!("{input}.{}", URL_SAFE_NO_PAD.encode(bytes));
    assert!(
        verifier
            .verify_bound(&untrusted, key().verifying_key(), XUID, now)
            .is_err()
    );
    let other = SigningKey::from_slice(&[2; 48]).unwrap();
    assert!(
        verifier
            .verify_bound(&token, other.verifying_key(), XUID, now)
            .is_err()
    );
    let mut optional = claims();
    optional["nbf"] = Value::Null;
    optional["iat"] = Value::Null;
    optional["leguuid"] = Value::Null;
    assert!(
        verifier
            .verify_bound(&signed(optional, ""), key().verifying_key(), XUID, now)
            .is_ok()
    );
    for header in [
        json!({"alg":"RS256","kid":"synthetic","crit":["unknown"]}),
        json!({"alg":"RS256","kid":"synthetic","b64":false}),
        json!({"alg":"HS256","kid":"synthetic"}),
    ] {
        assert!(ProviderVerifier::validate_format(&signed_header(claims(), header)).is_err());
    }
}
