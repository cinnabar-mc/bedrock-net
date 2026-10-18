use super::*;
use crate::login::{OfflineIdentity, encode_authenticated_request, encode_offline_request};
use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use bytes::Bytes;
use p384::{
    ecdsa::{Signature, SigningKey, signature::Signer},
    pkcs8::{DecodePublicKey, EncodePublicKey},
};
use serde_json::{Value, json};
use std::{
    cell::Cell,
    time::{Duration, UNIX_EPOCH},
};

const LIMIT: usize = 64 * 1024;

/// A synthetic issuer verifies a real signature with a configured key, not the token's x5u.
struct Provider {
    key: VerifyingKey,
    calls: Cell<usize>,
}

impl LoginVerifier for Provider {
    fn verify(&self, token: &str, now: SystemTime) -> Result<TrustedIdentity, LoginError> {
        self.calls.set(self.calls.get() + 1);
        let claims = jwt::verify_client(token, &self.key, LIMIT)?;
        let claims: Value = serde_json::from_slice(&claims).map_err(LoginError::Json)?;
        let seconds = now
            .duration_since(UNIX_EPOCH)
            .map_err(|_| LoginError::Authentication)?
            .as_secs();
        if claims["iss"] != "synthetic-login.invalid"
            || claims["exp"]
                .as_u64()
                .is_none_or(|expiry| seconds >= expiry)
        {
            return Err(LoginError::Authentication);
        }
        let der = STANDARD
            .decode(claims["cpk"].as_str().ok_or(LoginError::Authentication)?)
            .map_err(LoginError::Base64)?;
        let public = VerifyingKey::from_public_key_der(&der).map_err(LoginError::PublicKey)?;
        TrustedIdentity::new(
            claims["xid"]
                .as_str()
                .ok_or(LoginError::Authentication)?
                .into(),
            public,
        )
    }
}

/// Uses deterministic original scalars, with the issuer independent from the client's proof key.
fn key(byte: u8) -> SigningKey {
    SigningKey::from_slice(&[byte; 48]).unwrap()
}

/// Signs provider fixture claims through the retained Login signer, never a live credential.
fn credential(issuer: &SigningKey, client: &SigningKey) -> String {
    let claims = jwt::json_line(
        &json!({
            "iss":"synthetic-login.invalid", "exp":1060, "xid":"123",
            "cpk": STANDARD.encode(client.verifying_key().to_public_key_der().unwrap().as_bytes()),
        }),
        LIMIT,
    )
    .unwrap();
    let public = STANDARD.encode(
        issuer
            .verifying_key()
            .to_public_key_der()
            .unwrap()
            .as_bytes(),
    );
    jwt::sign(issuer, &public, &claims, LIMIT).unwrap()
}

/// Retains client-controlled spelling, including a claimed XUID that must never replace the provider's.
fn metadata() -> Box<RawValue> {
    RawValue::from_string("{\"Nonce\":\"original-member-nonce\",\"XUID\":\"999\"}".into()).unwrap()
}

#[test]
fn accepting_login_requires_provider_and_bound_client_signatures() {
    let issuer = key(3);
    let client = key(4);
    let provider = Provider {
        key: *issuer.verifying_key(),
        calls: Cell::new(0),
    };
    let token = credential(&issuer, &client);
    let request = encode_authenticated_request(&client, &token, &metadata(), LIMIT).unwrap();
    let now = UNIX_EPOCH + Duration::from_secs(1000);
    let login = verify_authenticated_request(&request, &provider, now, LIMIT).unwrap();
    assert_eq!(login.xuid(), "123");
    assert_eq!(login.nonce(), "original-member-nonce");
    assert_eq!(login.public_key(), client.verifying_key());
    assert_eq!(login.client_data().get().trim(), metadata().get());
    assert!(
        login
            .revalidate(&provider, now + Duration::from_secs(59))
            .is_ok()
    );
    assert!(matches!(
        login.revalidate(&provider, now + Duration::from_secs(60)),
        Err(LoginError::Authentication)
    ));

    let wrong_proof = encode_authenticated_request(&key(5), &token, &metadata(), LIMIT).unwrap();
    assert!(matches!(
        verify_authenticated_request(&wrong_proof, &provider, now, LIMIT),
        Err(LoginError::Signature(_))
    ));
    let forged_provider = credential(&key(6), &client);
    let forged =
        encode_authenticated_request(&client, &forged_provider, &metadata(), LIMIT).unwrap();
    assert!(matches!(
        verify_authenticated_request(&forged, &provider, now, LIMIT),
        Err(LoginError::Signature(_))
    ));
    let mut damaged = request.to_vec();
    let last = damaged.last_mut().unwrap();
    *last = if *last == b'A' { b'Q' } else { b'A' };
    assert!(verify_authenticated_request(&damaged, &provider, now, LIMIT).is_err());
}

#[test]
fn accepting_login_refuses_frames_and_nonprovider_modes_before_verification() {
    let issuer = key(3);
    let client = key(4);
    let provider = Provider {
        key: *issuer.verifying_key(),
        calls: Cell::new(0),
    };
    let request =
        encode_authenticated_request(&client, &credential(&issuer, &client), &metadata(), LIMIT)
            .unwrap();
    let now = UNIX_EPOCH + Duration::from_secs(1000);
    let mut negative = request.to_vec();
    negative[..4].copy_from_slice(&(-1i32).to_le_bytes());
    let mut huge = request.to_vec();
    huge[..4].copy_from_slice(&i32::MAX.to_le_bytes());
    let mut trailing = request.to_vec();
    trailing.push(0);
    for broken in [
        Bytes::new(),
        request.slice(..3),
        request.slice(..request.len() - 1),
        negative.into(),
        huge.into(),
        trailing.into(),
    ] {
        assert!(matches!(
            verify_authenticated_request(&broken, &provider, now, LIMIT),
            Err(LoginError::InvalidLength)
        ));
    }
    assert!(matches!(
        verify_authenticated_request(&request, &provider, now, request.len() - 1),
        Err(LoginError::LimitExceeded { .. })
    ));
    let offline = encode_offline_request(
        &client,
        &OfflineIdentity {
            display_name: "Fixture",
            identity: "",
            xuid: "123",
            playfab_id: "",
            playfab_title_id: "",
        },
        &metadata(),
        now,
        LIMIT,
    )
    .unwrap();
    assert!(matches!(
        verify_authenticated_request(&offline, &provider, now, LIMIT),
        Err(LoginError::UnsupportedAuthentication)
    ));
    for envelope in [
        r#"{"AuthenticationType":1,"Token":"present"}"#,
        r#"{"chain":[]}"#,
        r#"{"AuthenticationType":0,"Token":""}"#,
    ] {
        let mut raw = Vec::new();
        raw.extend_from_slice(&(envelope.len() as i32).to_le_bytes());
        raw.extend_from_slice(envelope.as_bytes());
        raw.extend_from_slice(&1i32.to_le_bytes());
        raw.push(b'x');
        assert!(verify_authenticated_request(&raw, &provider, now, LIMIT).is_err());
    }
    assert_eq!(
        provider.calls.get(),
        0,
        "malformed/offline inputs reached provider authority"
    );
}

#[test]
fn accepting_client_header_cannot_select_another_key_or_algorithm() {
    let issuer = key(3);
    let client = key(4);
    let provider = Provider {
        key: *issuer.verifying_key(),
        calls: Cell::new(0),
    };
    let credential = credential(&issuer, &client);
    let envelope = serde_json::to_vec(&json!({"AuthenticationType":0,"Token":credential})).unwrap();
    for header in [
        json!({"alg":"RS256"}),
        json!({"alg":"none"}),
        json!({"alg":"ES384","crit":["unknown"]}),
    ] {
        let input = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap()),
            URL_SAFE_NO_PAD.encode(metadata().get())
        );
        let signature: Signature = client.sign(input.as_bytes());
        let token = format!("{input}.{}", URL_SAFE_NO_PAD.encode(signature.to_bytes()));
        let mut request = Vec::new();
        request.extend_from_slice(&(envelope.len() as i32).to_le_bytes());
        request.extend_from_slice(&envelope);
        request.extend_from_slice(&(token.len() as i32).to_le_bytes());
        request.extend_from_slice(token.as_bytes());
        assert!(matches!(
            verify_authenticated_request(
                &request,
                &provider,
                UNIX_EPOCH + Duration::from_secs(1000),
                LIMIT
            ),
            Err(LoginError::UnsupportedHeader)
        ));
    }
}
