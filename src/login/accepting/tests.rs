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

/// Provider presentation survives signed client spoofing and cannot change during revalidation.
#[test]
fn accepting_login_retains_provider_player_identity_across_revalidation() {
    struct Presentation {
        provider: Provider,
        changed: Cell<u8>,
    }
    impl LoginVerifier for Presentation {
        fn verify(&self, token: &str, now: SystemTime) -> Result<TrustedIdentity, LoginError> {
            let identity = self.provider.verify(token, now)?;
            if self.changed.get() == 5 {
                return Ok(identity);
            }
            identity.with_player_identity(
                if self.changed.get() == 1 {
                    "Changed"
                } else {
                    "Verified"
                }
                .into(),
                (self.changed.get() == 2).then_some("00000000-0000-4000-8000-000000000011"),
                if self.changed.get() == 3 {
                    "changed-master"
                } else {
                    "original-master"
                }
                .into(),
                if self.changed.get() == 4 {
                    "changed-title"
                } else {
                    "original-title"
                }
                .into(),
            )
        }
    }
    let issuer = key(3);
    let client = key(4);
    let provider = Presentation {
        provider: Provider {
            key: *issuer.verifying_key(),
            calls: Cell::new(0),
        },
        changed: Cell::new(0),
    };
    let metadata = RawValue::from_string(r#"{"Nonce":"original-member-nonce","ThirdPartyName":"Spoofed","SelfSignedId":"00000000-0000-4000-8000-000000000099","PlayFabId":"spoofed-master"}"#.into()).unwrap();
    let request =
        encode_authenticated_request(&client, &credential(&issuer, &client), &metadata, LIMIT)
            .unwrap();
    let now = UNIX_EPOCH + Duration::from_secs(1000);
    let login = verify_authenticated_request(&request, &provider, now, LIMIT).unwrap();
    let player = login
        .player_identity()
        .expect("the trusted verifier supplied presentation");
    assert_eq!(player.display_name(), "Verified");
    assert_eq!(player.playfab_id(), "original-master");
    assert_eq!(player.playfab_title_id(), "original-title");
    assert_eq!(player.uuid().get_version_num(), 3);
    assert_eq!(login.client_data().get().trim(), metadata.get());
    assert!(login.revalidate(&provider, now).is_ok());
    for changed in 1..=5 {
        provider.changed.set(changed);
        assert!(matches!(
            login.revalidate(&provider, now),
            Err(LoginError::IdentityChanged)
        ));
    }
    assert!(
        verify_authenticated_request(&request, &provider.provider, now, LIMIT)
            .unwrap()
            .player_identity()
            .is_none(),
        "a narrow verifier must not fabricate presentation"
    );
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

/// Changes only the unsigned outer envelope, retaining the exact existing client JWT field and length.
fn replace_envelope(request: &[u8], envelope: &[u8]) -> Vec<u8> {
    let length = i32::from_le_bytes(request[..4].try_into().unwrap()) as usize;
    let mut output = Vec::new();
    output.extend_from_slice(&(envelope.len() as i32).to_le_bytes());
    output.extend_from_slice(envelope);
    output.extend_from_slice(&request[4 + length..]);
    output
}

#[test]
fn accepting_go_field_casing_preserves_signed_nonce_and_rejects_ambiguous_aliases() {
    let issuer = key(3);
    let client = key(4);
    let provider = Provider {
        key: *issuer.verifying_key(),
        calls: Cell::new(0),
    };
    let token = credential(&issuer, &client);
    let now = UNIX_EPOCH + Duration::from_secs(1000);
    for field in ["Nonce", "nonce", "NONCE", "nOnCe"] {
        let text =
            format!(r#"{{"{field}":"original-member-nonce","opaque":{{"nonce":"unrelated"}}}}"#);
        let metadata = RawValue::from_string(text.clone()).unwrap();
        let request = encode_authenticated_request(&client, &token, &metadata, LIMIT).unwrap();
        let login = verify_authenticated_request(&request, &provider, now, LIMIT).unwrap();
        assert_eq!(
            login.nonce(),
            "original-member-nonce",
            "signed field {field} lost its nonce"
        );
        assert_eq!(login.xuid(), "123");
        assert_eq!(login.client_data().get().trim(), text);
        for (mode, credential) in [
            ("AuthenticationType", "Token"),
            ("authenticationtype", "token"),
            ("AUTHENTICATIONTYPE", "TOKEN"),
            ("aUtHeNtIcAtIoNtYpE", "tOkEn"),
        ] {
            let envelope = serde_json::to_vec(&json!({mode:0, credential:token})).unwrap();
            let changed = replace_envelope(&request, &envelope);
            let login = verify_authenticated_request(&changed, &provider, now, LIMIT).unwrap();
            assert_eq!(login.nonce(), "original-member-nonce");
            assert_eq!(login.client_data().get().trim(), text);
        }
    }
    for json in [
        r#"{"Nonce":"original-member-nonce","nonce":"different"}"#,
        r#"{"nonce":"original-member-nonce","NONCE":"original-member-nonce"}"#,
        r#"{"Nonce":"first","Nonce":"second"}"#,
    ] {
        let request = encode_authenticated_request(
            &client,
            &token,
            &RawValue::from_string(json.into()).unwrap(),
            LIMIT,
        )
        .unwrap();
        assert!(
            verify_authenticated_request(&request, &provider, now, LIMIT).is_err(),
            "ambiguous signed nonce was admitted"
        );
    }
    let request = encode_authenticated_request(&client, &token, &metadata(), LIMIT).unwrap();
    for envelope in [
        format!(r#"{{"AuthenticationType":0,"authenticationtype":0,"Token":"{token}"}}"#),
        format!(r#"{{"AuthenticationType":0,"Token":"{token}","token":"{token}"}}"#),
    ] {
        assert!(
            verify_authenticated_request(
                &replace_envelope(&request, envelope.as_bytes()),
                &provider,
                now,
                LIMIT
            )
            .is_err(),
            "ambiguous outer identity field was admitted"
        );
    }
}

/// Includes public formatting and every nested source, matching ordinary caller diagnostic handling.
fn diagnostic(error: &LoginError) -> String {
    let mut result = format!("{error} {error:?}");
    let mut source = std::error::Error::source(error);
    while let Some(error) = source {
        result.push_str(&format!(" {error} {error:?}"));
        source = error.source();
    }
    result
}

#[test]
fn accepting_peer_json_diagnostics_never_retain_sensitive_values() {
    let issuer = key(3);
    let client = key(4);
    let provider = Provider {
        key: *issuer.verifying_key(),
        calls: Cell::new(0),
    };
    let token = credential(&issuer, &client);
    let now = UNIX_EPOCH + Duration::from_secs(1000);
    let marker = "synthetic-sensitive-login-value-7319";
    let request = encode_authenticated_request(&client, &token, &metadata(), LIMIT).unwrap();
    let envelope = serde_json::to_vec(&json!({"AuthenticationType":marker,"Token":token})).unwrap();
    let changed = replace_envelope(&request, &envelope);
    let error = verify_authenticated_request(&changed, &provider, now, LIMIT)
        .err()
        .expect("wrong field type must still fail");
    assert!(
        !diagnostic(&error).contains(marker),
        "outer Login error retained peer input"
    );

    // The existing shared parser also handles incoming server tokens; both public directions must redact.
    let header = URL_SAFE_NO_PAD.encode(
        serde_json::to_vec(&json!({"alg":"ES384","crit":marker,
        "x5u":STANDARD.encode(client.verifying_key().to_public_key_der().unwrap().as_bytes())}))
        .unwrap(),
    );
    let input = format!("{header}.{}", URL_SAFE_NO_PAD.encode(metadata().get()));
    let signature: Signature = client.sign(input.as_bytes());
    let malformed = format!("{input}.{}", URL_SAFE_NO_PAD.encode(signature.to_bytes()));
    let envelope = serde_json::to_vec(&json!({"AuthenticationType":0,"Token":token})).unwrap();
    let mut changed = Vec::new();
    changed.extend_from_slice(&(envelope.len() as i32).to_le_bytes());
    changed.extend_from_slice(&envelope);
    changed.extend_from_slice(&(malformed.len() as i32).to_le_bytes());
    changed.extend_from_slice(malformed.as_bytes());
    let error = verify_authenticated_request(&changed, &provider, now, LIMIT)
        .err()
        .expect("wrong critical header type must still fail");
    assert!(
        !diagnostic(&error).contains(marker),
        "client header error retained peer input"
    );
    let error = crate::login::finish_key_exchange(&client, &malformed, LIMIT)
        .err()
        .expect("wrong server header type must still fail");
    assert!(
        !diagnostic(&error).contains(marker),
        "shared server header error retained peer input"
    );
}
