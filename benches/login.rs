//! Login request formatting and authenticated verification; pairs with the Go benches.

mod common;

use std::hint::black_box;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use bedrock_net::login::{
    LoginError, LoginVerifier, OfflineIdentity, TrustedIdentity, encode_authenticated_request,
    encode_offline_request, verify_authenticated_request,
};
use criterion::{Criterion, criterion_group, criterion_main};
use p384::ecdsa::signature::{Signer, Verifier};
use p384::ecdsa::{Signature, SigningKey, VerifyingKey};
use p384::pkcs8::{DecodePublicKey, EncodePublicKey};
use serde_json::{Value, json, value::RawValue};

const LIMIT: usize = 16 * 1024 * 1024;

/// Verifies a provider token with a configured key, as an application verifier would.
struct Provider {
    key: VerifyingKey,
    issuer: String,
}

impl LoginVerifier for Provider {
    fn verify(&self, token: &str, now: SystemTime) -> Result<TrustedIdentity, LoginError> {
        let (input, signature) = token.rsplit_once('.').ok_or(LoginError::Authentication)?;
        let signature = URL_SAFE_NO_PAD
            .decode(signature)
            .map_err(|_| LoginError::Authentication)?;
        let signature =
            Signature::from_slice(&signature).map_err(|_| LoginError::Authentication)?;
        self.key
            .verify(input.as_bytes(), &signature)
            .map_err(|_| LoginError::Authentication)?;
        let payload = input.split_once('.').ok_or(LoginError::Authentication)?.1;
        let claims: Value = serde_json::from_slice(
            &URL_SAFE_NO_PAD
                .decode(payload)
                .map_err(|_| LoginError::Authentication)?,
        )
        .map_err(|_| LoginError::Authentication)?;
        let seconds = now.duration_since(UNIX_EPOCH).unwrap().as_secs();
        if claims["iss"] != self.issuer.as_str()
            || claims["exp"].as_u64().is_none_or(|exp| seconds >= exp)
        {
            return Err(LoginError::Authentication);
        }
        let der = STANDARD
            .decode(claims["cpk"].as_str().ok_or(LoginError::Authentication)?)
            .map_err(|_| LoginError::Authentication)?;
        let public =
            VerifyingKey::from_public_key_der(&der).map_err(|_| LoginError::Authentication)?;
        TrustedIdentity::new(
            claims["xid"]
                .as_str()
                .ok_or(LoginError::Authentication)?
                .into(),
            public,
        )
    }
}

/// Signs compact ES384 JSON with the line-terminated header the Go encoder also emits.
fn sign(key: &SigningKey, claims: &Value) -> String {
    let header = json!({ "alg": "ES384" });
    let input = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap()),
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(claims).unwrap())
    );
    let signature: Signature = key.sign(input.as_bytes());
    format!("{input}.{}", URL_SAFE_NO_PAD.encode(signature.to_bytes()))
}

/// Verifies a compact ES384 token and returns its JSON payload.
fn verify_es384(key: &VerifyingKey, token: &str) -> Value {
    let (input, signature) = token.rsplit_once('.').unwrap();
    let signature = Signature::from_slice(&URL_SAFE_NO_PAD.decode(signature).unwrap()).unwrap();
    key.verify(input.as_bytes(), &signature).unwrap();
    let payload = input.split_once('.').unwrap().1;
    serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload).unwrap()).unwrap()
}

/// Splits a Login request into its authentication token and client-data token.
fn fields(request: &[u8]) -> (String, String) {
    let length = u32::from_le_bytes(request[..4].try_into().unwrap()) as usize;
    let envelope: Value = serde_json::from_slice(&request[4..4 + length]).unwrap();
    let rest = &request[4 + length..];
    let client = u32::from_le_bytes(rest[..4].try_into().unwrap()) as usize;
    assert_eq!(rest.len(), 4 + client);
    (
        envelope["Token"].as_str().unwrap().into(),
        String::from_utf8(rest[4..].to_vec()).unwrap(),
    )
}

fn login(c: &mut Criterion) {
    let cases = common::Cases::load();
    let client_data = String::from_utf8(cases.read(cases.str("/login/client_data"))).unwrap();
    let client_data = RawValue::from_string(client_data).unwrap();
    let client =
        SigningKey::from_slice(&[cases.u64("/login/client_scalar_byte") as u8; 48]).unwrap();
    let provider =
        SigningKey::from_slice(&[cases.u64("/login/provider_scalar_byte") as u8; 48]).unwrap();
    let expiry = cases.u64("/login/expiry");
    let cpk = STANDARD.encode(
        client
            .verifying_key()
            .to_public_key_der()
            .unwrap()
            .as_bytes(),
    );
    let token = sign(
        &provider,
        &json!({
            "iss": cases.str("/login/issuer"), "aud": cases.str("/login/audience"),
            "exp": expiry, "nbf": 0, "iat": 0, "ipt": "PlayFab", "mid": "", "tid": "",
            "cpk": cpk, "xid": cases.str("/login/xuid"), "xname": cases.str("/login/display_name"),
        }),
    );
    let verifier = Provider {
        key: *provider.verifying_key(),
        issuer: cases.str("/login/issuer").into(),
    };
    let now = UNIX_EPOCH + Duration::from_secs(expiry - 3600);
    let request = encode_authenticated_request(&client, &token, &client_data, LIMIT).unwrap();
    let identity = OfflineIdentity {
        display_name: cases.str("/login/display_name"),
        identity: cases.str("/login/identity"),
        xuid: "",
        playfab_id: "",
        playfab_title_id: "",
    };

    // Each case checks its own output once: signatures verify and the identity survives.
    let offline = encode_offline_request(&client, &identity, &client_data, now, LIMIT).unwrap();
    let (auth, client_token) = fields(&offline);
    let claims = verify_es384(client.verifying_key(), &auth);
    assert_eq!(claims["xname"], identity.display_name);
    assert_eq!(
        verify_es384(client.verifying_key(), &client_token),
        serde_json::from_str::<Value>(client_data.get()).unwrap()
    );
    let own_token = encode_authenticated_request(&client, &token, &client_data, LIMIT).unwrap();
    let xuid = cases.str("/login/xuid");
    for request in [&own_token, &request] {
        let verified = verify_authenticated_request(request, &verifier, now, LIMIT).unwrap();
        assert_eq!(verified.xuid(), xuid);
    }

    let mut bench = c.benchmark_group("Login");
    bench.bench_function("encode_offline", |b| {
        b.iter(|| {
            black_box(encode_offline_request(&client, &identity, &client_data, now, LIMIT).unwrap())
        })
    });
    bench.bench_function("encode_token", |b| {
        b.iter(|| {
            black_box(encode_authenticated_request(&client, &token, &client_data, LIMIT).unwrap())
        })
    });
    bench.bench_function("verify_token", |b| {
        b.iter(|| black_box(verify_authenticated_request(&request, &verifier, now, LIMIT).unwrap()))
    });
    bench.finish();
}

criterion_group!(benches, login);
criterion_main!(benches);
