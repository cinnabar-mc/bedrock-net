//! Public offline parser controls for authority, metadata, framing and cached resolution.
#![cfg(feature = "login")]

use bedrock_net::login::{
    LoginError, LoginVerifier, OfflineIdentity, TrustedIdentity, encode_offline_request,
    parse_offline_request, verify_authenticated_request,
};
use p384::ecdsa::SigningKey;
use serde_json::value::RawValue;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Returns synthetic metadata accepted by the shared signed ClientData validator.
fn metadata() -> Box<RawValue> {
    RawValue::from_string(
        r#"{"DeviceOS":1,"GameVersion":"1.26.51","LanguageCode":"en_US","SkinId":"synthetic","ThirdPartyName":"MetadataName","Nonce":"original"}"#.into(),
    ).unwrap()
}

/// Encodes a synthetic offline request with intentionally untrusted account claims.
fn request(data: &RawValue) -> Vec<u8> {
    let key = SigningKey::from_slice(&[7; 48]).unwrap();
    encode_offline_request(
        &key,
        &OfflineIdentity {
            display_name: "TokenName",
            identity: "",
            xuid: "123",
            playfab_id: "claimed",
            playfab_title_id: "title",
        },
        data,
        UNIX_EPOCH + Duration::from_secs(1_800_000_000),
        16_384,
    )
    .unwrap()
    .to_vec()
}

struct NoProvider;
impl LoginVerifier for NoProvider {
    /// Fails if offline parsing or authenticated mode selection reaches a provider.
    fn verify(&self, _: &str, _: SystemTime) -> Result<TrustedIdentity, LoginError> {
        panic!("offline mode must not invoke a provider")
    }
}

#[test]
fn explicit_offline_parser_preserves_metadata_without_provider_authority() {
    let data = metadata();
    let request = request(&data);
    let now = UNIX_EPOCH + Duration::from_secs(1_800_000_000);
    let login =
        parse_offline_request(&request, now, 16_384, |_| panic!("literal address")).unwrap();
    assert_eq!(login.display_name(), "MetadataName");
    assert_eq!(login.claimed_xuid(), "123");
    assert_eq!(login.legacy_uuid_claim(), "");
    assert_eq!(
        login.claimed_identity(),
        "ebe094da-4482-31c0-8844-5e422cb123d5"
    );
    assert_eq!(login.claimed_playfab_id(), "claimed");
    assert_eq!(login.claimed_playfab_title_id(), "title");
    assert_eq!(login.client_data().get(), data.get());
    assert_eq!(login.client_data_json_bytes(), data.get().as_bytes());
    assert_eq!(login.nonce(), "original");
    assert_eq!(
        login.exchange_key().as_p384(),
        Some(login.signing_key().as_p384().unwrap())
    );
    assert!(matches!(
        verify_authenticated_request(&request, &NoProvider, now, 16_384),
        Err(LoginError::UnsupportedAuthentication)
    ));
    assert!(parse_offline_request(&request, now, request.len() - 1, |_| Ok(())).is_err());
}

#[test]
fn offline_resolution_requires_a_cached_result_without_a_provider() {
    let data = RawValue::from_string(metadata().get().replace(
        "\"Nonce\":\"original\"",
        "\"Nonce\":\"original\",\"ServerAddress\":\"fixture.invalid:19132\"",
    ))
    .unwrap();
    let request = request(&data);
    for cached in [None, Some(false), Some(true)] {
        let called = std::cell::Cell::new(false);
        let result = parse_offline_request(&request, UNIX_EPOCH, 16_384, |address| {
            called.set(true);
            assert_eq!(address, "fixture.invalid:19132");
            match cached {
                None => Err(LoginError::AddressResolutionRequired),
                Some(false) => Err(LoginError::InvalidClientData),
                Some(true) => Ok(()),
            }
        });
        assert!(called.get());
        match cached {
            None => assert!(matches!(result, Err(LoginError::AddressResolutionRequired))),
            Some(false) => assert!(matches!(result, Err(LoginError::InvalidClientData))),
            Some(true) => assert!(result.is_ok()),
        }
    }
}

#[test]
fn final_length_tolerance_is_offline_only_and_never_renews_the_byte_cap() {
    let mut request = request(&metadata());
    let prefix = 4 + i32::from_le_bytes(request[..4].try_into().unwrap()) as usize;
    request[prefix..prefix + 4].copy_from_slice(&i32::MAX.to_le_bytes());
    assert!(parse_offline_request(&request, UNIX_EPOCH, request.len(), |_| Ok(())).is_ok());
    assert!(matches!(
        verify_authenticated_request(&request, &NoProvider, UNIX_EPOCH, request.len()),
        Err(LoginError::InvalidLength)
    ));
    for length in [-1i32, 0, 1] {
        request[prefix..prefix + 4].copy_from_slice(&length.to_le_bytes());
        assert!(parse_offline_request(&request, UNIX_EPOCH, 16_384, |_| Ok(())).is_err());
    }
}
