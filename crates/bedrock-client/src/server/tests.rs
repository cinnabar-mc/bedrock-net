use super::*;
use crate::handshake::{ClientHandshake, ClientLogin, HandshakeOptions, SettingsEvent};
use bedrock_net::login::{self, TrustedIdentity};
use serde_json::value::RawValue;
use std::{cell::Cell, time::Duration};

const CREDENTIAL: &str = "original-caller-verified-provider-fixture";

/// Supplies the explicitly trusted provider boundary; real signature/header failures are tested in login.
struct Provider {
    public: VerifyingKey,
    revoked: Cell<bool>,
    changed: Cell<bool>,
}

impl LoginVerifier for Provider {
    fn verify(&self, token: &str, utc: SystemTime) -> Result<TrustedIdentity, LoginError> {
        if token != CREDENTIAL
            || self.revoked.get()
            || utc >= SystemTime::UNIX_EPOCH + Duration::from_secs(1060)
        {
            return Err(LoginError::Authentication);
        }
        TrustedIdentity::new(
            if self.changed.get() { "456" } else { "123" }.into(),
            self.public,
        )
    }
}

/// Drives actual generated client/server negotiation to the explicit application-approval boundary.
fn pending() -> (Engine, ClientLogin, Provider, Instant, SystemTime) {
    let now = Instant::now();
    let utc = SystemTime::UNIX_EPOCH + Duration::from_secs(1000);
    let client_key = Arc::new(SigningKey::from_slice(&[4; 48]).unwrap());
    let server_key = Arc::new(SigningKey::from_slice(&[5; 48]).unwrap());
    let provider = Provider {
        public: *client_key.verifying_key(),
        revoked: Cell::new(false),
        changed: Cell::new(false),
    };
    let mut server = Engine::new(
        Arc::clone(&server_key),
        Some(provider.public),
        ServerHandshakeOptions::default(),
        now + Duration::from_secs(10),
        now,
    )
    .unwrap();
    assert!(std::ptr::eq(server.key(), server_key.as_ref()));
    let client =
        ClientHandshake::new(Arc::clone(&client_key), HandshakeOptions::default()).unwrap();
    assert!(std::ptr::eq(client.key(), client_key.as_ref()));
    let (client, request) = client.start().unwrap();
    let EngineEvent::NetworkSettings {
        packet,
        compression,
    } = server.receive(request.into(), &provider, now, utc).unwrap()
    else {
        panic!("missing uncompressed settings boundary")
    };
    let SettingsEvent::Ready {
        login: client,
        compression: selected,
    } = client.receive(packet.into()).unwrap()
    else {
        panic!("client did not install settings")
    };
    assert_eq!(compression, selected);
    server.compression_installed(now).unwrap();
    let metadata =
        RawValue::from_string("{\"Nonce\":\"original-nonce\",\"XUID\":\"999\",\"DeviceOS\":1,\"GameVersion\":\"1.26.51\",\"LanguageCode\":\"en_US\",\"SkinId\":\"synthetic\",\"ThirdPartyName\":\"Probe\"}".into()).unwrap();
    let (client, mut login) = client.login_authenticated(CREDENTIAL, &metadata).unwrap();
    // The actual negotiated RequestNetworkSettings version supersedes this Login field.
    login.client_network_version = wire::I32BE(0);
    assert!(matches!(
        server.receive(login.into(), &provider, now, utc).unwrap(),
        EngineEvent::LoginVerified
    ));
    assert_eq!(server.login().unwrap().xuid(), "123");
    assert_eq!(server.login().unwrap().nonce(), "original-nonce");
    (server, client, provider, now, utc)
}

#[test]
fn accepting_generated_handshake_advances_directly_to_pack_boundary() {
    let (mut server, _client, provider, now, utc) = pending();
    let event = server.accept(&provider, now, utc).unwrap();
    assert!(matches!(event, EngineEvent::ReadyForPacks));
    let sibling = packets::ClientCacheStatus {
        is_cache_supported: true,
    };
    let EngineEvent::Unhandled(unhandled) = server
        .receive(sibling.clone().into(), &provider, now, utc)
        .unwrap()
    else {
        panic!("unrelated sibling was consumed")
    };
    assert_eq!(*unhandled, sibling.into());
    let login = server.finish(&provider, now, utc).unwrap();
    assert_eq!(login.xuid(), "123");
    assert_eq!(login.nonce(), "original-nonce");
    // No LoginSuccess or pack advertisement was produced by this handshake.
}

#[test]
fn accepting_original_deadline_and_provider_binding_survive_approval_wait() {
    let (mut expired, _, provider, now, utc) = pending();
    assert!(matches!(
        expired.accept(&provider, now + Duration::from_secs(10), utc),
        Err(ServerHandshakeError::TimedOut)
    ));
    assert!(matches!(
        expired.accept(&provider, now, utc),
        Err(ServerHandshakeError::InvalidState)
    ));
    let (mut changed, _, provider, now, utc) = pending();
    provider.changed.set(true);
    assert!(matches!(
        changed.accept(&provider, now, utc),
        Err(ServerHandshakeError::Login(LoginError::IdentityChanged))
    ));
    let (mut revoked, _, provider, now, utc) = pending();
    provider.revoked.set(true);
    assert!(matches!(
        revoked.accept(&provider, now, utc),
        Err(ServerHandshakeError::Login(LoginError::Authentication))
    ));
    let (mut rebound, _, mut provider, now, utc) = pending();
    provider.public = *SigningKey::from_slice(&[8; 48]).unwrap().verifying_key();
    assert!(matches!(
        rebound.accept(&provider, now, utc),
        Err(ServerHandshakeError::Login(LoginError::IdentityChanged))
    ));
    let (mut stale, _, provider, now, _) = pending();
    assert!(matches!(
        stale.accept(
            &provider,
            now,
            SystemTime::UNIX_EPOCH + Duration::from_secs(1060)
        ),
        Err(ServerHandshakeError::Login(LoginError::Authentication))
    ));
}

#[test]
fn accepting_approval_and_compression_transitions_are_single_use() {
    let (mut server, _, provider, now, utc) = pending();
    assert!(matches!(
        server.accept(&provider, now, utc).unwrap(),
        EngineEvent::ReadyForPacks
    ));
    assert!(matches!(
        server.accept(&provider, now, utc),
        Err(ServerHandshakeError::InvalidState)
    ));
    let (mut repeated_settings, _, provider, now, _) = pending();
    assert!(matches!(
        repeated_settings.compression_installed(now),
        Err(ServerHandshakeError::InvalidState)
    ));
    assert!(matches!(
        repeated_settings.receive(
            packets::ClientCacheStatus::default().into(),
            &provider,
            now,
            utc
        ),
        Err(ServerHandshakeError::InvalidState)
    ));
}

#[test]
fn accepting_rejects_version_and_transport_proof_before_application_admission() {
    let (pending, client, provider, now, utc) = pending();
    let mut server = Engine::new(
        SigningKey::from_slice(&[5; 48]).unwrap(),
        Some(*SigningKey::from_slice(&[6; 48]).unwrap().verifying_key()),
        ServerHandshakeOptions::default(),
        now + Duration::from_secs(10),
        now,
    )
    .unwrap();
    server
        .receive(
            packets::RequestNetworkSettings {
                client_network_version: wire::I32BE(PROTOCOL_VERSION),
            }
            .into(),
            &provider,
            now,
            utc,
        )
        .unwrap();
    server.compression_installed(now).unwrap();
    // Use the same client's public Login encoder because its one Login was already consumed above.
    let request = login::encode_authenticated_request(
        client.key(),
        CREDENTIAL,
        &RawValue::from_string(r#"{"DeviceOS":1,"GameVersion":"1.26.51","LanguageCode":"en_US","SkinId":"synthetic","ThirdPartyName":"Probe"}"#.into()).unwrap(),
        65536,
    )
    .unwrap();
    assert!(matches!(
        server.receive(
            packets::Login {
                client_network_version: wire::I32BE(PROTOCOL_VERSION),
                connection_request: request
            }
            .into(),
            &provider,
            now,
            utc
        ),
        Err(ServerHandshakeError::TransportKeyMismatch)
    ));
    assert!(server.login().is_none());
    drop(pending);
    for difference in [-1, 1] {
        let mut server = Engine::new(
            SigningKey::from_slice(&[5; 48]).unwrap(),
            None,
            Default::default(),
            now + Duration::from_secs(10),
            now,
        )
        .unwrap();
        let EngineEvent::Refused(status) = server
            .receive(
                packets::RequestNetworkSettings {
                    client_network_version: wire::I32BE(PROTOCOL_VERSION + difference),
                }
                .into(),
                &provider,
                now,
                utc,
            )
            .unwrap()
        else {
            panic!("incompatible protocol was not refused")
        };
        assert_eq!(
            status.status,
            if difference < 0 {
                PlayStatusType::LoginFailedClientOld
            } else {
                PlayStatusType::LoginFailedServerOld
            }
        );
        assert!(matches!(
            server.compression_installed(now),
            Err(ServerHandshakeError::InvalidState)
        ));
    }
}

mod lifecycle_tests;

mod session_tests;

#[test]
fn signed_rotation_binds_transport_with_the_final_key() {
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    use p384::pkcs8::EncodePublicKey;
    let signer = SigningKey::from_slice(&[4; 48]).unwrap();
    let rotated = SigningKey::from_slice(&[6; 48]).unwrap();
    let now = Instant::now();
    let utc = SystemTime::UNIX_EPOCH + Duration::from_secs(1000);
    let provider = Provider {
        public: *signer.verifying_key(),
        revoked: Cell::new(false),
        changed: Cell::new(false),
    };
    let data=RawValue::from_string(format!(r#"{{"DeviceOS":1,"GameVersion":"1.26.51","LanguageCode":"en_US","SkinId":"synthetic","ThirdPartyName":"Probe","Nonce":"first","nonce":"final","identityPublicKey":"{}"}}"#,STANDARD.encode(rotated.verifying_key().to_public_key_der().unwrap().as_bytes()))).unwrap();
    let request = login::encode_authenticated_request(&signer, CREDENTIAL, &data, 65536).unwrap();
    for transport in [*signer.verifying_key(), *rotated.verifying_key()] {
        let mut server = Engine::new(
            SigningKey::from_slice(&[5; 48]).unwrap(),
            Some(transport),
            Default::default(),
            now + Duration::from_secs(10),
            now,
        )
        .unwrap();
        server
            .receive(
                packets::RequestNetworkSettings {
                    client_network_version: wire::I32BE(PROTOCOL_VERSION),
                }
                .into(),
                &provider,
                now,
                utc,
            )
            .unwrap();
        server.compression_installed(now).unwrap();
        let result = server.receive(
            packets::Login {
                client_network_version: wire::I32BE(PROTOCOL_VERSION),
                connection_request: request.clone(),
            }
            .into(),
            &provider,
            now,
            utc,
        );
        if transport == *signer.verifying_key() {
            assert!(matches!(
                result,
                Err(ServerHandshakeError::TransportKeyMismatch)
            ));
            assert!(server.login().is_none());
            continue;
        }
        assert!(matches!(result.unwrap(), EngineEvent::LoginVerified));
        assert_eq!(server.login().unwrap().nonce(), "final");
        assert_eq!(
            server.login().unwrap().signing_key(),
            signer.verifying_key()
        );
        assert!(matches!(
            server.accept(&provider, now, utc).unwrap(),
            EngineEvent::ReadyForPacks
        ));
        let accepted = server.finish(&provider, now, utc).unwrap();
        assert_eq!(accepted.xuid(), "123");
        assert_eq!(accepted.nonce(), "final");
        assert_eq!(
            accepted.exchange_key().as_p384(),
            Some(rotated.verifying_key())
        );
    }
}

#[test]
fn non_p384_rotation_advances_after_approval() {
    let signer = SigningKey::from_slice(&[4; 48]).unwrap();
    let now = Instant::now();
    let utc = SystemTime::UNIX_EPOCH + Duration::from_secs(1000);
    let provider = Provider {
        public: *signer.verifying_key(),
        revoked: Cell::new(false),
        changed: Cell::new(false),
    };
    let data=RawValue::from_string(r#"{"DeviceOS":1,"GameVersion":"1.26.51","LanguageCode":"en_US","SkinId":"synthetic","ThirdPartyName":"Probe","identityPublicKey":"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEaxfR8uEsQkf4vOblY6RA8ncDfYEt6zOg9KE5RdiYwpZP40Li/hp/m47n60p8D54WK84zV2sxXs7LtkBoN79R9Q=="}"#.into()).unwrap();
    let request = login::encode_authenticated_request(&signer, CREDENTIAL, &data, 65536).unwrap();
    {
        let mut server = Engine::new(
            SigningKey::from_slice(&[5; 48]).unwrap(),
            None,
            ServerHandshakeOptions::default(),
            now + Duration::from_secs(10),
            now,
        )
        .unwrap();
        server
            .receive(
                packets::RequestNetworkSettings {
                    client_network_version: wire::I32BE(PROTOCOL_VERSION),
                }
                .into(),
                &provider,
                now,
                utc,
            )
            .unwrap();
        server.compression_installed(now).unwrap();
        assert!(matches!(
            server
                .receive(
                    packets::Login {
                        client_network_version: wire::I32BE(PROTOCOL_VERSION),
                        connection_request: request.clone()
                    }
                    .into(),
                    &provider,
                    now,
                    utc
                )
                .unwrap(),
            EngineEvent::LoginVerified
        ));
        assert!(server.login().unwrap().exchange_key().as_p384().is_none());
        let result = server.accept(&provider, now, utc);
        assert!(matches!(result, Ok(EngineEvent::ReadyForPacks)));
    }
}
