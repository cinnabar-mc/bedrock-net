use super::*;
use crate::handshake::{ClientHandshake, ClientLogin, HandshakeOptions, LoginEvent, SettingsEvent};
use bedrock_net::login::TrustedIdentity;
use bytes::Bytes;
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
fn pending(encrypted: bool) -> (Engine, ClientLogin, Provider, Instant, SystemTime) {
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
        ServerHandshakeOptions {
            batch_encryption: encrypted,
            ..Default::default()
        },
        now + Duration::from_secs(10),
        now,
    )
    .unwrap();
    assert!(std::ptr::eq(server.key(), server_key.as_ref()));
    let client = ClientHandshake::new(
        Arc::clone(&client_key),
        HandshakeOptions {
            batch_encryption: encrypted,
            ..Default::default()
        },
    )
    .unwrap();
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
fn accepting_generated_handshake_preserves_cipher_order_and_pack_boundary() {
    for encrypted in [true, false] {
        let (mut server, client, provider, now, utc) = pending(encrypted);
        let event = server
            .accept(&provider, encrypted.then_some(&[7; 16]), now, utc)
            .unwrap();
        if encrypted {
            let EngineEvent::KeyExchange { packet, ciphers } = event else {
                panic!("missing plaintext exchange")
            };
            let (mut outgoing, mut incoming) = *ciphers;
            let LoginEvent::KeyExchange(exchange) = client.receive(packet.into()).unwrap() else {
                panic!("client did not verify the signed exchange")
            };
            let (_client, ciphers, response) = exchange.into_parts();
            let (mut client_outgoing, mut client_incoming) = *ciphers.unwrap();
            // The next packet uses the streams only after the server's plaintext token was handed off.
            server.encryption_installed(now).unwrap();
            let encrypted_ack = client_outgoing
                .encrypt(Bytes::from_static(b"first encrypted acknowledgment"))
                .unwrap();
            assert_eq!(
                incoming.decrypt(encrypted_ack).unwrap(),
                "first encrypted acknowledgment"
            );
            assert!(matches!(
                server
                    .receive(response.into(), &provider, now, utc)
                    .unwrap(),
                EngineEvent::ReadyForPacks
            ));
            for body in [
                b"pack preparation".as_slice(),
                b"next exact batch".as_slice(),
            ] {
                let encrypted = outgoing.encrypt(Bytes::copy_from_slice(body)).unwrap();
                assert_eq!(client_incoming.decrypt(encrypted).unwrap(), body);
                let encrypted = client_outgoing
                    .encrypt(Bytes::copy_from_slice(body))
                    .unwrap();
                assert_eq!(incoming.decrypt(encrypted).unwrap(), body);
            }
        } else {
            assert!(matches!(event, EngineEvent::ReadyForPacks));
        }
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
}

#[test]
fn accepting_original_deadline_and_provider_binding_survive_approval_wait() {
    let (mut expired, _, provider, now, utc) = pending(true);
    assert!(matches!(
        expired.accept(
            &provider,
            Some(&[1; 16]),
            now + Duration::from_secs(10),
            utc
        ),
        Err(ServerHandshakeError::TimedOut)
    ));
    assert!(matches!(
        expired.accept(&provider, Some(&[1; 16]), now, utc),
        Err(ServerHandshakeError::InvalidState)
    ));
    let (mut changed, _, provider, now, utc) = pending(true);
    provider.changed.set(true);
    assert!(matches!(
        changed.accept(&provider, Some(&[1; 16]), now, utc),
        Err(ServerHandshakeError::Login(LoginError::IdentityChanged))
    ));
    let (mut revoked, _, provider, now, utc) = pending(false);
    provider.revoked.set(true);
    assert!(matches!(
        revoked.accept(&provider, None, now, utc),
        Err(ServerHandshakeError::Login(LoginError::Authentication))
    ));
    let (mut rebound, _, mut provider, now, utc) = pending(true);
    provider.public = *SigningKey::from_slice(&[8; 48]).unwrap().verifying_key();
    assert!(matches!(
        rebound.accept(&provider, Some(&[1; 16]), now, utc),
        Err(ServerHandshakeError::Login(LoginError::IdentityChanged))
    ));
    let (mut stale, _, provider, now, _) = pending(true);
    assert!(matches!(
        stale.accept(
            &provider,
            Some(&[1; 16]),
            now,
            SystemTime::UNIX_EPOCH + Duration::from_secs(1060)
        ),
        Err(ServerHandshakeError::Login(LoginError::Authentication))
    ));
}

#[test]
fn accepting_cipher_and_compression_transitions_are_single_use() {
    let (mut server, _, provider, now, utc) = pending(true);
    assert!(matches!(
        server.accept(&provider, Some(&[1; 16]), now, utc).unwrap(),
        EngineEvent::KeyExchange { .. }
    ));
    assert!(matches!(
        server.accept(&provider, Some(&[1; 16]), now, utc),
        Err(ServerHandshakeError::InvalidState)
    ));
    let (mut early_ack, _, provider, now, utc) = pending(true);
    early_ack
        .accept(&provider, Some(&[1; 16]), now, utc)
        .unwrap();
    assert!(matches!(
        early_ack.receive(
            packets::ClientToServerHandshake {}.into(),
            &provider,
            now,
            utc
        ),
        Err(ServerHandshakeError::InvalidState)
    ));
    let (mut repeated_install, _, provider, now, utc) = pending(true);
    repeated_install
        .accept(&provider, Some(&[1; 16]), now, utc)
        .unwrap();
    repeated_install.encryption_installed(now).unwrap();
    assert!(matches!(
        repeated_install.encryption_installed(now),
        Err(ServerHandshakeError::InvalidState)
    ));
    let (mut repeated_settings, _, provider, now, _) = pending(false);
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
    let (pending, client, provider, now, utc) = pending(false);
    let mut server = Engine::new(
        SigningKey::from_slice(&[5; 48]).unwrap(),
        Some(*SigningKey::from_slice(&[6; 48]).unwrap().verifying_key()),
        ServerHandshakeOptions {
            batch_encryption: false,
            ..Default::default()
        },
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
fn signed_rotation_binds_transport_and_continues_ciphers_with_the_final_key() {
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
        let EngineEvent::KeyExchange { packet, ciphers } =
            server.accept(&provider, Some(&[7; 16]), now, utc).unwrap()
        else {
            panic!("missing exchange")
        };
        let (mut server_out, mut server_in) = *ciphers;
        let (mut client_out, mut client_in) = login::finish_key_exchange(
            &rotated,
            packet.handshake_web_token.to_str().unwrap(),
            65536,
        )
        .unwrap();
        server.encryption_installed(now).unwrap();
        let ack = client_out
            .encrypt(Bytes::from_static(b"ack with rotated key"))
            .unwrap();
        assert_eq!(server_in.decrypt(ack).unwrap(), "ack with rotated key");
        assert!(matches!(
            server
                .receive(
                    packets::ClientToServerHandshake {}.into(),
                    &provider,
                    now,
                    utc
                )
                .unwrap(),
            EngineEvent::ReadyForPacks
        ));
        for body in [
            b"first exact batch".as_slice(),
            b"second exact batch".as_slice(),
        ] {
            assert_eq!(
                client_in
                    .decrypt(server_out.encrypt(Bytes::copy_from_slice(body)).unwrap())
                    .unwrap(),
                body
            );
            assert_eq!(
                server_in
                    .decrypt(client_out.encrypt(Bytes::copy_from_slice(body)).unwrap())
                    .unwrap(),
                body
            );
        }
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
fn non_p384_rotation_is_parsed_before_the_existing_cipher_curve_check() {
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
    for encrypted in [false, true] {
        let mut server = Engine::new(
            SigningKey::from_slice(&[5; 48]).unwrap(),
            None,
            ServerHandshakeOptions {
                batch_encryption: encrypted,
                ..Default::default()
            },
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
        let result = server.accept(&provider, Some(&[7; 16]), now, utc);
        if encrypted {
            assert!(matches!(
                result,
                Err(ServerHandshakeError::Login(
                    LoginError::UnsupportedExchangeCurve
                ))
            ));
        } else {
            assert!(matches!(result, Ok(EngineEvent::ReadyForPacks)));
        }
    }
}
