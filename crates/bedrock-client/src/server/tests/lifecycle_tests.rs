//! Exercises the public accepting capabilities with the actual public client owner.

use super::{CREDENTIAL, Provider};
use crate::{
    handshake::{ClientHandshake, ClientLogin, HandshakeOptions, LoginEvent, SettingsEvent},
    server::{
        ServerAcknowledgmentEvent, ServerApprovalEvent, ServerHandshake, ServerHandshakeOptions,
        ServerLoginEvent, ServerPacksReady, ServerSettingsEvent,
    },
};
use bedrock_net::login::LoginError;
use bedrock_protocol::{packets, wire};
use bytes::Bytes;
use p384::ecdsa::SigningKey;
use serde_json::value::RawValue;
use std::{
    cell::Cell,
    convert::Infallible,
    sync::Arc,
    time::{Duration, Instant, SystemTime},
};

/// Explicit fixture authority data; never a `HostedApproval` or real membership claim.
pub(super) struct Grant {
    xuid: String,
    nonce: String,
}

/// Retains actual settings/Login/cipher boundaries, optional encryption and original authority.
pub(super) fn ready_with_client(
    encrypted: bool,
) -> (
    ServerPacksReady<Grant>,
    ClientLogin,
    Provider,
    Instant,
    SystemTime,
) {
    let now = Instant::now();
    let utc = SystemTime::UNIX_EPOCH + Duration::from_secs(1000);
    let key = Arc::new(SigningKey::from_slice(&[4; 48]).unwrap());
    let provider = Provider {
        public: *key.verifying_key(),
        revoked: Cell::new(false),
        changed: Cell::new(false),
    };
    let client = ClientHandshake::new(
        key,
        HandshakeOptions {
            batch_encryption: encrypted,
            ..Default::default()
        },
    )
    .unwrap();
    let server = ServerHandshake::new(
        SigningKey::from_slice(&[5; 48]).unwrap(),
        Some(provider.public),
        ServerHandshakeOptions {
            batch_encryption: encrypted,
            ..Default::default()
        },
        now + Duration::from_secs(10),
        now,
    )
    .unwrap();
    let (client, request) = client.start().unwrap();
    let ServerSettingsEvent::Settings(settings) =
        server.receive(request.into(), &provider, now, utc).unwrap()
    else {
        panic!("missing original plaintext settings continuation");
    };
    let SettingsEvent::Ready {
        login: client,
        compression,
    } = client.receive(settings.packet().clone().into()).unwrap()
    else {
        panic!("client settings did not complete");
    };
    assert_eq!(settings.compression(), compression);
    // The real adapter sends/flushes and installs compression before consuming this capability.
    let server = settings.flushed(now).unwrap();
    let (client, mut login) = client
        .login_authenticated(
            CREDENTIAL,
            &RawValue::from_string("{\"Nonce\":\"superseded-nonce\",\"nonce\":\"original-nonce\",\"XUID\":\"999\",\"DeviceOS\":1,\"GameVersion\":\"1.26.51\",\"LanguageCode\":\"en_US\",\"SkinId\":\"synthetic\",\"ThirdPartyName\":\"Probe\"}".into())
                .unwrap(),
        )
        .unwrap();
    login.client_network_version = wire::I32BE(0);
    let ServerLoginEvent::Verified(verified) =
        server.receive(login.into(), &provider, now, utc).unwrap()
    else {
        panic!("provider verification did not produce the actual Login capability");
    };
    assert_eq!(verified.login().xuid(), "123");
    let approved = verified
        .authorize(|login| {
            Ok::<_, Infallible>(Grant {
                xuid: login.xuid().to_owned(),
                nonce: login.nonce().to_owned(),
            })
        })
        .unwrap();
    let (server, client) = match approved
        .accept(&provider, encrypted.then_some(&[7; 16]), now, utc)
        .unwrap()
    {
        ServerApprovalEvent::Ready(server) => {
            assert!(!encrypted);
            (server, client)
        }
        ServerApprovalEvent::KeyExchange(exchange) => {
            assert!(encrypted);
            assert_eq!(exchange.grant().xuid, "123");
            let LoginEvent::KeyExchange(client) =
                client.receive(exchange.packet().clone().into()).unwrap()
            else {
                panic!("client did not verify the original server exchange");
            };
            let (client, ciphers, response) = client.into_parts();
            let (server, ciphers_server) = exchange.flushed(now).unwrap();
            let (mut outgoing, mut incoming) = *ciphers_server;
            let (mut client_outgoing, mut client_incoming) = *ciphers.unwrap();
            for body in [
                b"acknowledgment prefix".as_slice(),
                b"next exact cipher body".as_slice(),
            ] {
                let encrypted = client_outgoing
                    .encrypt(Bytes::copy_from_slice(body))
                    .unwrap();
                assert_eq!(incoming.decrypt(encrypted).unwrap(), body);
                let encrypted = outgoing.encrypt(Bytes::copy_from_slice(body)).unwrap();
                assert_eq!(client_incoming.decrypt(encrypted).unwrap(), body);
            }
            let sibling = packets::Packet::ClientCacheStatus(packets::ClientCacheStatus {
                is_cache_supported: true,
            });
            let ServerAcknowledgmentEvent::Unhandled {
                acknowledgment: server,
                packet,
            } = server
                .receive(sibling.clone(), &provider, now, utc)
                .unwrap()
            else {
                panic!("unrelated accepted sibling disappeared at the cipher boundary");
            };
            assert_eq!(*packet, sibling);
            let ServerAcknowledgmentEvent::Ready(server) = server
                .receive(response.into(), &provider, now, utc)
                .unwrap()
            else {
                panic!("actual encrypted acknowledgment did not complete Login");
            };
            (server, client)
        }
    };
    (server, client, provider, now, utc)
}

/// Keeps existing lifecycle controls on the same public negotiation fixture.
fn ready(encrypted: bool) -> (ServerPacksReady<Grant>, Provider, Instant, SystemTime) {
    let (server, _client, provider, now, utc) = ready_with_client(encrypted);
    (server, provider, now, utc)
}

#[test]
fn public_accepting_capabilities_preserve_original_cipher_identity_grant_and_deadline() {
    for encrypted in [true, false] {
        let (server, provider, now, utc) = ready(encrypted);
        assert_eq!(server.login().xuid(), server.grant().xuid);
        assert_eq!(server.login().nonce(), server.grant().nonce);
        assert_eq!(server.deadline(), now + Duration::from_secs(10));
        let accepted = server.finish(&provider, now, utc).unwrap();
        assert_eq!(accepted.deadline(), now + Duration::from_secs(10));
        let (login, grant) = accepted.into_parts();
        assert_eq!(login.xuid(), grant.xuid);
        assert_eq!(login.nonce(), grant.nonce);
    }
}

#[test]
fn failed_ready_handoff_retains_original_grant_without_reopening_admission() {
    let (server, provider, now, utc) = ready(false);
    provider.revoked.set(true);
    let Err(failure) = server.finish(&provider, now, utc) else {
        panic!("revoked provider must retain a failed handoff");
    };
    let (server, error) = failure.into_parts();
    assert!(matches!(
        error,
        super::ServerHandshakeError::Login(LoginError::Authentication)
    ));
    assert_eq!(server.grant().xuid, "123");
    assert_eq!(server.login().nonce(), server.grant().nonce);
    provider.revoked.set(false);
    let Err(failure) = server.finish(&provider, now, utc) else {
        panic!("failed readiness must not reopen admission");
    };
    let (_, error) = failure.into_parts();
    assert!(matches!(error, super::ServerHandshakeError::InvalidState));
}
