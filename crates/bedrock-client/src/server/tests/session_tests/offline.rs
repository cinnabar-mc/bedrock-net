//! Actual offline Login, external pack delivery and world/relay continuations.

use super::*;
use crate::{
    handshake::{ClientHandshake, HandshakeOptions, SettingsEvent},
    server::{
        OfflinePolicy, ServerAcknowledgmentEvent, ServerApprovalEvent, ServerHandshake,
        ServerHandshakeOptions, ServerLoginEvent, ServerPacksReady, ServerSettingsEvent,
    },
};
use bedrock_net::login::{OfflineIdentity, OfflineLogin};
use p384::ecdsa::SigningKey;
use serde_json::value::RawValue;
use std::{convert::Infallible, time::Duration};

type Policy = OfflinePolicy<fn(&str) -> Result<(), LoginError>>;

/// Supplies no resolver result for the synthetic literal address.
fn policy() -> Policy {
    OfflinePolicy::new(|_| panic!("literal address must not require resolution"))
}

/// Completes the actual public settings, authorization and optional encrypted acknowledgment.
fn ready(
    encrypted: bool,
) -> (
    ServerPacksReady<Box<u32>, OfflineLogin>,
    ClientLogin,
    Instant,
    SystemTime,
) {
    let now = Instant::now();
    let utc = SystemTime::UNIX_EPOCH + Duration::from_secs(1000);
    let key = SigningKey::from_slice(&[4; 48]).unwrap();
    let server = ServerHandshake::new_offline(
        SigningKey::from_slice(&[5; 48]).unwrap(),
        Some(*key.verifying_key()),
        ServerHandshakeOptions {
            batch_encryption: encrypted,
            ..Default::default()
        },
        now + Duration::from_secs(10),
        now,
    )
    .unwrap();
    let client = ClientHandshake::new(
        key,
        HandshakeOptions {
            batch_encryption: encrypted,
            ..Default::default()
        },
    )
    .unwrap();
    let (client, request) = client.start().unwrap();
    let ServerSettingsEvent::Settings(settings) =
        server.receive(request.into(), &policy(), now, utc).unwrap()
    else {
        panic!("missing original settings flush boundary")
    };
    let SettingsEvent::Ready { login: client, .. } =
        client.receive(settings.packet().clone().into()).unwrap()
    else {
        panic!("client did not install compression")
    };
    let server = settings.flushed(now).unwrap();
    let metadata = RawValue::from_string(r#"{"DeviceOS":1,"GameVersion":"1.26.51","LanguageCode":"en_US","SkinId":"synthetic","ThirdPartyName":"OfflineName","Nonce":"original-nonce","ServerAddress":"127.0.0.1:19132"}"#.into()).unwrap();
    let (client, request) = client
        .login_offline(
            &OfflineIdentity {
                display_name: "TokenName",
                identity: "bad-uuid",
                xuid: "",
                playfab_id: "claimed",
                playfab_title_id: "title",
            },
            &metadata,
            utc,
        )
        .unwrap();
    let ServerLoginEvent::Verified(verified) =
        server.receive(request.into(), &policy(), now, utc).unwrap()
    else {
        panic!("signed offline metadata did not produce its distinct capability")
    };
    assert_eq!(verified.login().legacy_uuid_claim(), "bad-uuid");
    assert_eq!(verified.login().display_name(), "OfflineName");
    let approved = verified
        .authorize(|login| {
            assert_eq!(login.nonce(), "original-nonce");
            Ok::<_, Infallible>(Box::new(91u32))
        })
        .unwrap();
    match approved
        .accept(&policy(), encrypted.then_some(&[7; 16]), now, utc)
        .unwrap()
    {
        ServerApprovalEvent::Ready(server) => {
            assert!(!encrypted);
            (server, client, now, utc)
        }
        ServerApprovalEvent::KeyExchange(exchange) => {
            assert!(encrypted);
            let LoginEvent::KeyExchange(client) =
                client.receive(exchange.packet().clone().into()).unwrap()
            else {
                panic!("missing client exchange")
            };
            let (client, ciphers, response) = client.into_parts();
            let (server, server_ciphers) = exchange.flushed(now).unwrap();
            let (mut output, mut input) = *server_ciphers;
            let (mut client_output, mut client_input) = *ciphers.unwrap();
            let encrypted = client_output
                .encrypt(bytes::Bytes::from_static(b"ack"))
                .unwrap();
            assert_eq!(input.decrypt(encrypted).unwrap(), b"ack".as_slice());
            let encrypted = output.encrypt(bytes::Bytes::from_static(b"reply")).unwrap();
            assert_eq!(
                client_input.decrypt(encrypted).unwrap(),
                b"reply".as_slice()
            );
            let ServerAcknowledgmentEvent::Ready(server) = server
                .receive(response.into(), &policy(), now, utc)
                .unwrap()
            else {
                panic!("missing real acknowledgment")
            };
            (server, client, now, utc)
        }
    }
}

#[test]
fn offline_capability_survives_external_pack_reads_and_actual_world_initialization() {
    for encrypted in [false, true] {
        let (server, client, now, utc) = ready(encrypted);
        let deadline = server.deadline();
        let grant = server.grant().as_ref() as *const u32;
        let (server, packets) = server
            .start_packs(
                snapshot(),
                ServerPackDelivery {
                    chunk_size: CHUNK_BYTES,
                    ..Default::default()
                },
                &policy(),
                now,
                utc,
            )
            .unwrap();
        let (world, spawn, handoff) = exchange_packs(server, packets, client, now);
        assert_eq!(handoff.len(), 2);
        let initialized = initialize(world, spawn, &policy(), now, utc);
        assert_eq!(initialized.deadline(), deadline);
        // Later modern UTC has no provider expiry to revalidate; the original monotonic cutoff remains.
        let accepted = initialized
            .finish(&policy(), now, utc + Duration::from_secs(1_000_000))
            .unwrap();
        let (login, retained_grant, _, radius) = accepted.into_parts();
        assert_eq!(login.display_name(), "OfflineName");
        assert_eq!(login.legacy_uuid_claim(), "bad-uuid");
        assert_eq!(retained_grant.as_ref() as *const u32, grant);
        assert_eq!(radius, 6);
    }
}

#[test]
fn offline_packless_relay_keeps_actual_forward_flush_and_original_cutoff() {
    for without_packs in [false, true] {
        let (server, client, now, utc) = ready(false);
        let deadline = server.deadline();
        let mut relay = if without_packs {
            let pending = server
                .relay_without_packs(1024 * 1024, &policy(), now, utc)
                .unwrap();
            assert_eq!(pending.login().display_name(), "OfflineName");
            let ServerRelayProgress::Continue(relay) = pending.flushed(now).unwrap() else {
                panic!("premature initialization")
            };
            relay
        } else {
            let (server, packets) = server
                .start_packs(
                    snapshot(),
                    ServerPackDelivery {
                        chunk_size: CHUNK_BYTES,
                        ..Default::default()
                    },
                    &policy(),
                    now,
                    utc,
                )
                .unwrap();
            let (world, _, _) = exchange_packs(server, packets, client, now);
            world.relay_world(&policy(), now, utc).unwrap()
        };
        for (packet, source) in [
            (
                packets::Packet::StartGame(Box::new(packets::StartGame {
                    runtime_id: ActorRuntimeID(73),
                    ..Default::default()
                })),
                wire::Peer::Server,
            ),
            (packets::ItemRegistry::default().into(), wire::Peer::Server),
            (radius().into(), wire::Peer::Client),
            (
                packets::ChunkRadiusUpdated {
                    chunk_radius: wire::ZigZag32(5),
                }
                .into(),
                wire::Peer::Server,
            ),
            (
                packets::PlayStatus {
                    status: bedrock_protocol::enums::PlayStatusType::PlayerSpawn,
                }
                .into(),
                wire::Peer::Server,
            ),
        ] {
            let pending = match source {
                wire::Peer::Server => relay.forward_server(packet, now),
                wire::Peer::Client => relay.forward_client(packet, now),
            }
            .unwrap();
            let ServerRelayProgress::Continue(next) = pending.flushed(now).unwrap() else {
                panic!("premature initialization")
            };
            relay = next;
        }
        let pending = relay
            .forward_client(
                packets::SetLocalPlayerAsInitialized {
                    player_id: ActorRuntimeID(73),
                }
                .into(),
                now,
            )
            .unwrap();
        let ServerRelayProgress::Initialized(initialized) = pending.flushed(now).unwrap() else {
            panic!("actual forward did not initialize")
        };
        assert_eq!(initialized.deadline(), deadline);
        let accepted = initialized.finish(&policy(), now, utc).unwrap();
        assert_eq!(accepted.login().nonce(), "original-nonce");
        assert_eq!(accepted.chunk_radius(), 5);
    }

    let (server, _, now, utc) = ready(false);
    let deadline = server.deadline();
    let pending = server
        .relay_without_packs(1024 * 1024, &policy(), now, utc)
        .unwrap();
    let Err(error) = pending.flushed(deadline) else {
        panic!("offline wait renewed its cutoff")
    };
    let (pending, _) = error.into_parts();
    assert!(pending.flushed(now).is_err());
}
