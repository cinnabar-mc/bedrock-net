use super::*;
use crate::packs::PackEvent;

/// Uses a synthetic deterministic proof key, without account or transport I/O.
fn handshake(batch_encryption: bool) -> ClientHandshake {
    let key = Arc::new(SigningKey::from_slice(&[1; 48]).unwrap());
    let client = ClientHandshake::new(
        Arc::clone(&key),
        HandshakeOptions {
            batch_encryption,
            blob_cache: true,
            ..Default::default()
        },
    )
    .unwrap();
    assert!(std::ptr::eq(client.key(), key.as_ref()));
    client
}

/// Sends the generated settings and then signs one offline Login with that same owner.
fn login(client: &mut ClientHandshake) -> packets::Login {
    let request = client.start().unwrap();
    assert_eq!(request.client_network_version.0, PROTOCOL_VERSION);
    let event = client
        .receive(packets::Packet::NetworkSettings(packets::NetworkSettings {
            compression_algorithm: bedrock_protocol::enums::PacketCompressionAlgorithm::Unknown(37),
            compression_threshold: wire::U16LE(128),
            ..Default::default()
        }))
        .unwrap();
    assert!(matches!(
        event,
        HandshakeEvent::Compression(CompressionSettings {
            algorithm: CompressionAlgorithm::Deflate,
            threshold: 128
        })
    ));
    client
        .login_offline(
            &OfflineIdentity {
                display_name: "Fixture",
                identity: "",
                xuid: "",
                playfab_id: "",
                playfab_title_id: "",
            },
            &RawValue::from_string("{}".into()).unwrap(),
            SystemTime::UNIX_EPOCH,
        )
        .unwrap()
}

/// Reuses the synthetic, already signed ES384 identity token as a valid exchange token.
/// Missing salt is accepted by the existing token verifier; no crypto fixture is duplicated.
fn exchange_token(login: &packets::Login) -> String {
    let bytes = &login.connection_request;
    let length = u32::from_le_bytes(bytes[..4].try_into().unwrap()) as usize;
    let envelope: serde_json::Value = serde_json::from_slice(&bytes[4..4 + length]).unwrap();
    envelope["Token"].as_str().unwrap().to_owned()
}

#[test]
fn settings_login_and_verified_exchange_use_one_key_and_one_transition() {
    for batch_encryption in [true, false] {
        let mut client = handshake(batch_encryption);
        let request = login(&mut client);
        assert_eq!(request.client_network_version.0, PROTOCOL_VERSION);
        let token = exchange_token(&request);
        let event = client
            .receive(packets::Packet::ServerToClientHandshake(
                packets::ServerToClientHandshake {
                    handshake_web_token: token.clone().into(),
                },
            ))
            .unwrap();
        let HandshakeEvent::KeyExchange {
            ciphers,
            response: _,
        } = event
        else {
            panic!("verified exchange")
        };
        assert_eq!(ciphers.is_some(), batch_encryption);
        assert!(matches!(
            client.receive(packets::Packet::ServerToClientHandshake(
                packets::ServerToClientHandshake {
                    handshake_web_token: token.into(),
                }
            )),
            Err(HandshakeError::RepeatedKeyExchange)
        ));
        assert!(matches!(
            client.receive(packets::Packet::ResourcePacksInfo(Default::default())),
            Err(HandshakeError::InvalidState)
        ));
    }
}

#[test]
fn pack_offer_and_login_success_in_either_order_emit_one_cache_status() {
    for offer_first in [false, true] {
        let mut client = handshake(true);
        let signed_login = login(&mut client);
        let success = || {
            packets::Packet::PlayStatus(packets::PlayStatus {
                status: PlayStatusType::Loginsuccess,
            })
        };
        let mut statuses = Vec::new();
        if !offer_first {
            let HandshakeEvent::Send(sent) = client.receive(success()).unwrap() else {
                panic!("cache status")
            };
            statuses.extend(sent);
        }
        let HandshakeEvent::Packs {
            cache_status,
            mut negotiation,
        } = client
            .receive(packets::Packet::ResourcePacksInfo(Default::default()))
            .unwrap()
        else {
            panic!("pack owner")
        };
        statuses.extend(cache_status.map(packets::Packet::ClientCacheStatus));
        assert!(matches!(
            client
                .receive(packets::Packet::ServerToClientHandshake(
                    packets::ServerToClientHandshake {
                        handshake_web_token: exchange_token(&signed_login).into(),
                    }
                ))
                .unwrap(),
            HandshakeEvent::KeyExchange {
                ciphers: Some(_),
                ..
            }
        ));
        let HandshakeEvent::Send(sent) = client.receive(success()).unwrap() else {
            panic!("late success")
        };
        statuses.extend(sent);
        assert_eq!(statuses.len(), 1);
        assert!(
            matches!(&statuses[0], packets::Packet::ClientCacheStatus(status) if status.is_cache_supported)
        );
        negotiation.start().unwrap();
        assert!(matches!(
            negotiation
                .receive(packets::Packet::ResourcePackStack(Default::default()))
                .unwrap(),
            PackEvent::Finished { .. }
        ));
    }
}

#[test]
fn failed_exchange_is_terminal_even_when_transport_already_encrypts() {
    let mut client = handshake(false);
    login(&mut client);
    assert!(matches!(
        client.receive(packets::Packet::ServerToClientHandshake(
            packets::ServerToClientHandshake {
                handshake_web_token: "untrusted".into(),
            }
        )),
        Err(HandshakeError::Login(_))
    ));
    assert!(matches!(
        client.receive(packets::Packet::ResourcePacksInfo(Default::default())),
        Err(HandshakeError::InvalidState)
    ));
}

#[test]
fn early_refusal_and_terminal_packets_preserve_their_meaning() {
    let mut client = handshake(true);
    client.start().unwrap();
    let disconnect = packets::Packet::Disconnect(Default::default());
    assert!(
        matches!(client.receive(disconnect.clone()).unwrap(), HandshakeEvent::Unhandled(packet) if *packet == disconnect)
    );
    assert!(matches!(
        client.receive(packets::Packet::PlayStatus(packets::PlayStatus {
            status: PlayStatusType::LoginfailedClientold,
        })),
        Err(HandshakeError::LoginRefused(
            PlayStatusType::LoginfailedClientold
        ))
    ));
}

#[test]
fn deferred_spawn_neither_sends_cache_status_nor_consumes_the_verified_exchange() {
    let mut client = handshake(true);
    let signed_login = login(&mut client);
    let spawn = packets::Packet::PlayStatus(packets::PlayStatus {
        status: PlayStatusType::Playerspawn,
    });
    assert!(
        matches!(client.receive(spawn.clone()).unwrap(), HandshakeEvent::Unhandled(packet) if *packet == spawn)
    );
    assert!(matches!(
        client
            .receive(packets::Packet::ServerToClientHandshake(
                packets::ServerToClientHandshake {
                    handshake_web_token: exchange_token(&signed_login).into(),
                },
            ))
            .unwrap(),
        HandshakeEvent::KeyExchange {
            ciphers: Some(_),
            ..
        }
    ));
    let success = || {
        packets::Packet::PlayStatus(packets::PlayStatus {
            status: PlayStatusType::Loginsuccess,
        })
    };
    let HandshakeEvent::Send(sent) = client.receive(success()).unwrap() else {
        panic!("LoginSuccess must still emit the initial capability");
    };
    assert!(matches!(
        sent.as_slice(),
        [packets::Packet::ClientCacheStatus(status)] if status.is_cache_supported
    ));
    assert!(
        matches!(client.receive(spawn.clone()).unwrap(), HandshakeEvent::Unhandled(packet) if *packet == spawn)
    );
    assert!(matches!(
        client.receive(success()).unwrap(),
        HandshakeEvent::Send(sent) if sent.is_empty()
    ));
    assert!(matches!(
        client
            .receive(packets::Packet::ResourcePacksInfo(Default::default()))
            .unwrap(),
        HandshakeEvent::Packs {
            cache_status: None,
            ..
        }
    ));
}

#[test]
fn refusal_and_unknown_statuses_still_end_the_handshake_during_packs() {
    for status in [
        PlayStatusType::LoginfailedServerfullsubclient,
        PlayStatusType::Unknown(i32::MAX),
    ] {
        let mut client = handshake(true);
        login(&mut client);
        let HandshakeEvent::Packs {
            mut negotiation, ..
        } = client
            .receive(packets::Packet::ResourcePacksInfo(Default::default()))
            .unwrap()
        else {
            panic!("actual pack owner");
        };
        negotiation.start().unwrap();
        let PackEvent::Unhandled(packet) = negotiation
            .receive(packets::Packet::PlayStatus(packets::PlayStatus { status }))
            .unwrap()
        else {
            panic!("the pack owner must preserve handshake-owned statuses");
        };
        assert!(matches!(
            client.receive(*packet),
            Err(HandshakeError::LoginRefused(received)) if received == status
        ));
        assert!(matches!(
            client.receive(packets::Packet::PlayStatus(packets::PlayStatus {
                status: PlayStatusType::Playerspawn,
            })),
            Err(HandshakeError::InvalidState)
        ));
    }
}

#[test]
fn deferred_spawn_does_not_admit_login_before_settings_or_login_construction() {
    let mut client = handshake(true);
    client.start().unwrap();
    let spawn = packets::Packet::PlayStatus(packets::PlayStatus {
        status: PlayStatusType::Playerspawn,
    });
    assert!(
        matches!(client.receive(spawn.clone()).unwrap(), HandshakeEvent::Unhandled(packet) if *packet == spawn)
    );
    assert!(matches!(
        client
            .receive(packets::Packet::NetworkSettings(Default::default()))
            .unwrap(),
        HandshakeEvent::Compression(_)
    ));
    assert!(
        matches!(client.receive(spawn.clone()).unwrap(), HandshakeEvent::Unhandled(packet) if *packet == spawn)
    );
    assert!(matches!(
        client.receive(packets::Packet::PlayStatus(packets::PlayStatus {
            status: PlayStatusType::Loginsuccess,
        })),
        Err(HandshakeError::InvalidState)
    ));
}
