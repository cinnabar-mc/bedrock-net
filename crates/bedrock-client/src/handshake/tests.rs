use super::*;
use crate::packs::PackEvent;

mod packless;

#[test]
fn public_handshake_enables_retained_metadata_only_for_the_original_requested_owner() {
    for retain in [false, true] {
        let configured = ClientHandshake::new(
            SigningKey::from_slice(&[1; 48]).unwrap(),
            HandshakeOptions::default(),
        )
        .unwrap();
        let configured = if retain {
            configured.retain_pack_metadata()
        } else {
            configured
        };
        let (client, _) = configured.start().unwrap();
        let SettingsEvent::Ready { login, .. } = client
            .receive(packets::NetworkSettings::default().into())
            .unwrap()
        else {
            panic!("actual public settings owner did not advance");
        };
        let (client, _) = login
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
            .unwrap();
        let LoginEvent::Packs { packs, .. } = client
            .receive(packets::ResourcePacksInfo::default().into())
            .unwrap()
        else {
            panic!("original public offer did not advance");
        };
        let (packs, _) = packs.start().unwrap();
        let PacksEvent::Finished(complete) = packs
            .receive(packets::ResourcePackStack::default().into())
            .unwrap()
        else {
            panic!("original public stack did not complete");
        };
        let (_, handoff, metadata) = complete.into_parts_with_metadata();
        assert!(handoff.is_empty());
        assert_eq!(metadata.is_some(), retain);
    }
}

/// Uses a synthetic deterministic proof key, without account or transport I/O.
fn handshake(batch_encryption: bool) -> Engine {
    let key = Arc::new(SigningKey::from_slice(&[1; 48]).unwrap());
    let client = Engine::new(
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
fn login(client: &mut Engine) -> packets::Login {
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
        EngineEvent::Compression(CompressionSettings {
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
        let EngineEvent::KeyExchange {
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
            Ok(EngineEvent::Unhandled(_))
        ));
        assert!(matches!(
            client.receive(packets::Packet::ResourcePacksInfo(Default::default())),
            Ok(EngineEvent::Packs { .. })
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
            let EngineEvent::Send(sent) = client.receive(success()).unwrap() else {
                panic!("cache status")
            };
            statuses.extend(sent);
        }
        let EngineEvent::Packs {
            cache_status,
            negotiation,
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
            EngineEvent::KeyExchange {
                ciphers: Some(_),
                ..
            }
        ));
        let EngineEvent::Send(sent) = client.receive(success()).unwrap() else {
            panic!("late success")
        };
        statuses.extend(sent);
        assert_eq!(statuses.len(), 1);
        assert!(
            matches!(&statuses[0], packets::Packet::ClientCacheStatus(status) if status.is_cache_supported)
        );
        let (mut negotiation, _) = negotiation.start().unwrap();
        assert!(matches!(
            negotiation
                .receive(packets::Packet::ResourcePackStack(Default::default()))
                .unwrap(),
            PackEvent::Finished(_)
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
        matches!(client.receive(disconnect.clone()).unwrap(), EngineEvent::Unhandled(packet) if *packet == disconnect)
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
        matches!(client.receive(spawn.clone()).unwrap(), EngineEvent::Unhandled(packet) if *packet == spawn)
    );
    assert!(matches!(
        client
            .receive(packets::Packet::ServerToClientHandshake(
                packets::ServerToClientHandshake {
                    handshake_web_token: exchange_token(&signed_login).into(),
                },
            ))
            .unwrap(),
        EngineEvent::KeyExchange {
            ciphers: Some(_),
            ..
        }
    ));
    let success = || {
        packets::Packet::PlayStatus(packets::PlayStatus {
            status: PlayStatusType::Loginsuccess,
        })
    };
    let EngineEvent::Send(sent) = client.receive(success()).unwrap() else {
        panic!("LoginSuccess must still emit the initial capability");
    };
    assert!(matches!(
        sent.as_slice(),
        [packets::Packet::ClientCacheStatus(status)] if status.is_cache_supported
    ));
    assert!(
        matches!(client.receive(spawn.clone()).unwrap(), EngineEvent::Unhandled(packet) if *packet == spawn)
    );
    assert!(matches!(
        client.receive(success()).unwrap(),
        EngineEvent::Send(sent) if sent.is_empty()
    ));
    assert!(matches!(
        client
            .receive(packets::Packet::ResourcePacksInfo(Default::default()))
            .unwrap(),
        EngineEvent::Packs {
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
        let EngineEvent::Packs { negotiation, .. } = client
            .receive(packets::Packet::ResourcePacksInfo(Default::default()))
            .unwrap()
        else {
            panic!("actual pack owner");
        };
        let (mut negotiation, _) = negotiation.start().unwrap();
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
        matches!(client.receive(spawn.clone()).unwrap(), EngineEvent::Unhandled(packet) if *packet == spawn)
    );
    assert!(matches!(
        client
            .receive(packets::Packet::NetworkSettings(Default::default()))
            .unwrap(),
        EngineEvent::Compression(_)
    ));
    assert!(
        matches!(client.receive(spawn.clone()).unwrap(), EngineEvent::Unhandled(packet) if *packet == spawn)
    );
    assert!(matches!(
        client.receive(packets::Packet::PlayStatus(packets::PlayStatus {
            status: PlayStatusType::Loginsuccess,
        })),
        Ok(EngineEvent::Unhandled(_))
    ));
}

#[test]
fn packless_startup_returns_the_actual_packet_and_retires_login() {
    let mut client = handshake(true);
    login(&mut client);
    let start_game = packets::StartGame {
        runtime_id: bedrock_protocol::types::ActorRuntimeID(42),
        ..Default::default()
    };
    let EngineEvent::Startup(received) = client.receive(start_game.clone().into()).unwrap() else {
        panic!("the actual packet must end the packless Login phase");
    };
    assert_eq!(*received, start_game);
    assert!(matches!(
        client.receive(
            packets::PlayStatus {
                status: PlayStatusType::Loginsuccess,
            }
            .into()
        ),
        Err(HandshakeError::InvalidState)
    ));
}

#[test]
fn start_game_during_an_advertised_pack_phase_keeps_the_original_completion() {
    let mut client = handshake(true);
    login(&mut client);
    let EngineEvent::Packs { negotiation, .. } = client
        .receive(packets::ResourcePacksInfo::default().into())
        .unwrap()
    else {
        panic!("the actual offer must retain its original transfer owner");
    };
    let start_game = packets::Packet::from(packets::StartGame::default());
    assert!(matches!(
        client.receive(start_game.clone()).unwrap(),
        EngineEvent::Unhandled(packet) if *packet == start_game
    ));
    let (mut packs, _) = negotiation.start().unwrap();
    assert!(matches!(
        packs
            .receive(packets::ResourcePackStack::default().into())
            .unwrap(),
        PackEvent::Finished(_)
    ));
}

#[test]
fn unexpected_login_controls_do_not_consume_the_original_transition() {
    let mut client = handshake(true);
    client.start().unwrap();
    for packet in [
        packets::Packet::ServerToClientHandshake(packets::ServerToClientHandshake {
            handshake_web_token: "unexpected".into(),
        }),
        packets::Packet::PlayStatus(packets::PlayStatus {
            status: PlayStatusType::Loginsuccess,
        }),
    ] {
        assert!(
            matches!(client.receive(packet.clone()).unwrap(), EngineEvent::Unhandled(returned) if *returned == packet)
        );
    }
    assert!(matches!(
        client
            .receive(packets::NetworkSettings::default().into())
            .unwrap(),
        EngineEvent::Compression(_)
    ));
    let repeated = packets::Packet::NetworkSettings(Default::default());
    assert!(
        matches!(client.receive(repeated.clone()).unwrap(), EngineEvent::Unhandled(returned) if *returned == repeated)
    );
    let request = client
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
        .unwrap();
    let packet = packets::Packet::ServerToClientHandshake(packets::ServerToClientHandshake {
        handshake_web_token: exchange_token(&request).into(),
    });
    assert!(matches!(
        client.receive(packet.clone()).unwrap(),
        EngineEvent::KeyExchange { .. }
    ));
    assert!(
        matches!(client.receive(packet.clone()).unwrap(), EngineEvent::Unhandled(returned) if *returned == packet)
    );
    assert!(matches!(
        client
            .receive(packets::ResourcePacksInfo::default().into())
            .unwrap(),
        EngineEvent::Packs { .. }
    ));
}
