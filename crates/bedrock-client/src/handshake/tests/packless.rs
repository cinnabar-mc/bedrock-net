//! A real post-Login `StartGame` can begin startup without an advertised pack phase.

use super::*;
use bedrock_protocol::types::ActorRuntimeID;

/// Signs Login with the same public owner and completes its actual verified exchange.
fn verified_login(batch_encryption: bool) -> ClientLogin {
    let key = Arc::new(SigningKey::from_slice(&[1; 48]).unwrap());
    let configured = ClientHandshake::new(
        Arc::clone(&key),
        HandshakeOptions {
            batch_encryption,
            blob_cache: true,
            ..Default::default()
        },
    )
    .unwrap();
    assert!(std::ptr::eq(configured.key(), key.as_ref()));
    let (settings, _) = configured.start().unwrap();
    let SettingsEvent::Ready { login, .. } = settings
        .receive(packets::NetworkSettings::default().into())
        .unwrap()
    else {
        panic!("the actual settings must enable Login construction");
    };
    let (login, signed) = login
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
    let early_spawn = packets::Packet::PlayStatus(packets::PlayStatus {
        status: PlayStatusType::PlayerSpawn,
    });
    let LoginEvent::Unhandled { login, packet } = login.receive(early_spawn.clone()).unwrap()
    else {
        panic!("the original early spawn must stay on the caller's FIFO");
    };
    assert_eq!(*packet, early_spawn);
    let LoginEvent::KeyExchange(exchange) = login
        .receive(
            packets::ServerToClientHandshake {
                handshake_web_token: exchange_token(&signed).into(),
            }
            .into(),
        )
        .unwrap()
    else {
        panic!("the same key must verify the actual server exchange");
    };
    let (login, ciphers, _) = exchange.into_parts();
    assert_eq!(ciphers.is_some(), batch_encryption);
    assert!(std::ptr::eq(login.key(), key.as_ref()));
    login
}

/// Covers both absent and already-observed `LoginSuccess` without inventing an offer or stack.
fn packless_start_game(batch_encryption: bool) {
    for login_success in [false, true] {
        let mut login = verified_login(batch_encryption);
        if login_success {
            let LoginEvent::Send {
                login: pending,
                packets,
            } = login
                .receive(
                    packets::PlayStatus {
                        status: PlayStatusType::LoginSuccess,
                    }
                    .into(),
                )
                .unwrap()
            else {
                panic!("actual LoginSuccess must retain the original capability response");
            };
            assert!(matches!(packets.as_slice(),
                [packets::Packet::ClientCacheStatus(status)] if status.is_cache_supported));
            login = pending;
        }
        let event = login
            .receive(
                packets::StartGame {
                    runtime_id: ActorRuntimeID(42),
                    ..Default::default()
                }
                .into(),
            )
            .unwrap();
        assert!(
            !matches!(event, LoginEvent::Unhandled { .. }),
            "actual packless StartGame left the original Login waiting for an offer"
        );
    }
}

#[test]
fn packless_start_game_after_verified_batch_exchange_finishes_login() {
    packless_start_game(true);
}

#[test]
fn packless_start_game_on_encrypted_transport_finishes_login() {
    packless_start_game(false);
}

#[test]
fn packless_start_game_does_not_skip_actual_settings() {
    let (settings, _) = ClientHandshake::new(
        SigningKey::from_slice(&[1; 48]).unwrap(),
        HandshakeOptions::default(),
    )
    .unwrap()
    .start()
    .unwrap();
    let start = packets::Packet::from(packets::StartGame::default());
    let SettingsEvent::Pending { settings, packet } = settings.receive(start.clone()).unwrap()
    else {
        panic!("StartGame cannot replace actual settings or Login dispatch");
    };
    assert_eq!(*packet, start);
    assert!(matches!(
        settings
            .receive(packets::NetworkSettings::default().into())
            .unwrap(),
        SettingsEvent::Ready { .. }
    ));
}
