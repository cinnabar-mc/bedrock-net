//! Real generated client/server pack exchange, original file IO and selected-world initialization.

mod offline;
mod relay_tests;

use super::{
    Provider,
    lifecycle_tests::{Grant, ready_with_client},
};
use crate::{
    handshake::{ClientLogin, ClientPacks, LoginEvent, PacksEvent},
    packs::{PackEvent, PackOffer, PackTransferLimits},
    server::session::*,
    spawn::SpawnNegotiation,
};
use bedrock_net::login::LoginError;
use bedrock_packs::ResourcePackHandoff;
use bedrock_protocol::{
    packets,
    types::{ActorRuntimeID, PackInfoData, PackInstanceId},
    wire,
};
use sha2::{Digest, Sha256};
use std::{
    collections::VecDeque,
    io::{Read, Seek, SeekFrom},
    path::PathBuf,
    time::{Instant, SystemTime},
};

const CHUNK_BYTES: u32 = 256;
const MEMORY_PAYLOAD: &[u8] = &[1, 2, 3, 4, 5, 6, 7];
const CHUNK_REQUEST_VERSION: &str = "ignored-request-version";

/// Existing redistributable catalog bytes exercise a disk source, not a real pack/assets claim.
fn disk_payload() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("data/builtin-packs.json")
}

/// Exercises actual framing and generated sender contracts in both directions.
fn on_wire(packet: packets::Packet, sender: wire::Peer) -> packets::Packet {
    let mut encoded = Vec::new();
    packet.encode_frame(sender, 0, 0, &mut encoded).unwrap();
    let mut frames = wire::Frames::new(encoded.into(), 1);
    let frame = frames.next().unwrap().unwrap();
    assert!(frames.next().is_none());
    let packets::Decoded::Known(decoded) =
        packets::Packet::decode_frame(&frame, sender, &wire::Limits::default()).unwrap()
    else {
        panic!("fixture remains a known generated packet")
    };
    decoded
}

/// Shares explicit synthetic metadata with the original memory/file archive descriptors.
fn snapshot() -> ServerPackSnapshot {
    let mut infos = Vec::new();
    let mut contents = Vec::new();
    for (id, payload) in [
        (1, MEMORY_PAYLOAD.to_vec()),
        (2, std::fs::read(disk_payload()).unwrap()),
    ] {
        let mut info = PackInfoData::default();
        info.pack_id_version.pack_uuid = uuid::Uuid::from_u128(id);
        info.pack_id_version.pack_version.version = "1.0.0".into();
        info.pack_size = wire::U64LE(payload.len() as u64);
        info.content_key = format!("synthetic-key-{id}").into();
        infos.push(info);
        contents.push(if id == 1 {
            ServerPackContent::new(payload, 6, false)
        } else {
            ServerPackContent::external(
                payload.len() as u64,
                Sha256::digest(&payload).into(),
                6,
                false,
            )
        });
    }
    ServerPackSnapshot {
        offer: packets::ResourcePacksInfo {
            resource_pack_required: true,
            resource_packs: infos,
            ..Default::default()
        },
        stack: packets::ResourcePackStack {
            texture_pack_required: true,
            texture_pack_list: [2, 1]
                .into_iter()
                .map(|id| PackInstanceId {
                    pack_id: uuid::Uuid::from_u128(id).to_string().into(),
                    version: "1.0.0".into(),
                    sub_pack_name: format!("selected-{id}").into(),
                })
                .collect(),
            base_game_version: bedrock_protocol::GAME_VERSION.into(),
            ..Default::default()
        },
        contents,
    }
}

/// One original client-selected radius, consumed only after actual pack completion.
fn radius() -> packets::RequestChunkRadius {
    packets::RequestChunkRadius {
        chunk_radius: wire::ZigZag32(8),
        max_chunk_radius: wire::U8(8),
    }
}

/// Completes actual public provider/approval/Login boundaries before advertising pack data.
fn accepted(
    snapshot: ServerPackSnapshot,
) -> (
    ServerPacks<Grant>,
    Vec<packets::Packet>,
    ClientLogin,
    Provider,
    Instant,
    SystemTime,
) {
    let (server, client, provider, now, utc) = ready_with_client();
    let (server, packets) = server
        .start_packs(
            snapshot,
            ServerPackDelivery {
                chunk_size: CHUNK_BYTES,
                ..Default::default()
            },
            &provider,
            now,
            utc,
        )
        .unwrap();
    (server, packets, client, provider, now, utc)
}

/// Retains caller-owned pipelined siblings while each original read/write continuation is consumed.
fn exchange_packs<A, L>(
    server: ServerPacks<A, L>,
    initial: Vec<packets::Packet>,
    client: ClientLogin,
    now: Instant,
) -> (
    ServerWorldReady<A, L>,
    SpawnNegotiation,
    ResourcePackHandoff,
) {
    let mut server = Some(server);
    let mut client = Some(client);
    let mut packs: Option<ClientPacks> = None;
    let mut down: VecDeque<_> = initial.into();
    let mut up = VecDeque::new();
    let mut completion = None;
    let mut saw_cache = false;
    let mut saw_external = false;
    let mut disk = std::fs::File::open(disk_payload()).unwrap();
    for _ in 0..100 {
        while let Some(packet) = down.pop_front() {
            let packet = on_wire(packet, wire::Peer::Server);
            if let Some(active) = packs.take() {
                match active.receive(packet).unwrap() {
                    PacksEvent::Send {
                        packs: active,
                        packets,
                    } => {
                        packs = Some(active);
                        up.extend(packets);
                    }
                    PacksEvent::Finished(complete) => {
                        let (spawn, response, handoff) = complete.start_spawn(radius()).unwrap();
                        completion = Some((spawn, handoff));
                        up.push_back(response.into());
                    }
                    _ => panic!("unexpected actual client pack effect"),
                }
            } else {
                match client
                    .take()
                    .expect("Login remains pending until offer")
                    .receive(packet)
                    .unwrap()
                {
                    LoginEvent::Send { login, packets } => {
                        client = Some(login);
                        up.extend(packets);
                    }
                    LoginEvent::Packs {
                        cache_status,
                        packs: offer,
                    } => {
                        if let Some(status) = cache_status {
                            up.push_back(status.into());
                        }
                        let (active, response) = offer.start().unwrap();
                        packs = Some(active);
                        up.push_back(response.into());
                    }
                    _ => panic!("unexpected actual client Login effect"),
                }
            }
        }
        let packet = on_wire(
            up.pop_front()
                .expect("pack exchange makes bounded progress"),
            wire::Peer::Client,
        );
        saw_cache |= matches!(packet, packets::Packet::ClientCacheStatus(_));
        let event = match server.take().unwrap().receive(packet, now).unwrap() {
            ServerPackEvent::ReadChunk(read) => {
                assert_eq!(read.archive_index(), 1);
                assert!(read.byte_len() <= CHUNK_BYTES as usize);
                disk.seek(SeekFrom::Start(read.offset())).unwrap();
                let mut bytes = vec![0; read.byte_len()];
                disk.read_exact(&mut bytes).unwrap();
                saw_external = true;
                ServerPackEvent::Chunk(read.supply(bytes, now).unwrap())
            }
            event => event,
        };
        match event {
            ServerPackEvent::Send { session, packets } => {
                server = Some(session);
                down.extend(packets);
            }
            ServerPackEvent::Chunk(chunk) => {
                assert!(!chunk.packet().chunk_data.is_empty());
                assert!(chunk.packet().chunk_data.len() <= CHUNK_BYTES as usize);
                down.push_back(chunk.packet().clone().into());
                // The adapter flushes the exact packet before releasing its continuation.
                let (session, next) = chunk.flushed(now).unwrap();
                server = Some(session);
                down.extend(next);
            }
            ServerPackEvent::WorldReady(world) => {
                assert!(up.is_empty() && down.is_empty());
                assert!(saw_cache);
                let (spawn, handoff) =
                    completion.expect("client applied stack before acknowledgment");
                if handoff.len() > 1 {
                    assert!(saw_external);
                }
                return (world, spawn, handoff);
            }
            _ => panic!("unexpected actual server pack effect"),
        }
    }
    panic!("bounded original pack exchange did not complete");
}

/// Caller-selected synthetic world facts; production has no fabricated/default world constructor.
fn world() -> ServerWorld {
    ServerWorld {
        start_game: Box::new(packets::StartGame {
            runtime_id: ActorRuntimeID(42),
            ..Default::default()
        }),
        items: packets::ItemRegistry::default(),
        creative: packets::CreativeContent::default(),
        max_chunk_radius: 6,
        initial_chunk_radius: None,
    }
}

/// Runs actual startup observations and original runtime-ID acknowledgment without attaching a world.
fn initialize<A, L>(
    server: ServerWorldReady<A, L>,
    mut spawn: SpawnNegotiation,
    provider: &impl crate::server::LoginPolicy<L>,
    now: Instant,
    utc: SystemTime,
) -> ServerInitialized<A, L> {
    let (server, definitions) = server.start_world(world(), provider, now, utc).unwrap();
    let mut request = None;
    let mut prepared = false;
    for packet in definitions {
        let update = spawn.receive(on_wire(packet, wire::Peer::Server)).unwrap();
        request = request.or(update.request_radius);
        if let Some(startup) = update.startup {
            assert_eq!(startup.start_game.runtime_id.0, 42);
            prepared = true;
        }
    }
    assert!(prepared);
    let ServerSpawnEvent::Send {
        session: server,
        packets: responses,
    } = server
        .receive(on_wire(request.unwrap().into(), wire::Peer::Client), now)
        .unwrap()
    else {
        panic!("missing actual initial radius/spawn")
    };
    let mut ready = None;
    let mut deferred = Vec::new();
    for packet in responses {
        if ready.is_some() {
            deferred.push(Box::new(on_wire(packet, wire::Peer::Server)));
            continue;
        }
        let update = spawn.receive(on_wire(packet, wire::Peer::Server)).unwrap();
        ready = ready.or(update.ready);
        deferred.extend(update.deferred);
    }
    let ready = ready.expect("actual original player prerequisites completed");
    assert_eq!(ready.runtime_id(), 42);
    assert!(
        matches!(deferred[0].as_ref(), packets::Packet::ChunkRadiusUpdated(radius) if radius.chunk_radius.0 == 6)
    );
    assert!(matches!(
        deferred[1].as_ref(),
        packets::Packet::CreativeContent(_)
    ));
    let ServerSpawnEvent::Initialized(server) = server
        .receive(
            on_wire(ready.finish_loading().into(), wire::Peer::Client),
            now,
        )
        .unwrap()
    else {
        panic!("missing exact actual runtime-ID initialization")
    };
    server
}

#[test]
fn typed_accepting_packs_and_spawn_preserve_memory_file_order_keys_and_original_identity() {
    let (server, initial, client, provider, now, utc) = accepted(snapshot());
    let (world, spawn, handoff) = exchange_packs(server, initial, client, now);
    assert!(handoff.required());
    let archives = handoff.into_archives();
    assert_eq!(
        archives
            .iter()
            .map(|a| a.pack_id.as_u128())
            .collect::<Vec<_>>(),
        [2, 1]
    );
    assert_eq!(archives[0].archive, std::fs::read(disk_payload()).unwrap());
    assert_eq!(archives[1].archive.as_slice(), MEMORY_PAYLOAD);
    assert_eq!(archives[0].sub_pack_name, b"selected-2");
    assert_eq!(archives[1].content_key.expose(), b"synthetic-key-1");
    let accepted = initialize(world, spawn, &provider, now, utc)
        .finish(&provider, now, utc)
        .unwrap();
    assert_eq!(accepted.login().xuid(), "123");
    assert_eq!(accepted.login().nonce(), "original-nonce");
    assert!(!accepted.client_cache_enabled());
    assert_eq!(accepted.chunk_radius(), 6);
}

/// Uses actual cached/empty-stack client acknowledgments before the world-boundary controls.
fn at_world() -> (
    ServerWorldReady<Grant>,
    SpawnNegotiation,
    Provider,
    Instant,
    SystemTime,
) {
    let (server, initial, client, provider, now, utc) = accepted(ServerPackSnapshot {
        offer: Default::default(),
        stack: Default::default(),
        contents: Vec::new(),
    });
    let (world, spawn, handoff) = exchange_packs(server, initial, client, now);
    assert!(handoff.is_empty());
    (world, spawn, provider, now, utc)
}

#[test]
fn typed_accepting_world_and_final_handoffs_revalidate_original_provider_without_reopening() {
    let (server, _, provider, now, utc) = at_world();
    provider.changed.set(true);
    let Err(failed) = server.start_world(world(), &provider, now, utc) else {
        panic!("changed identity entered a world")
    };
    let (server, error) = failed.into_parts();
    assert!(matches!(
        error,
        ServerSessionError::Login(LoginError::IdentityChanged)
    ));
    provider.changed.set(false);
    let Err(failed) = server.start_world(world(), &provider, now, utc) else {
        panic!("failed owner reopened world admission")
    };
    assert!(matches!(
        failed.into_parts().1,
        ServerSessionError::InvalidState
    ));
    let (server, _, provider, now, utc) = at_world();
    let (server, _) = server.start_world(world(), &provider, now, utc).unwrap();
    assert!(
        server
            .receive(
                packets::SetLocalPlayerAsInitialized {
                    player_id: ActorRuntimeID(99)
                }
                .into(),
                now
            )
            .is_err()
    );
    let (server, spawn, provider, now, utc) = at_world();
    let server = initialize(server, spawn, &provider, now, utc);
    provider.revoked.set(true);
    let Err(failed) = server.finish(&provider, now, utc) else {
        panic!("revoked identity completed world handoff")
    };
    let (server, error) = failed.into_parts();
    assert!(matches!(
        error,
        ServerSessionError::Login(LoginError::Authentication)
    ));
    provider.revoked.set(false);
    assert!(server.finish(&provider, now, utc).is_err());
}

/// Obtains the original external range from actual bounded client chunk requests.
fn external_read() -> (PendingServerChunkRead<Grant>, Instant) {
    let mut source = snapshot();
    source.contents[0] = ServerPackContent::external(
        MEMORY_PAYLOAD.len() as u64,
        Sha256::digest(MEMORY_PAYLOAD).into(),
        6,
        false,
    );
    let offered = source.offer.clone();
    let (server, _, _, _, now, _) = accepted(source);
    let (mut client, response) = PackOffer::new(offered, PackTransferLimits::default())
        .unwrap()
        .start()
        .unwrap();
    let ServerPackEvent::Send {
        session: server,
        packets: infos,
    } = server.receive(response.into(), now).unwrap()
    else {
        panic!("missing original external metadata")
    };
    let PackEvent::Send(mut requests) = client.receive(infos.into_iter().next().unwrap()).unwrap()
    else {
        panic!("missing actual client chunk requests")
    };
    // The Go chunk handler routes UUID only after an exact version was admitted for downloading.
    let packets::Packet::ResourcePackChunkRequest(request) = &mut requests[0] else {
        panic!("missing actual generated chunk request");
    };
    let (id, _) = request
        .resource_name
        .to_str()
        .unwrap()
        .split_once('_')
        .unwrap();
    request.resource_name = format!("{id}_{CHUNK_REQUEST_VERSION}").into();
    let ServerPackEvent::ReadChunk(read) = server.receive(requests.remove(0), now).unwrap() else {
        panic!("missing original external range")
    };
    (read, now)
}

/// Reaches a real one-chunk request through original signed Login and generated pack metadata.
fn memory_chunk_request(
    max_metadata_bytes: usize,
    requested_version: Option<&str>,
) -> (ServerPacks<Grant>, packets::Packet, Instant) {
    let mut source = snapshot();
    source.offer.resource_packs.truncate(1);
    let info = &mut source.offer.resource_packs[0];
    info.pack_size = wire::U64LE(u64::from(CHUNK_BYTES));
    let id = info.pack_id_version.pack_uuid.to_string();
    source
        .stack
        .texture_pack_list
        .retain(|pack| pack.pack_id.to_str().unwrap() == id);
    source.contents = vec![ServerPackContent::new(
        vec![0; CHUNK_BYTES as usize],
        6,
        false,
    )];
    let (server, _client, provider, now, utc) = ready_with_client();
    let (server, initial) = server
        .start_packs(
            source,
            ServerPackDelivery {
                chunk_size: CHUNK_BYTES,
                max_metadata_bytes,
                ..Default::default()
            },
            &provider,
            now,
            utc,
        )
        .unwrap();
    let offer = initial
        .into_iter()
        .find_map(|packet| match on_wire(packet, wire::Peer::Server) {
            packets::Packet::ResourcePacksInfo(offer) => Some(offer),
            _ => None,
        })
        .unwrap();
    let (mut client, response) = PackOffer::new(offer, PackTransferLimits::default())
        .unwrap()
        .start()
        .unwrap();
    let ServerPackEvent::Send {
        session: server,
        packets: infos,
    } = server
        .receive(on_wire(response.into(), wire::Peer::Client), now)
        .unwrap()
    else {
        panic!("missing original memory archive metadata")
    };
    assert_eq!(infos.len(), 1);
    let PackEvent::Send(mut requests) = client
        .receive(on_wire(
            infos.into_iter().next().unwrap(),
            wire::Peer::Server,
        ))
        .unwrap()
    else {
        panic!("missing actual memory archive chunk request")
    };
    assert_eq!(requests.len(), 1);
    let mut request = requests.remove(0);
    if let Some(version) = requested_version {
        assert!(version.len() <= PackTransferLimits::default().max_version_bytes);
        let packets::Packet::ResourcePackChunkRequest(request) = &mut request else {
            panic!("missing generated chunk request")
        };
        request.resource_name = format!("{id}_{version}").into();
    }
    (server, on_wire(request, wire::Peer::Client), now)
}

/// Measures the actual generated response, including its frame prefix and packet header.
fn chunk_frame_len(chunk: &PendingServerChunk<Grant>) -> usize {
    let mut encoded = Vec::new();
    packets::Packet::from(chunk.packet().clone())
        .encode_frame(wire::Peer::Server, 0, 0, &mut encoded)
        .unwrap();
    encoded.len()
}

#[test]
fn typed_accepting_echoed_chunk_name_respects_actual_response_wire_budget() {
    let (server, request, now) =
        memory_chunk_request(ServerPackDelivery::default().max_metadata_bytes, None);
    let ServerPackEvent::Chunk(canonical) = server.receive(request, now).unwrap() else {
        panic!("missing canonical memory chunk")
    };
    let budget = chunk_frame_len(&canonical);
    for version in [None, Some("2.0.0")] {
        let (server, request, now) = memory_chunk_request(budget, version);
        let packets::Packet::ResourcePackChunkRequest(original) = &request else {
            panic!("missing generated chunk request")
        };
        let name = original.resource_name.clone();
        let ServerPackEvent::Chunk(chunk) = server.receive(request, now).unwrap() else {
            panic!("a fitting UUID-only request must remain accepted")
        };
        assert_eq!(chunk.packet().resource_name, name);
        assert!(chunk_frame_len(&chunk) <= budget);
    }
    let (server, request, now) = memory_chunk_request(budget, Some(CHUNK_REQUEST_VERSION));
    let deadline = server.deadline();
    let grant = server.grant() as *const Grant;
    let packets::Packet::ResourcePackChunkRequest(original) = &request else {
        panic!("missing generated chunk request")
    };
    let name = original.resource_name.clone();
    match server.receive(request.clone(), now) {
        Ok(ServerPackEvent::Chunk(chunk)) => {
            assert_eq!(chunk.packet().resource_name, name);
            assert!(
                chunk_frame_len(&chunk) <= budget,
                "the actual response with its echoed request name exceeded its wire budget"
            );
        }
        Err(failed) => {
            let (server, error) = failed.into_parts();
            assert!(matches!(error, ServerSessionError::InvalidData(_)));
            assert_eq!(server.deadline(), deadline);
            assert_eq!(server.grant() as *const Grant, grant);
            assert_eq!(server.login().xuid(), "123");
            assert_eq!(server.login().nonce(), "original-nonce");
            let Err(failed) = server.receive(request, now) else {
                panic!("a failed output budget must not reopen the original owner")
            };
            assert!(matches!(
                failed.into_parts().1,
                ServerSessionError::InvalidState
            ));
        }
        _ => panic!("memory request did not retain its original chunk or failure"),
    }
}

#[test]
fn typed_external_read_checks_original_sha_length_deadline_and_sealed_failure() {
    let (read, now) = external_read();
    let Err(failed) = read.supply(vec![0; MEMORY_PAYLOAD.len()], now) else {
        panic!("wrong original SHA was emitted")
    };
    let (read, error) = failed.into_parts();
    assert!(matches!(error, ServerSessionError::InvalidData(_)));
    assert!(read.supply(MEMORY_PAYLOAD.to_vec(), now).is_err());
    let (read, now) = external_read();
    assert!(read.supply(vec![1; MEMORY_PAYLOAD.len() - 1], now).is_err());
    let (read, _) = external_read();
    let deadline = read.deadline();
    let Err(failed) = read.supply(MEMORY_PAYLOAD.to_vec(), deadline) else {
        panic!("late read reset the original deadline")
    };
    assert!(matches!(
        failed.into_parts().1,
        ServerSessionError::TimedOut
    ));
    let (read, now) = external_read();
    let chunk = read.supply(MEMORY_PAYLOAD.to_vec(), now).unwrap();
    assert_eq!(chunk.packet().chunk_data.as_ref(), MEMORY_PAYLOAD);
    assert!(
        chunk
            .packet()
            .resource_name
            .to_str()
            .unwrap()
            .ends_with(CHUNK_REQUEST_VERSION)
    );
    let deadline = chunk.deadline();
    let Err(failed) = chunk.flushed(deadline) else {
        panic!("late actual flush reset its original deadline")
    };
    assert!(matches!(
        failed.into_parts().1,
        ServerSessionError::TimedOut
    ));
    let (read, now) = external_read();
    let chunk = read.supply(MEMORY_PAYLOAD.to_vec(), now).unwrap();
    assert_eq!(
        chunk.flushed(now).unwrap().1.len(),
        1,
        "next original metadata follows actual flush"
    );
}

mod count_limits;

#[test]
fn empty_pack_download_list_preserves_the_original_exchange() {
    let (server, initial, client, _provider, now, _utc) = accepted(snapshot());
    let ServerPackEvent::Send { session, packets } = server
        .receive(
            on_wire(
                packets::ResourcePackClientResponse {
                    response:
                        bedrock_protocol::types::ResourcePackClientResponseData::Downloading {
                            response_type: "downloading".into(),
                            downloading_packs: Vec::new(),
                        },
                }
                .into(),
                wire::Peer::Client,
            ),
            now,
        )
        .unwrap()
    else {
        panic!("empty selection must preserve the offer");
    };
    assert!(packets.is_empty());
    let (_, _, handoff) = exchange_packs(session, initial, client, now);
    assert_eq!(handoff.len(), 2);
}

#[test]
fn acquired_repeated_stack_rows_relay_through_the_accepting_owner() {
    for required in [false, true] {
        for version in [
            bytes::Bytes::new(),
            bytes::Bytes::from(vec![b'v'; 257]),
            bytes::Bytes::from_static(b"\xff"),
            bytes::Bytes::from_static(b"1.0.0"),
        ] {
            let id = uuid::Uuid::from_u128(1);
            let mut info = PackInfoData::default();
            info.pack_id_version.pack_uuid = id;
            info.pack_id_version.pack_version.version = version.clone().into();
            info.pack_size = wire::U64LE(3);
            let mut offer = PackOffer::new_with_metadata(
                packets::ResourcePacksInfo {
                    resource_packs: vec![info],
                    ..Default::default()
                },
                PackTransferLimits::default(),
            )
            .unwrap();
            offer.supply_preloaded(id, b"abc".to_vec()).unwrap();
            let (mut client, _) = offer.start().unwrap();
            let row = PackInstanceId {
                pack_id: id.to_string().into(),
                version: version.into(),
                ..Default::default()
            };
            let PackEvent::Finished(complete) = client
                .receive(
                    packets::ResourcePackStack {
                        texture_pack_required: required,
                        texture_pack_list: vec![row.clone(), row],
                        ..Default::default()
                    }
                    .into(),
                )
                .unwrap()
            else {
                panic!("acquired stack completes");
            };
            let (_, handoff, metadata) = complete.into_parts_with_metadata();
            let metadata = metadata.unwrap();
            let source = ServerPackSnapshot {
                offer: metadata.offer,
                stack: metadata.stack,
                contents: handoff
                    .into_archives()
                    .into_iter()
                    .map(|archive| ServerPackContent::new(archive.archive, 6, false))
                    .collect(),
            };
            let (server, initial, client, _provider, now, _utc) = accepted(source);
            let (_, _, handoff) = exchange_packs(server, initial, client, now);
            assert_eq!(handoff.len(), 1);
        }
    }
}
