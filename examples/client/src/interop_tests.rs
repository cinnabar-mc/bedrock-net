//! Joins the probe's own session and owners against a pinned gophertunnel server.
//!
//! `BEDROCK_NET_GO_INTEROP` names the `tools/go-oracle/cmd/interop-server` helper. Each
//! scenario's observations are compared with what a Go Dialer does; mismatches must be
//! listed in [`EXPECTED_DIVERGENCES`] and listed entries must still diverge.

use std::error::Error;
use std::io::{BufRead, BufReader};
use std::net::SocketAddr;
use std::process::{Child, ChildStdout, Command, Stdio};
use std::time::SystemTime;

use bedrock_client::handshake::{
    ClientHandshake, ClientLogin, HandshakeOptions, LoginEvent, OfferEvent, PacksEvent,
};
use bedrock_client::spawn::SpawnNegotiation;
use bedrock_net::BatchLimits;
use bedrock_net::login::OfflineIdentity;
use bedrock_protocol::{
    packets,
    wire::{self, PacketHeader, Peer, Reader},
};
use serde_json::Value;

use bedrock_client_tokio::connection::Connection;

use crate::{
    HANDSHAKE_TIMEOUT, PROBE_NAME, PROBE_UUID, apply_exchange, client_data, is_login_success,
    receive_settings, send_responses,
};

/// Known differences from a Go Dialer, each naming its audit item.
const EXPECTED_DIVERGENCES: &[(&str, &str)] = &[];

/// One running helper and the defaults it reported.
struct Helper {
    child: Child,
    lines: BufReader<ChildStdout>,
    address: SocketAddr,
    go: Value,
}

impl Helper {
    fn start(scenario: &str) -> Option<Self> {
        let Some(binary) = std::env::var_os("BEDROCK_NET_GO_INTEROP") else {
            // CI sets BEDROCK_NET_REQUIRE_FIXTURES so a dropped helper fails instead of skipping.
            assert!(
                std::env::var_os("BEDROCK_NET_REQUIRE_FIXTURES").is_none(),
                "missing fixture: BEDROCK_NET_GO_INTEROP; build tools/go-oracle/cmd/interop-server"
            );
            eprintln!(
                "missing fixture: BEDROCK_NET_GO_INTEROP; build tools/go-oracle/cmd/interop-server"
            );
            return None;
        };
        let mut child = Command::new(binary)
            .arg(scenario)
            .stdout(Stdio::piped())
            .spawn()
            .expect("start the interop server");
        let mut lines = BufReader::new(child.stdout.take().unwrap());
        let go = next_line(&mut lines);
        let address = go["address"].as_str().unwrap().parse().unwrap();
        Some(Self {
            child,
            lines,
            address,
            go,
        })
    }

    /// Waits for the helper's own verdict on the connection.
    fn finish(mut self) -> Value {
        let result = next_line(&mut self.lines);
        self.child.wait().unwrap();
        result
    }
}

fn next_line(lines: &mut BufReader<ChildStdout>) -> Value {
    let mut line = String::new();
    lines.read_line(&mut line).unwrap();
    serde_json::from_str(&line).unwrap_or_else(|_| panic!("helper line: {line:?}"))
}

/// What the client saw, in the terms a Go Dialer's behaviour is stated in.
#[derive(Default, Debug)]
struct Observed {
    compression: Option<String>,
    encrypted: bool,
    login_success: bool,
    initial_requests: usize,
    archives: Vec<usize>,
    spawned: bool,
    unknown_ids: Vec<u32>,
    disconnect: Option<String>,
    unhandled: Vec<String>,
    packless_startup: bool,
}

/// Decodes the next known server packet; unknown IDs are recorded, as no generated packet holds them.
async fn next_packet(
    session: &mut Connection,
    observed: &mut Observed,
) -> Result<packets::Packet, Box<dyn Error>> {
    loop {
        let bytes = session.next_raw().await?;
        let mut reader = Reader::from_shared(&bytes);
        let header = PacketHeader::from_raw(reader.read_var_u32()?);
        if packets::PacketId::from_raw(header.id).is_none() {
            observed.unknown_ids.push(header.id);
            continue;
        }
        return Ok(packets::Packet::decode_from(
            header.id,
            Peer::Server,
            &mut reader,
        )?);
    }
}

fn name(packet: &packets::Packet) -> String {
    format!("{:?}", packet.id())
}

/// Runs Login, packs and startup with the probe's session until the server ends the connection.
async fn join(address: SocketAddr, observed: &mut Observed) -> Result<(), Box<dyn Error>> {
    let (transport, key) = crate::transport::connect("raknet", address).await?;
    let configured = ClientHandshake::new(
        key,
        HandshakeOptions {
            batch_encryption: transport.batch_encryption(),
            max_login_bytes: BatchLimits::default().max_decoded_bytes,
            ..Default::default()
        },
    )?;
    let mut session = Connection::new(
        transport,
        BatchLimits::default(),
        bedrock_protocol::wire::Limits::receiving_from(Peer::Server),
        BatchLimits::default().max_decoded_bytes,
    );
    let (settings, request) = configured.start()?;
    session
        .send_packet(&request.into(), Peer::Client, 0, 0)
        .await?;
    let (ready, compression) = receive_settings(&mut session, settings).await?;
    observed.compression = Some(format!("{:?}", compression.algorithm));
    session.enable_compression(compression)?;
    let metadata = client_data("raknet", address, session.transport().nonce())?;
    let (login, request) = ready.login_offline(
        &OfflineIdentity {
            display_name: PROBE_NAME,
            identity: PROBE_UUID,
            xuid: "",
            playfab_id: "",
            playfab_title_id: "",
        },
        &metadata,
        SystemTime::now(),
    )?;
    session
        .send_packet(&request.into(), Peer::Client, 0, 0)
        .await?;
    login_phase(&mut session, login, observed).await?;
    session
        .transport_mut()
        .finish_close()
        .await
        .map_err(Into::into)
}

async fn login_phase(
    session: &mut Connection,
    mut login: ClientLogin,
    observed: &mut Observed,
) -> Result<(), Box<dyn Error>> {
    let mut offer = loop {
        let packet = next_packet(session, observed).await?;
        observed.login_success |= is_login_success(&packet);
        match login.receive(packet)? {
            LoginEvent::Send {
                login: next,
                packets,
            } => {
                send_responses(session, packets).await?;
                login = next;
            }
            LoginEvent::KeyExchange(exchange) => {
                let (next, installed) = apply_exchange(session, exchange).await?;
                observed.encrypted |= installed;
                login = next;
            }
            LoginEvent::Packs {
                cache_status,
                packs,
            } => {
                if let Some(status) = cache_status {
                    session
                        .send_packet(&status.into(), Peer::Client, 0, 0)
                        .await?;
                }
                break packs;
            }
            // Startup without a pack phase; the scenario sends nothing further.
            LoginEvent::Startup { .. } => {
                observed.packless_startup = true;
                return Ok(());
            }
            // Terminal or out-of-phase input stays with the caller; the scenario ends here.
            LoginEvent::Unhandled { packet, .. } => {
                observed.unhandled.push(name(&packet));
                if let packets::Packet::Disconnect(disconnect) = *packet {
                    observed.disconnect = Some(format!("{:?}", disconnect.messages));
                }
                return Ok(());
            }
        }
    };
    while !observed.login_success {
        let packet = next_packet(session, observed).await?;
        observed.login_success |= is_login_success(&packet);
        match offer.receive_control(packet)? {
            OfferEvent::Send {
                offer: next,
                packets,
            } => {
                send_responses(session, packets).await?;
                offer = next;
            }
            OfferEvent::KeyExchange(exchange) => {
                let (next, installed) = apply_exchange(session, exchange).await?;
                observed.encrypted |= installed;
                offer = next;
            }
            OfferEvent::Unhandled { packet, .. } => {
                observed.unhandled.push(name(&packet));
                return Ok(());
            }
        }
    }
    let (mut packs, response) = offer.start()?;
    session
        .send_packet(&response.into(), Peer::Client, 0, 0)
        .await?;
    let mut first_send = true;
    let mut deferred_stacks: std::collections::VecDeque<Box<packets::ResourcePackStack>> =
        std::collections::VecDeque::new();
    let complete = loop {
        let packet = if packs.ready_for_stack() && !deferred_stacks.is_empty() {
            packets::Packet::ResourcePackStack(*deferred_stacks.pop_front().unwrap())
        } else {
            next_packet(session, observed).await?
        };
        match packs.receive(packet)? {
            PacksEvent::Send {
                packs: next,
                packets,
            } => {
                let requests = packets
                    .iter()
                    .filter(|p| matches!(p, packets::Packet::ResourcePackChunkRequest(_)))
                    .count();
                if first_send && requests != 0 {
                    observed.initial_requests = requests;
                    first_send = false;
                }
                send_responses(session, packets).await?;
                packs = next;
            }
            PacksEvent::KeyExchange(exchange) => {
                let (next, installed) = apply_exchange(session, exchange).await?;
                observed.encrypted |= installed;
                packs = next;
            }
            PacksEvent::DeferredStack { packs: next, stack } => {
                deferred_stacks.push_back(stack);
                packs = next;
            }
            PacksEvent::Finished(complete) => break complete,
            PacksEvent::Unhandled { packet, .. } => {
                observed.unhandled.push(name(&packet));
                return Ok(());
            }
        }
    };
    let (mut spawn, response, handoff) = complete.start_spawn(packets::RequestChunkRadius {
        chunk_radius: wire::ZigZag32(4),
        max_chunk_radius: wire::U8(4),
    })?;
    observed.archives = handoff
        .into_archives()
        .iter()
        .map(|pack| pack.archive.len())
        .collect();
    session
        .send_packet(&response.into(), Peer::Client, 0, 0)
        .await?;
    spawn_phase(session, &mut spawn, observed).await
}

async fn spawn_phase(
    session: &mut Connection,
    spawn: &mut SpawnNegotiation,
    observed: &mut Observed,
) -> Result<(), Box<dyn Error>> {
    loop {
        let packet = next_packet(session, observed).await?;
        if let packets::Packet::Disconnect(disconnect) = &packet {
            observed.disconnect = Some(format!("{:?}", disconnect.messages));
            return Ok(());
        }
        if observed.spawned {
            continue;
        }
        let update = spawn.receive(packet)?;
        if let Some(radius) = update.request_radius {
            session
                .send_packet(&radius.into(), Peer::Client, 0, 0)
                .await?;
        }
        if let Some(ready) = update.ready {
            session
                .send_packet(&ready.finish_loading().into(), Peer::Client, 0, 0)
                .await?;
            observed.spawned = true;
        }
    }
}

/// Runs one scenario and returns the client's observations with the helper's verdict.
fn scenario(name: &str) -> Option<(Observed, Value, Value)> {
    let helper = Helper::start(name)?;
    let mut observed = Observed::default();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let joined = runtime.block_on(async {
        tokio::time::timeout(HANDSHAKE_TIMEOUT, join(helper.address, &mut observed)).await
    });
    let go = helper.go.clone();
    let verdict = helper.finish();
    match joined {
        Ok(Ok(())) => {}
        Ok(Err(error)) => panic!("{name}: client failed: {error}; observed {observed:?}"),
        Err(_) => panic!("{name}: client timed out; observed {observed:?}"),
    }
    Some((observed, go, verdict))
}

#[derive(Default)]
struct Ledger {
    unexpected: Vec<String>,
    seen: Vec<&'static str>,
}

impl Ledger {
    /// `go` is what a Go Dialer would observe; `rust` is what the probe observed.
    fn compare<T: PartialEq + std::fmt::Debug>(&mut self, name: &str, go: T, rust: T) {
        let listed = EXPECTED_DIVERGENCES.iter().find(|(case, _)| *case == name);
        match (go == rust, listed) {
            (true, None) => {}
            (false, Some((case, _))) => self.seen.push(case),
            (true, Some(_)) => self.unexpected.push(format!(
                "{name}: now matches Go; remove its divergence entry"
            )),
            (false, None) => self
                .unexpected
                .push(format!("{name}: Go {go:?} != Rust {rust:?}")),
        }
    }

    fn finish(self, prefix: &str) {
        let missing: Vec<_> = EXPECTED_DIVERGENCES
            .iter()
            .filter(|(case, _)| case.starts_with(prefix) && !self.seen.contains(case))
            .collect();
        assert!(
            self.unexpected.is_empty() && missing.is_empty(),
            "unexpected: {:#?}\nlisted but not diverging: {missing:?}",
            self.unexpected
        );
    }
}

/// A Listener join that spawns: Login, encryption and the server's compression choice.
fn spawned_join(name: &str, compression: &str) {
    let Some((observed, _, verdict)) = scenario(name) else {
        return;
    };
    assert_eq!(verdict["result"], "ok", "{name}: {verdict}; {observed:?}");
    assert_eq!(observed.compression.as_deref(), Some(compression));
    assert!(observed.encrypted && observed.login_success && observed.spawned);
}

#[test]
fn flate_listener_join_spawns() {
    spawned_join("flate", "Deflate");
}

#[test]
fn snappy_listener_join_spawns() {
    spawned_join("snappy", "Snappy");
}

#[test]
fn threshold_listener_join_spawns() {
    spawned_join("threshold", "Deflate");
}

#[test]
fn chunked_pack_is_downloaded() {
    let Some((observed, go, verdict)) = scenario("chunk-pack") else {
        return;
    };
    assert_eq!(verdict["result"], "ok", "{verdict}; {observed:?}");
    assert!(observed.spawned && observed.archives.len() == 1);
    let chunks = go["pack_chunk_count"].as_u64().unwrap() as usize;
    let window = go["request_window"].as_u64().unwrap() as usize;
    assert!(
        chunks > window,
        "the pack must span more chunks than Go's request window"
    );
    // Check the configured default as well as the independently reported Go window.
    let rust_window = bedrock_client::packs::DEFAULT_REQUEST_WINDOW as usize;
    assert_eq!(observed.initial_requests, chunks.min(rust_window));
    let mut ledger = Ledger::default();
    ledger.compare(
        "chunk-pack/initial_requests",
        chunks.min(window),
        observed.initial_requests,
    );
    ledger.finish("chunk-pack/");
    // The session hands the caller raw bytes for IDs no generated packet represents.
    assert_eq!(observed.unknown_ids, [0x3ff]);
}

#[test]
fn url_pack_falls_back_to_chunks() {
    let Some((observed, _, verdict)) = scenario("url-pack") else {
        return;
    };
    assert_eq!(verdict["result"], "ok", "{verdict}; {observed:?}");
    assert!(observed.spawned && observed.archives.len() == 1);
}

#[test]
fn start_game_without_pack_phase() {
    let Some((observed, _, _)) = scenario("startgame-without-packs") else {
        return;
    };
    // A Go Dialer starts the game from this StartGame; so does the Rust Login owner.
    assert!(
        observed.packless_startup && observed.unhandled.is_empty(),
        "{observed:?}"
    );
}

#[test]
fn pack_offer_before_login_success() {
    let Some((observed, _, verdict)) = scenario("packs-info-before-login-success") else {
        return;
    };
    assert_eq!(verdict["result"], "ok", "{verdict}; {observed:?}");
    assert!(observed.login_success && observed.unhandled.is_empty());
}

#[test]
fn transfer_before_login_success_reaches_the_caller() {
    let Some((observed, _, _)) = scenario("transfer-before-login-success") else {
        return;
    };
    assert_eq!(observed.unhandled, ["Transfer"]);
}

#[test]
fn disconnect_before_login_success_reaches_the_caller() {
    let Some((observed, _, _)) = scenario("disconnect-before-login-success") else {
        return;
    };
    assert_eq!(observed.unhandled, ["Disconnect"]);
    assert!(observed.disconnect.unwrap().contains("interop refused"));
}
