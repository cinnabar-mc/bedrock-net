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

use bedrock_client::handshake::{ClientHandshake, HandshakeOptions};
use bedrock_client::spawn::SpawnNegotiation;
use bedrock_client_tokio::{
    connection::Connection,
    error::NegotiationError,
    handshake::{self, LoginData, Observation},
    packs::{self as pack_driver, InBand},
};
use bedrock_net::BatchLimits;
use bedrock_net::login::OfflineIdentity;
use bedrock_protocol::{
    packets,
    wire::{self, Peer},
};
use serde_json::Value;

use crate::{HANDSHAKE_TIMEOUT, PROBE_NAME, PROBE_UUID, client_data, is_login_success};

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

/// Observes the actual driver reads/effects without replacing their packets or authority.
fn observe(observed: &mut Observed, event: Observation<'_>) {
    match event {
        Observation::Unknown(header) => observed.unknown_ids.push(header.id),
        Observation::Received(_, packet) => observed.login_success |= is_login_success(packet),
        Observation::Sent(packets) if observed.initial_requests == 0 => {
            observed.initial_requests = packets
                .iter()
                .filter(|packet| matches!(packet, packets::Packet::ResourcePackChunkRequest(_)))
                .count();
        }
        Observation::Sent(_) => {}
    }
}

/// Keeps real server terminal observations in the probe's original comparison vocabulary.
fn terminal(error: NegotiationError, observed: &mut Observed) -> Result<(), Box<dyn Error>> {
    match error {
        NegotiationError::Disconnect(disconnect) => {
            observed.unhandled.push("Disconnect".into());
            observed.disconnect = Some(format!("{:?}", disconnect.messages));
            Ok(())
        }
        NegotiationError::Transfer(_) => {
            observed.unhandled.push("Transfer".into());
            Ok(())
        }
        error => Err(error.into()),
    }
}

/// Uses the original generated decoder and records unknown IDs before continuing.
async fn next_packet(
    session: &mut Connection,
    observed: &mut Observed,
) -> Result<packets::Packet, Box<dyn Error>> {
    Ok(session
        .next_packet_observed(&mut |event| observe(observed, event))
        .await?
        .1)
}

/// Runs Login, packs and startup with the probe's session until the server ends the connection.
async fn join(
    address: SocketAddr,
    observed: &mut Observed,
    deadline: tokio::time::Instant,
) -> Result<(), Box<dyn Error>> {
    let (transport, key) = crate::transport::connect("raknet", address, deadline).await?;
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
    let (ready, compression) = handshake::settings(&mut session, configured, &mut |event| {
        observe(observed, event)
    })
    .await?;
    observed.compression = Some(format!("{:?}", compression.algorithm));
    let metadata = client_data("raknet", address, session.transport().nonce())?;
    let result = handshake::login(
        &mut session,
        ready,
        LoginData::Offline {
            identity: OfflineIdentity {
                display_name: PROBE_NAME,
                identity: PROBE_UUID,
                xuid: "",
                playfab_id: "",
                playfab_title_id: "",
            },
            claims: &metadata,
            now: SystemTime::now(),
        },
        &mut |event| observe(observed, event),
    )
    .await;
    observed.encrypted |= session.has_batch_ciphers();
    let outcome = match result {
        Ok(Some(offer)) => login_phase(&mut session, offer, observed).await,
        Ok(None) => {
            observed.packless_startup = true;
            Ok(())
        }
        Err(error) => terminal(error, observed),
    };
    let closed = session.transport_mut().finish_close().await;
    outcome?;
    closed.map_err(Into::into)
}

/// Preserves the original late `LoginSuccess` wait before starting actual pack acquisition.
async fn login_phase(
    session: &mut Connection,
    mut offer: bedrock_client::handshake::ClientPackOffer,
    observed: &mut Observed,
) -> Result<(), Box<dyn Error>> {
    while !observed.login_success {
        let result =
            handshake::offer_control(session, offer, &mut |event| observe(observed, event)).await;
        observed.encrypted |= session.has_batch_ciphers();
        offer = match result {
            Ok(offer) => offer,
            Err(error) => return terminal(error, observed),
        };
    }
    let result = pack_driver::acquire(session, offer, &mut InBand, &mut |event| {
        observe(observed, event)
    })
    .await;
    observed.encrypted |= session.has_batch_ciphers();
    let acquired = match result {
        Ok(acquired) => acquired,
        Err(error) => return terminal(error, observed),
    };
    observed.archives = acquired
        .handoff
        .into_archives()
        .iter()
        .map(|pack| pack.archive.len())
        .collect();
    let mut spawn = SpawnNegotiation::new(packets::RequestChunkRadius {
        chunk_radius: wire::ZigZag32(4),
        max_chunk_radius: wire::U8(4),
    })?;
    session.replay_deferred();
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
        let deadline = tokio::time::Instant::now() + HANDSHAKE_TIMEOUT;
        tokio::time::timeout_at(deadline, join(helper.address, &mut observed, deadline)).await
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

/// A stack received during the original late-Login wait must complete without another stack.
#[test]
fn pack_stack_before_login_success_is_replayed_once() {
    let Some((observed, _, verdict)) = scenario("pack-stack-before-login-success") else {
        return;
    };
    assert_eq!(verdict["result"], "ok", "{verdict}; {observed:?}");
    assert!(observed.login_success && observed.unhandled.is_empty());
}
