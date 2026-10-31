//! Joins the probe's own session and owners against a pinned gophertunnel server.
//!
//! `BEDROCK_NET_GO_INTEROP` names the `tools/go-oracle/cmd/interop-server` helper. Each
//! scenario's observations are compared with what a Go Dialer does; mismatches must be
//! listed in [`EXPECTED_DIVERGENCES`] and listed entries must still diverge.

use std::error::Error;
use std::io::{self, BufRead, BufReader, Read};
use std::net::SocketAddr;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::{self, Receiver};
use std::time::{Duration, Instant, SystemTime};

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

/// Kills and reaps the exact helper on errors, early returns and unwinding.
struct HelperChild(Child);

impl Drop for HelperChild {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// One running helper and its first absolute lifecycle cutoff.
struct Helper {
    child: HelperChild,
    lines: Receiver<io::Result<Value>>,
    address: SocketAddr,
    go: Value,
    deadline: Instant,
}

impl Helper {
    /// Starts the caller-selected fixture under the same cutoff as negotiation.
    fn start(scenario: &str) -> Option<Self> {
        let Some(binary) = std::env::var_os("BEDROCK_NET_GO_INTEROP") else {
            assert!(
                std::env::var_os("BEDROCK_NET_REQUIRE_FIXTURES").is_none(),
                "missing fixture: BEDROCK_NET_GO_INTEROP; build tools/go-oracle/cmd/interop-server"
            );
            return None;
        };
        let mut command = Command::new(binary);
        command.arg(scenario);
        Some(
            Self::spawn(command, Instant::now() + HANDSHAKE_TIMEOUT)
                .expect("start the interop server"),
        )
    }

    /// Owns the child before reading any output, so malformed readiness cannot leak it.
    fn spawn(mut command: Command, deadline: Instant) -> io::Result<Self> {
        let child = command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()?;
        Self::from_child(child, deadline)
    }

    /// Moves blocking pipe reads onto one bounded channel while retaining exact child cleanup.
    fn from_child(child: Child, deadline: Instant) -> io::Result<Self> {
        let mut child = HelperChild(child);
        let stdout = child.0.stdout.take().expect("piped helper stdout");
        let (send, lines) = mpsc::sync_channel(1);
        std::thread::spawn(move || {
            let mut reader = BufReader::new(stdout);
            loop {
                let mut line = String::new();
                let result = reader
                    .by_ref()
                    .take(1024 * 1024 + 1)
                    .read_line(&mut line)
                    .and_then(|length| {
                        if length == 0 {
                            return Err(io::ErrorKind::UnexpectedEof.into());
                        }
                        if length > 1024 * 1024 {
                            return Err(io::ErrorKind::InvalidData.into());
                        }
                        serde_json::from_str(&line).map_err(io::Error::other)
                    });
                let failed = result.is_err();
                if send.send(result).is_err() || failed {
                    break;
                }
            }
        });
        let go = next_line(&lines, deadline)?;
        let address = go["address"]
            .as_str()
            .and_then(|text| text.parse().ok())
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid helper address"))?;
        Ok(Self {
            child,
            lines,
            address,
            go,
            deadline,
        })
    }

    /// Bounds verdict and process exit; dropping this owner always reaps its exact child.
    fn finish(mut self) -> io::Result<Value> {
        let verdict = next_line(&self.lines, self.deadline)?;
        loop {
            if let Some(status) = self.child.0.try_wait()? {
                return if status.success() {
                    Ok(verdict)
                } else {
                    Err(io::Error::other("interop helper failed"))
                };
            }
            let remaining = self.deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(io::ErrorKind::TimedOut.into());
            }
            std::thread::park_timeout(remaining.min(Duration::from_millis(10)));
        }
    }
}

/// Receives one bounded JSON record under the original lifecycle cutoff.
fn next_line(lines: &Receiver<io::Result<Value>>, deadline: Instant) -> io::Result<Value> {
    lines
        .recv_timeout(deadline.saturating_duration_since(Instant::now()))
        .map_err(|error| {
            io::Error::from(match error {
                mpsc::RecvTimeoutError::Timeout => io::ErrorKind::TimedOut,
                mpsc::RecvTimeoutError::Disconnected => io::ErrorKind::UnexpectedEof,
            })
        })?
}

/// What the client saw, in the terms a Go Dialer's behaviour is stated in.
#[derive(Default, Debug)]
struct Observed {
    compression: Option<String>,
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
    let (transport, key) = crate::transport::connect("nethernet", address, deadline).await?;
    let configured = ClientHandshake::new(
        key,
        HandshakeOptions {
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
    let metadata = client_data("nethernet", address, session.transport().nonce())?;
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

    let outcome = match result {
        Ok(Some(offer)) => login_phase(&mut session, offer, observed).await,
        Ok(None) => {
            observed.packless_startup = true;
            start_spawn(&mut session, observed).await
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

        offer = match result {
            Ok(offer) => offer,
            Err(error) => return terminal(error, observed),
        };
    }
    let result = pack_driver::acquire(session, offer, &mut InBand, &mut |event| {
        observe(observed, event)
    })
    .await;

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
    start_spawn(session, observed).await
}

/// Replays the original startup prefix after either Login handoff reaches world negotiation.
async fn start_spawn(
    session: &mut Connection,
    observed: &mut Observed,
) -> Result<(), Box<dyn Error>> {
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
        let deadline = helper.deadline.into();
        tokio::time::timeout_at(deadline, join(helper.address, &mut observed, deadline)).await
    });
    let go = helper.go.clone();
    match joined {
        Ok(Ok(())) => {}
        Ok(Err(error)) => panic!("{name}: client failed: {error}; observed {observed:?}"),
        Err(_) => panic!("{name}: client timed out; observed {observed:?}"),
    }
    let verdict = helper
        .finish()
        .unwrap_or_else(|error| panic!("{name}: helper failed: {error}"));
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

/// A Listener join that spawns: Login and the server's compression choice.
fn spawned_join(name: &str, compression: &str) {
    let Some((observed, _, verdict)) = scenario(name) else {
        return;
    };
    assert_eq!(verdict["result"], "ok", "{name}: {verdict}; {observed:?}");
    assert_eq!(observed.compression.as_deref(), Some(compression));
    assert!(observed.login_success && observed.spawned);
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
    let Some((observed, _, verdict)) = scenario("startgame-without-packs") else {
        return;
    };
    assert_eq!(verdict["result"], "ok", "{verdict}; {observed:?}");
    assert!(
        observed.packless_startup && observed.spawned && observed.unhandled.is_empty(),
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

#[cfg(unix)]
#[test]
fn stalled_helpers_time_out_and_are_reaped_at_every_lifecycle_stage() {
    for stage in ["startup", "verdict", "exit", "invalid"] {
        let mut command = Command::new("sh");
        let output = match stage {
            "startup" => "",
            "invalid" => "printf '{\"address\":false}\\n';",
            "verdict" => "printf '{\"address\":\"127.0.0.1:1\"}\\n';",
            _ => "printf '{\"address\":\"127.0.0.1:1\"}\\n{}\\n';",
        };
        command.arg("-c").arg(format!("{output} read waiting"));
        let child = command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let pid = child.id();
        let helper = Helper::from_child(child, Instant::now() + Duration::from_millis(200));
        let error = match helper {
            Ok(helper) => helper.finish().unwrap_err(),
            Err(error) => error,
        };
        assert_eq!(
            error.kind(),
            if stage == "invalid" {
                io::ErrorKind::InvalidData
            } else {
                io::ErrorKind::TimedOut
            },
            "{stage}"
        );
        assert!(
            !Command::new("kill")
                .args(["-0", &pid.to_string()])
                .stderr(Stdio::null())
                .status()
                .unwrap()
                .success(),
            "helper {pid} was not reaped"
        );
    }
}
