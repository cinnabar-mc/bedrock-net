//! Differential checks against the pinned Go codec through one long-lived `go-oracle serve`.
//!
//! Every case compares Rust's accept/drop/fatal decision and bytes with Go's. A mismatch must
//! be listed in [`EXPECTED_DIVERGENCES`], and a listed entry must still diverge.

use std::io::{Read, Write};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::{Mutex, OnceLock};

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use bedrock_net::encryption::{BatchDecryptor, BatchEncryptor};
use bedrock_net::{
    BatchCodec, BatchHeader, BatchLimits, BatchPhase, CompressionAlgorithm, CompressionSettings,
    DecodeOutcome,
};
use bytes::{Bytes, BytesMut};
use serde_json::{Value, json};

/// Known Go/Rust differences: case, the Rust result's [`Summary`], and its audit item.
/// A listed case must still diverge with exactly that Rust result; a fix must remove it here.
const EXPECTED_DIVERGENCES: &[(&str, &str, &str)] = &[
    // Audit A "readBatch, empty transport message": Go skips it, Rust is fatal.
    ("decode/empty_message", "fatal", "empty transport message"),
    (
        "decode/encrypted_empty_message",
        "fatal",
        "empty transport message",
    ),
    // Audit stricter-limits list: incoming wire messages over 32 MiB are fatal.
    (
        "decode/wire_over_32mib",
        "fatal",
        "max_encoded_bytes wire cap",
    ),
    // Audit stricter-limits list: outgoing batches split at 16 MiB; Go has no outgoing cap.
    ("encode/split_16mib", "2", "outgoing 16 MiB split"),
    // NEW: Go keeps the low 32 bits of a five-byte length whose last byte overflows.
    (
        "decode/length_overflow_fifth_byte",
        "fatal",
        "NEW: varuint32 overflow",
    ),
    // NEW: Go's accepting decoder rejects empty entries; Rust skips them in both directions.
    (
        "decode/accepting_empty_entry",
        "packets(1)",
        "NEW: accepting empty entries",
    ),
];

/// A short description of a result, so a listed divergence cannot silently change shape.
trait Summary {
    fn summary(&self) -> String;
}

impl Summary for Vec<Outcome> {
    fn summary(&self) -> String {
        let parts: Vec<_> = self
            .iter()
            .map(|outcome| match outcome {
                Outcome::Packets(packets) => format!("packets({})", packets.len()),
                Outcome::Dropped => "dropped".into(),
                Outcome::Fatal => "fatal".into(),
            })
            .collect();
        parts.join(",")
    }
}

/// Frames written per encode call.
impl Summary for Vec<Vec<Vec<u8>>> {
    fn summary(&self) -> String {
        let parts: Vec<_> = self.iter().map(|call| call.len().to_string()).collect();
        parts.join(",")
    }
}

impl Summary for Vec<(u8, Vec<Outcome>)> {
    fn summary(&self) -> String {
        let parts: Vec<_> = self
            .iter()
            .map(|(marker, outcomes)| format!("{marker:#04x}:{}", outcomes.summary()))
            .collect();
        parts.join(",")
    }
}

impl Summary for bool {
    fn summary(&self) -> String {
        if *self { "accept" } else { "reject" }.into()
    }
}

const KEY: [u8; 32] = [7; 32];

struct Oracle {
    _child: Child,
    stdin: ChildStdin,
    stdout: ChildStdout,
}

impl Oracle {
    fn call(&mut self, request: Value) -> Value {
        let request = serde_json::to_vec(&request).unwrap();
        self.stdin
            .write_all(&(request.len() as u32).to_le_bytes())
            .unwrap();
        self.stdin.write_all(&request).unwrap();
        self.stdin.flush().unwrap();
        let mut size = [0; 4];
        self.stdout.read_exact(&mut size).unwrap();
        let mut response = vec![0; u32::from_le_bytes(size) as usize];
        self.stdout.read_exact(&mut response).unwrap();
        let response: Value = serde_json::from_slice(&response).unwrap();
        assert!(response.get("error").is_none(), "oracle error: {response}");
        response
    }
}

/// Starts the shared oracle once per test binary, or reports the missing fixture.
fn oracle() -> Option<std::sync::MutexGuard<'static, Oracle>> {
    static ORACLE: OnceLock<Option<Mutex<Oracle>>> = OnceLock::new();
    let oracle = ORACLE.get_or_init(|| {
        let binary = std::env::var_os("BEDROCK_NET_GO_ORACLE")?;
        let mut child = Command::new(binary)
            .arg("serve")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .expect("start go-oracle serve");
        Some(Mutex::new(Oracle {
            stdin: child.stdin.take().unwrap(),
            stdout: child.stdout.take().unwrap(),
            _child: child,
        }))
    });
    match oracle {
        Some(oracle) => Some(oracle.lock().unwrap_or_else(|poison| poison.into_inner())),
        None => {
            // CI sets BEDROCK_NET_REQUIRE_FIXTURES so a dropped helper fails instead of skipping.
            assert!(
                std::env::var_os("BEDROCK_NET_REQUIRE_FIXTURES").is_none(),
                "missing fixture: BEDROCK_NET_GO_ORACLE; build tools/go-oracle"
            );
            eprintln!("missing fixture: BEDROCK_NET_GO_ORACLE; build tools/go-oracle");
            None
        }
    }
}

fn b64(bytes: &[u8]) -> Value {
    STANDARD.encode(bytes).into()
}

fn unb64(value: &Value) -> Vec<u8> {
    STANDARD.decode(value.as_str().unwrap()).unwrap()
}

/// Tracks mismatches so the divergence table is checked in both directions.
#[derive(Default)]
struct Ledger {
    unexpected: Vec<String>,
    seen: Vec<&'static str>,
}

impl Ledger {
    fn compare<T: PartialEq + std::fmt::Debug + Summary>(&mut self, name: &str, go: T, rust: T) {
        let listed = EXPECTED_DIVERGENCES.iter().find(|(case, ..)| *case == name);
        match (go == rust, listed) {
            (true, None) => {}
            (false, Some((case, expected, _))) if rust.summary() == *expected => {
                self.seen.push(case)
            }
            (false, Some((_, expected, _))) => self.unexpected.push(format!(
                "{name}: Rust result changed from {expected} to {}; Go {}",
                rust.summary(),
                go.summary()
            )),
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
            .filter(|(case, ..)| case.starts_with(prefix) && !self.seen.contains(case))
            .map(|(case, ..)| *case)
            .collect();
        assert!(
            self.unexpected.is_empty() && missing.is_empty(),
            "unexpected: {:#?}\nlisted but not run or not diverging: {missing:?}",
            self.unexpected
        );
    }
}

#[derive(Debug, PartialEq)]
enum Outcome {
    Packets(Vec<Vec<u8>>),
    Dropped,
    Fatal,
}

/// Incoming codec settings shared by both sides; `compression` None means before NetworkSettings.
#[derive(Clone, Copy, Default)]
struct Settings {
    compression: Option<&'static str>,
    max_decompressed: Option<usize>,
    accepting: bool,
    key: bool,
    nethernet: bool,
}

impl Settings {
    const NEGOTIATED: Self = Self {
        compression: Some("flate"),
        max_decompressed: None,
        accepting: false,
        key: false,
        nethernet: false,
    };

    fn header(self) -> BatchHeader {
        if self.nethernet {
            BatchHeader::NetherNet
        } else {
            BatchHeader::RakNet
        }
    }

    fn limits(self) -> BatchLimits {
        let mut limits = BatchLimits {
            max_incoming_packets: self.accepting.then_some(1600),
            ..BatchLimits::default()
        };
        if self.compression.is_none()
            && let Some(maximum) = self.max_decompressed
        {
            limits.max_decoded_bytes = maximum;
        }
        limits
    }

    fn go(self) -> Value {
        json!({
            "nethernet": self.nethernet,
            "compression": self.compression,
            "max_decompressed": self.max_decompressed.unwrap_or(0),
            "packet_limit": self.accepting,
            "key": if self.key { b64(&KEY) } else { Value::Null },
        })
    }
}

fn algorithm_id(name: &str) -> u8 {
    algorithm(name).network_id() as u8
}

fn algorithm(name: &str) -> CompressionAlgorithm {
    match name {
        "flate" => CompressionAlgorithm::Deflate,
        "snappy" => CompressionAlgorithm::Snappy,
        "none" => CompressionAlgorithm::None,
        other => panic!("unknown compression {other}"),
    }
}

/// Decodes like a connection: optional decryption, marker restore, then the batch codec.
fn rust_decode(settings: Settings, messages: &[Vec<u8>]) -> Vec<Outcome> {
    let plain = BatchCodec::new(settings.header(), settings.limits());
    match settings.compression {
        None => decode_all(&plain, settings, messages),
        Some(name) => {
            let mut codec = plain.negotiate(CompressionSettings {
                algorithm: algorithm(name),
                threshold: 0,
            });
            if let Some(maximum) = settings.max_decompressed {
                codec = codec.with_incoming_decoded_limit(maximum);
            }
            decode_all(&codec, settings, messages)
        }
    }
}

fn decode_all<S: BatchPhase>(
    codec: &BatchCodec<S>,
    settings: Settings,
    messages: &[Vec<u8>],
) -> Vec<Outcome> {
    let mut decryptor = settings.key.then(|| BatchDecryptor::new(KEY));
    let mut out = Vec::new();
    for message in messages {
        let mut message = Bytes::copy_from_slice(message);
        if let Some(decryptor) = &mut decryptor {
            let marker = settings.header().marker();
            if let Some(marker) = marker
                && message.first() != Some(&marker)
            {
                out.push(Outcome::Fatal);
                break;
            }
            let body = message.slice(usize::from(marker.is_some())..);
            match decryptor.decrypt(body) {
                Ok(plain) => message = envelope(marker, plain),
                Err(_) => {
                    out.push(Outcome::Fatal);
                    break;
                }
            }
        }
        match codec.decode(message) {
            Ok(DecodeOutcome::Packets { packets, .. }) => {
                out.push(Outcome::Packets(packets.map(|p| p.to_vec()).collect()))
            }
            Ok(DecodeOutcome::Dropped(_)) => out.push(Outcome::Dropped),
            Err(_) => {
                out.push(Outcome::Fatal);
                break;
            }
        }
    }
    out
}

fn go_decode(oracle: &mut Oracle, settings: Settings, messages: &[Vec<u8>]) -> Vec<Outcome> {
    let mut request = settings.go();
    request["op"] = "decode_batch".into();
    request["messages"] = messages.iter().map(|m| b64(m)).collect();
    let response = oracle.call(request);
    response["results"]
        .as_array()
        .unwrap()
        .iter()
        .map(|result| match result["outcome"].as_str().unwrap() {
            "packets" => Outcome::Packets(
                result["packets"]
                    .as_array()
                    .map(|packets| packets.iter().map(unb64).collect())
                    .unwrap_or_default(),
            ),
            "dropped" => Outcome::Dropped,
            "fatal" => Outcome::Fatal,
            other => panic!("unknown outcome {other}"),
        })
        .collect()
}

fn envelope(marker: Option<u8>, body: Bytes) -> Bytes {
    let Some(marker) = marker else {
        return body;
    };
    let mut message = BytesMut::with_capacity(body.len() + 1);
    message.extend_from_slice(&[marker]);
    message.extend_from_slice(&body);
    message.freeze()
}

/// Encodes with Rust's negotiated codec at threshold 0.
fn rust_batch(header: BatchHeader, name: &str, packets: &[Vec<u8>]) -> Vec<u8> {
    let codec = BatchCodec::new(header, BatchLimits::default()).negotiate(CompressionSettings {
        algorithm: algorithm(name),
        threshold: 0,
    });
    let mut batches = codec.encode(packets).unwrap();
    assert_eq!(batches.len(), 1);
    batches.pop().unwrap().to_vec()
}

/// Encrypts consecutive plaintext RakNet messages with one outgoing stream.
fn encrypt_all(messages: &[Vec<u8>]) -> Vec<Vec<u8>> {
    let mut encryptor = BatchEncryptor::new(KEY);
    messages
        .iter()
        .map(|message| {
            let body = Bytes::copy_from_slice(&message[1..]);
            envelope(Some(0xfe), encryptor.encrypt(body).unwrap()).to_vec()
        })
        .collect()
}

fn sample() -> Vec<Vec<u8>> {
    vec![
        vec![2, 0, 0, 0, 0],
        vec![9, 3, b'h', b'e', b'y'],
        (0..200).map(|i| (i % 13) as u8).collect(),
    ]
}

fn entries(packets: &[&[u8]]) -> Vec<u8> {
    let mut body = Vec::new();
    for packet in packets {
        let mut length = packet.len() as u32;
        while length >= 0x80 {
            body.push(length as u8 | 0x80);
            length >>= 7;
        }
        body.push(length as u8);
        body.extend_from_slice(packet);
    }
    body
}

fn uncompressed(packets: &[&[u8]]) -> Vec<u8> {
    [&[0xfe, 0xff][..], &entries(packets)].concat()
}

fn decode_corpus() -> Vec<(&'static str, Settings, Vec<Vec<u8>>)> {
    let n = Settings::NEGOTIATED;
    let sample = sample();
    let flate = rust_batch(BatchHeader::RakNet, "flate", &sample);
    let snappy = rust_batch(BatchHeader::RakNet, "snappy", &sample);
    let none = rust_batch(BatchHeader::RakNet, "none", &sample);
    let one_byte: Vec<&[u8]> = vec![&[1]; 1601];
    let big = vec![0x42; 16 * 1024 * 1024 + 512 * 1024];
    let mut corpus = vec![
        ("flate_multi", n, vec![flate.clone()]),
        ("snappy_multi", n, vec![snappy]),
        ("uncompressed_multi", n, vec![none.clone()]),
        (
            "empty_entries",
            n,
            vec![[&[0xfe, 0xff, 0][..], &entries(&[&[1, 2], &[]]), &[0]].concat()],
        ),
        (
            "unknown_compression_02",
            n,
            vec![vec![0xfe, 0x02, 1, 2], flate.clone()],
        ),
        (
            "unknown_compression_7f",
            n,
            vec![vec![0xfe, 0x7f, 1, 2], none.clone()],
        ),
        ("uncompressed_no_packets", n, vec![vec![0xfe, 0xff]]),
        ("missing_compression_id", n, vec![vec![0xfe]]),
        ("empty_message", n, vec![vec![]]),
        ("invalid_batch_header", n, vec![vec![0xfd, 0xff, 1, 1]]),
        (
            "flate_garbage",
            n,
            vec![vec![0xfe, 0x00, 0xde, 0xad, 0xbe, 0xef, 0x00, 0x11]],
        ),
        (
            "flate_truncated",
            n,
            vec![flate[..flate.len() - 3].to_vec(), none.clone()],
        ),
        (
            "flate_trailing_data",
            n,
            vec![[&flate[..], &[1, 2, 3]].concat()],
        ),
        (
            "snappy_declared_over_limit",
            n,
            vec![vec![0xfe, 0x01, 0xff, 0xff, 0xff, 0xff, 0x0f]],
        ),
        (
            "snappy_garbage",
            n,
            vec![vec![0xfe, 0x01, 0x05, 0xff, 0xff], none.clone()],
        ),
        (
            "flate_over_limit",
            Settings {
                max_decompressed: Some(1024),
                ..n
            },
            vec![rust_batch(BatchHeader::RakNet, "flate", &[vec![3; 4096]])],
        ),
        (
            "uncompressed_over_limit",
            Settings {
                max_decompressed: Some(1024),
                ..n
            },
            vec![uncompressed(&[&[3; 2048]])],
        ),
        (
            "uncompressed_at_limit",
            Settings {
                max_decompressed: Some(1026),
                ..n
            },
            vec![uncompressed(&[&[3; 1024]])],
        ),
        ("truncated_entry", n, vec![vec![0xfe, 0xff, 0x05, 1, 2]]),
        (
            "unterminated_length",
            n,
            vec![vec![0xfe, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]],
        ),
        (
            "length_overflow_fifth_byte",
            n,
            vec![vec![
                0xfe, 0xff, 0x85, 0x80, 0x80, 0x80, 0x10, 1, 2, 3, 4, 5,
            ]],
        ),
        ("packets_1601_client", n, vec![uncompressed(&one_byte)]),
        (
            "plain_multi",
            Settings::default(),
            vec![
                BatchCodec::new(BatchHeader::RakNet, BatchLimits::default())
                    .encode(&sample)
                    .unwrap()[0]
                    .to_vec(),
            ],
        ),
        (
            "plain_leading_ff",
            Settings::default(),
            vec![vec![0xfe, 0x02, 0xff, 0x01]],
        ),
        (
            "accepting_empty_entry",
            Settings {
                accepting: true,
                ..n
            },
            vec![uncompressed(&[&[1, 2], &[]])],
        ),
        (
            "accepting_1600_packets",
            Settings {
                accepting: true,
                ..n
            },
            vec![uncompressed(&one_byte[..1600])],
        ),
        (
            "accepting_1601_packets",
            Settings {
                accepting: true,
                ..n
            },
            vec![uncompressed(&one_byte)],
        ),
        (
            "nethernet_uncompressed",
            Settings {
                nethernet: true,
                ..n
            },
            vec![vec![0xff, 1, 7]],
        ),
        (
            "nethernet_flate",
            Settings {
                nethernet: true,
                ..n
            },
            vec![rust_batch(BatchHeader::NetherNet, "flate", &sample)],
        ),
        (
            "wire_over_32mib",
            Settings {
                max_decompressed: Some(256 * 1024 * 1024),
                ..n
            },
            vec![uncompressed(&[&big, &big])],
        ),
    ];
    let keyed = Settings { key: true, ..n };
    let snappy_small = rust_batch(BatchHeader::RakNet, "snappy", &sample[..1]);
    corpus.extend([
        (
            "encrypted_consecutive",
            keyed,
            encrypt_all(&[flate.clone(), none.clone(), snappy_small]),
        ),
        (
            "encrypted_drop_keeps_stream",
            keyed,
            encrypt_all(&[none.clone(), vec![0xfe, 0x02, 9, 9], flate.clone()]),
        ),
        ("encrypted_bad_checksum", keyed, {
            let mut frames = encrypt_all(&[none.clone(), none.clone()]);
            *frames[1].last_mut().unwrap() ^= 1;
            frames
        }),
        ("encrypted_short", keyed, vec![vec![0xfe, 1, 2, 3]]),
        ("encrypted_empty_message", keyed, vec![vec![]]),
    ]);
    corpus
}

#[test]
fn decode_decisions_match_go() {
    let Some(mut oracle) = oracle() else { return };
    // Go's own decision for these cases, so an agreeing pair of failures cannot pass.
    let anchors = [
        ("flate_multi", "packets(3)"),
        ("snappy_multi", "packets(3)"),
        ("uncompressed_multi", "packets(3)"),
        ("unknown_compression_02", "dropped,packets(3)"),
        ("plain_multi", "packets(3)"),
        ("nethernet_flate", "packets(3)"),
        ("missing_compression_id", "fatal"),
        ("encrypted_consecutive", "packets(3),packets(3),packets(1)"),
        (
            "encrypted_drop_keeps_stream",
            "packets(3),dropped,packets(3)",
        ),
        ("encrypted_bad_checksum", "packets(3),fatal"),
    ];
    let mut ledger = Ledger::default();
    for (name, settings, messages) in decode_corpus() {
        let go = go_decode(&mut oracle, settings, &messages);
        if let Some((_, expected)) = anchors.iter().find(|(case, _)| *case == name) {
            assert_eq!(go.summary(), *expected, "Go decision for {name}");
        }
        ledger.compare(
            &format!("decode/{name}"),
            go,
            rust_decode(settings, &messages),
        );
    }
    ledger.finish("decode/");
}

/// Outgoing settings: `None` is before NetworkSettings.
struct EncodeCase {
    name: &'static str,
    compression: Option<(&'static str, u16)>,
    nethernet: bool,
    key: bool,
    calls: Vec<Vec<Vec<u8>>>,
}

/// Encodes each call like a connection, encrypting after framing when keyed.
fn rust_encode(case: &EncodeCase) -> Vec<Vec<Vec<u8>>> {
    let header = if case.nethernet {
        BatchHeader::NetherNet
    } else {
        BatchHeader::RakNet
    };
    let plain = BatchCodec::new(header, BatchLimits::default());
    let mut encryptor = case.key.then(|| BatchEncryptor::new(KEY));
    let encode = |packets: &[Vec<u8>]| match case.compression {
        None => plain.encode(packets),
        Some((name, threshold)) => BatchCodec::new(header, BatchLimits::default())
            .negotiate(CompressionSettings {
                algorithm: algorithm(name),
                threshold,
            })
            .encode(packets),
    };
    case.calls
        .iter()
        .map(|packets| match encode(packets) {
            Ok(batches) => batches
                .into_iter()
                .map(|message| match &mut encryptor {
                    Some(encryptor) => {
                        let marker = header.marker();
                        let body = message.slice(usize::from(marker.is_some())..);
                        envelope(marker, encryptor.encrypt(body).unwrap()).to_vec()
                    }
                    None => message.to_vec(),
                })
                .collect(),
            Err(_) => Vec::new(),
        })
        .collect()
}

fn go_encode(oracle: &mut Oracle, case: &EncodeCase) -> Vec<Vec<Vec<u8>>> {
    let response = oracle.call(json!({
        "op": "encode_batch",
        "nethernet": case.nethernet,
        "compression": case.compression.map(|(name, _)| name),
        "threshold": case.compression.map_or(0, |(_, threshold)| threshold),
        "key": if case.key { b64(&KEY) } else { Value::Null },
        "batches": case.calls.iter().map(|packets| packets.iter().map(|p| b64(p)).collect::<Vec<_>>()).collect::<Vec<_>>(),
    }));
    response["results"]
        .as_array()
        .unwrap()
        .iter()
        .map(|call| {
            call.as_array()
                .map(|frames| frames.iter().map(unb64).collect())
                .unwrap_or_default()
        })
        .collect()
}

/// Reduces compressed frames to what must match: compression marker and decoded packets.
fn semantic(oracle: &mut Oracle, frames: &[Vec<Vec<u8>>]) -> Vec<(u8, Vec<Outcome>)> {
    frames
        .iter()
        .flatten()
        .map(|frame| {
            let decoded = go_decode(oracle, Settings::NEGOTIATED, std::slice::from_ref(frame));
            (frame[1], decoded)
        })
        .collect()
}

#[test]
fn encode_output_matches_go() {
    let Some(mut oracle) = oracle() else { return };
    let sample = sample();
    let body_len = entries(&sample.iter().map(Vec::as_slice).collect::<Vec<_>>()).len() as u16;
    let many: Vec<Vec<u8>> = (0..3201).map(|i| vec![1, (i % 251) as u8]).collect();
    let huge = vec![vec![0x24; 9 * 1024 * 1024], vec![0x25; 9 * 1024 * 1024]];
    let exact = [
        EncodeCase {
            name: "plain_exact",
            compression: None,
            nethernet: false,
            key: false,
            calls: vec![sample.clone()],
        },
        EncodeCase {
            name: "uncompressed_exact",
            compression: Some(("none", 0)),
            nethernet: false,
            key: false,
            calls: vec![sample.clone(), sample[..1].to_vec()],
        },
        EncodeCase {
            name: "below_threshold",
            compression: Some(("flate", body_len + 1)),
            nethernet: false,
            key: false,
            calls: vec![sample.clone()],
        },
        EncodeCase {
            name: "split_1600",
            compression: None,
            nethernet: false,
            key: false,
            calls: vec![many],
        },
        EncodeCase {
            name: "split_16mib",
            compression: None,
            nethernet: false,
            key: false,
            calls: vec![huge],
        },
        EncodeCase {
            name: "encrypted_exact",
            compression: Some(("none", 0)),
            nethernet: false,
            key: true,
            calls: vec![sample.clone(), sample.clone(), sample[1..].to_vec()],
        },
        EncodeCase {
            name: "nethernet_exact",
            compression: Some(("none", 0)),
            nethernet: true,
            key: false,
            calls: vec![sample.clone()],
        },
    ];
    let mut ledger = Ledger::default();
    for case in &exact {
        let go = go_encode(&mut oracle, case);
        assert!(
            go.iter().all(|frames| !frames.is_empty()),
            "Go wrote no batch for {}",
            case.name
        );
        if case.name == "split_1600" {
            assert_eq!(
                go.summary(),
                "3",
                "Go splits 3201 packets into three batches"
            );
        }
        ledger.compare(&format!("encode/{}", case.name), go, rust_encode(case));
    }
    for (name, algorithm) in [("at_threshold", "flate"), ("snappy_at_threshold", "snappy")] {
        let case = EncodeCase {
            name,
            compression: Some((algorithm, body_len)),
            nethernet: false,
            key: false,
            calls: vec![sample.clone()],
        };
        let go = go_encode(&mut oracle, &case);
        let rust = rust_encode(&case);
        let marker = algorithm_id(algorithm);
        let expected = vec![(marker, vec![Outcome::Packets(sample.clone())])];
        assert_eq!(
            semantic(&mut oracle, &go),
            expected,
            "Go compresses at the threshold"
        );
        // Go's compressed bytes must decode the same in Rust, and Rust's in Go.
        let rust_reads_go: Vec<_> = go
            .iter()
            .flatten()
            .map(|frame| {
                (
                    frame[1],
                    rust_decode(Settings::NEGOTIATED, std::slice::from_ref(frame)),
                )
            })
            .collect();
        ledger.compare(
            &format!("encode/{name}"),
            semantic(&mut oracle, &go),
            semantic(&mut oracle, &rust),
        );
        ledger.compare(
            &format!("encode/{name}_cross"),
            semantic(&mut oracle, &go),
            rust_reads_go,
        );
    }
    ledger.finish("encode/");
}

#[test]
fn encryption_checksums_match_go() {
    let Some(mut oracle) = oracle() else { return };
    let bodies: Vec<Vec<u8>> = vec![
        vec![0xff],
        (0..1024).map(|i| i as u8).collect(),
        vec![0; 64 * 1024],
        vec![0x01, 9, 9, 9],
    ];
    let response = oracle.call(json!({
        "op": "encrypt",
        "key": b64(&KEY),
        "bodies": bodies.iter().map(|b| b64(b)).collect::<Vec<_>>(),
    }));
    let go: Vec<Vec<u8>> = response["ciphertexts"]
        .as_array()
        .unwrap()
        .iter()
        .map(unb64)
        .collect();
    let mut encryptor = BatchEncryptor::new(KEY);
    let rust: Vec<Vec<u8>> = bodies
        .iter()
        .map(|body| {
            envelope(
                Some(0xfe),
                encryptor.encrypt(Bytes::copy_from_slice(body)).unwrap(),
            )
            .to_vec()
        })
        .collect();
    assert_eq!(go, rust);
}

#[cfg(feature = "login")]
mod login {
    use super::*;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use bedrock_net::login::{
        LoginError, LoginVerifier, OfflineIdentity, TrustedIdentity, encode_authenticated_request,
        encode_offline_request, verify_authenticated_request,
    };
    use p384::ecdsa::signature::{Signer, Verifier};
    use p384::ecdsa::{Signature, SigningKey, VerifyingKey};
    use p384::pkcs8::{DecodePublicKey, EncodePublicKey};
    use serde_json::value::RawValue;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    const LIMIT: usize = 1024 * 1024;
    const ISSUER: &str = "https://synthetic-login.invalid";
    const AUDIENCE: &str = "api://auth-minecraft-services/multiplayer";
    const NOW: u64 = 2_000_000_000;

    fn client_data() -> Value {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/testdata/bench/client_data.json"
        );
        serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
    }

    fn public_der(key: &SigningKey) -> Vec<u8> {
        key.verifying_key()
            .to_public_key_der()
            .unwrap()
            .as_bytes()
            .to_vec()
    }

    /// Signs compact ES384 JSON; `line` appends the newline vanilla clients emit.
    fn sign(key: &SigningKey, header: &Value, payload: &[u8]) -> String {
        let input = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(header).unwrap()),
            URL_SAFE_NO_PAD.encode(payload)
        );
        let signature: Signature = key.sign(input.as_bytes());
        format!("{input}.{}", URL_SAFE_NO_PAD.encode(signature.to_bytes()))
    }

    /// A configured-key provider check, standing in for the application's verifier.
    struct Provider(VerifyingKey);

    impl LoginVerifier for Provider {
        fn verify(&self, token: &str, now: SystemTime) -> Result<TrustedIdentity, LoginError> {
            let fail = |_| LoginError::Authentication;
            let (input, signature) = token.rsplit_once('.').ok_or(LoginError::Authentication)?;
            let signature = Signature::from_slice(
                &URL_SAFE_NO_PAD
                    .decode(signature)
                    .map_err(|_| LoginError::Authentication)?,
            )
            .map_err(fail)?;
            self.0.verify(input.as_bytes(), &signature).map_err(fail)?;
            let payload = input.split_once('.').ok_or(LoginError::Authentication)?.1;
            let claims: Value = serde_json::from_slice(
                &URL_SAFE_NO_PAD
                    .decode(payload)
                    .map_err(|_| LoginError::Authentication)?,
            )
            .map_err(|_| LoginError::Authentication)?;
            let seconds = now.duration_since(UNIX_EPOCH).unwrap().as_secs();
            if claims["iss"] != ISSUER || claims["exp"].as_u64().is_none_or(|exp| seconds >= exp) {
                return Err(LoginError::Authentication);
            }
            let der = STANDARD
                .decode(claims["cpk"].as_str().ok_or(LoginError::Authentication)?)
                .map_err(|_| LoginError::Authentication)?;
            TrustedIdentity::new(
                claims["xid"]
                    .as_str()
                    .ok_or(LoginError::Authentication)?
                    .into(),
                VerifyingKey::from_public_key_der(&der).map_err(|_| LoginError::Authentication)?,
            )
        }
    }

    /// Splits a request into its envelope line and client token.
    fn fields(request: &[u8]) -> (Vec<u8>, String) {
        let length = u32::from_le_bytes(request[..4].try_into().unwrap()) as usize;
        let envelope = request[4..4 + length].to_vec();
        let rest = &request[4 + length..];
        let client = u32::from_le_bytes(rest[..4].try_into().unwrap()) as usize;
        (
            envelope,
            String::from_utf8(rest[4..4 + client].to_vec()).unwrap(),
        )
    }

    fn part(token: &str, index: usize) -> Vec<u8> {
        URL_SAFE_NO_PAD
            .decode(token.split('.').nth(index).unwrap())
            .unwrap()
    }

    fn frame(envelope: &[u8], client: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&(envelope.len() as u32).to_le_bytes());
        out.extend_from_slice(envelope);
        out.extend_from_slice(&(client.len() as u32).to_le_bytes());
        out.extend_from_slice(client);
        out
    }

    /// Offline and token requests carry Go's exact header, envelope and claim layout.
    #[test]
    fn login_formatting_matches_go() {
        let Some(mut oracle) = oracle() else { return };
        let key = SigningKey::from_slice(&[3; 48]).unwrap();
        let data = client_data();
        let raw = RawValue::from_string(data.to_string()).unwrap();
        let identity = OfflineIdentity {
            display_name: "Probe",
            identity: "00000000-0000-4000-8000-000000000001",
            xuid: "",
            playfab_id: "",
            playfab_title_id: "",
        };
        let token = "synthetic.multiplayer.token";
        let response = oracle.call(json!({
            "op": "login_build", "scalar": b64(&key.to_bytes()), "client_data": data,
            "display_name": identity.display_name, "identity": identity.identity, "token": token,
        }));
        let now = SystemTime::now();
        let rust_offline = encode_offline_request(&key, &identity, &raw, now, LIMIT).unwrap();
        let rust_token = encode_authenticated_request(&key, token, &raw, LIMIT).unwrap();
        let (go_envelope, go_client) = fields(&unb64(&response["offline"]));
        let (rust_envelope, rust_client) = fields(&rust_offline);
        let envelope_keys = |line: &[u8]| {
            assert_eq!(line.last(), Some(&b'\n'));
            let value: serde_json::Map<String, Value> = serde_json::from_slice(line).unwrap();
            value.keys().cloned().collect::<Vec<_>>()
        };
        assert_eq!(envelope_keys(&go_envelope), envelope_keys(&rust_envelope));
        let go_inner: Value = serde_json::from_slice(&go_envelope).unwrap();
        let rust_inner: Value = serde_json::from_slice(&rust_envelope).unwrap();
        let (go_auth, rust_auth) = (
            go_inner["Token"].as_str().unwrap(),
            rust_inner["Token"].as_str().unwrap(),
        );
        // Signed header lines, including the trailing newline, are byte-identical.
        for (go, rust) in [
            (go_auth, rust_auth),
            (go_client.as_str(), rust_client.as_str()),
        ] {
            assert_eq!(part(go, 0), part(rust, 0));
        }
        // Offline claims keep Go's key order; only the clock-derived values differ.
        let claims = |token: &str| {
            let raw = part(token, 1);
            assert_eq!(raw.last(), Some(&b'\n'));
            let mut map: serde_json::Map<String, Value> = serde_json::from_slice(&raw).unwrap();
            let window = map["exp"].as_i64().unwrap() - map["nbf"].as_i64().unwrap();
            map.insert("exp".into(), Value::Null);
            map.insert("nbf".into(), Value::Null);
            (serde_json::to_string(&map).unwrap(), window)
        };
        assert_eq!(claims(go_auth), claims(rust_auth));
        let (go_envelope, _) = fields(&unb64(&response["token"]));
        let (rust_envelope, _) = fields(&rust_token);
        assert_eq!(go_envelope, rust_envelope);
    }

    /// Accept/reject decisions for authenticated requests, Go Parse with a static-key verifier.
    #[test]
    fn login_verification_decisions_match_go() {
        let Some(mut oracle) = oracle() else { return };
        let client = SigningKey::from_slice(&[4; 48]).unwrap();
        let other = SigningKey::from_slice(&[6; 48]).unwrap();
        let provider = SigningKey::from_slice(&[5; 48]).unwrap();
        let token_for = |key: &SigningKey, exp: u64| {
            let claims = json!({
                "iss": ISSUER, "aud": AUDIENCE, "exp": exp, "nbf": 0, "iat": 0, "ipt": "PlayFab",
                "mid": "", "tid": "", "cpk": STANDARD.encode(public_der(key)),
                "xid": "2535400000000001", "xname": "Probe",
            });
            sign(
                &provider,
                &json!({"alg": "ES384"}),
                &serde_json::to_vec(&claims).unwrap(),
            )
        };
        let token = token_for(&client, NOW + 3600);
        let data = client_data();
        let raw = |value: &Value| RawValue::from_string(value.to_string()).unwrap();
        let valid = encode_authenticated_request(&client, &token, &raw(&data), LIMIT)
            .unwrap()
            .to_vec();
        let (envelope, _) = fields(&valid);
        let x5u = STANDARD.encode(public_der(&client));
        let client_token =
            |payload: &[u8]| sign(&client, &json!({"alg": "ES384", "x5u": x5u}), payload);
        let mut invalid_skin = data.clone();
        invalid_skin["SkinId"] = "".into();
        let mut cases: Vec<(&str, Vec<u8>)> = vec![
            ("valid", valid.clone()),
            ("truncated", valid[..valid.len() - 1].to_vec()),
            ("trailing_byte", [&valid[..], &[0]].concat()),
            (
                "negative_length",
                [&(-1_i32).to_le_bytes()[..], &valid[4..]].concat(),
            ),
            (
                "zero_length",
                [&0_u32.to_le_bytes()[..], &valid[4..]].concat(),
            ),
            (
                "client_signed_by_other_key",
                encode_authenticated_request(&other, &token, &raw(&data), LIMIT)
                    .unwrap()
                    .to_vec(),
            ),
            (
                "expired_token",
                encode_authenticated_request(
                    &client,
                    &token_for(&client, NOW - 1),
                    &raw(&data),
                    LIMIT,
                )
                .unwrap()
                .to_vec(),
            ),
            (
                "client_without_newline",
                frame(
                    &envelope,
                    client_token(data.to_string().as_bytes()).as_bytes(),
                ),
            ),
            (
                "client_not_object",
                frame(&envelope, client_token(b"[1]\n").as_bytes()),
            ),
            (
                "client_fails_go_validation",
                encode_authenticated_request(&client, &token, &raw(&invalid_skin), LIMIT)
                    .unwrap()
                    .to_vec(),
            ),
        ];
        cases.push(("offline_mode", {
            let identity = OfflineIdentity {
                display_name: "Probe",
                identity: "00000000-0000-4000-8000-000000000001",
                xuid: "",
                playfab_id: "",
                playfab_title_id: "",
            };
            let now = UNIX_EPOCH + Duration::from_secs(NOW);
            encode_offline_request(&client, &identity, &raw(&data), now, LIMIT)
                .unwrap()
                .to_vec()
        }));
        let verifier = Provider(*provider.verifying_key());
        let now = UNIX_EPOCH + Duration::from_secs(NOW);
        let mut ledger = Ledger::default();
        for (name, request) in cases {
            let response = oracle.call(json!({
                "op": "login_parse", "request": b64(&request), "provider_key": b64(&public_der(&provider)),
                "issuer": ISSUER, "audience": AUDIENCE, "now": NOW,
            }));
            let go = response["accepted"].as_bool().unwrap()
                && response["authenticated"].as_bool().unwrap();
            let rust = verify_authenticated_request(&request, &verifier, now, LIMIT).is_ok();
            // Anchors Go's decision so an agreeing pair of failures cannot pass.
            match name {
                "valid" => assert!(go, "Go must accept the valid request"),
                "client_signed_by_other_key" | "client_fails_go_validation" => {
                    assert!(!go, "Go must reject {name}")
                }
                _ => {}
            }
            ledger.compare(&format!("login/{name}"), go, rust);
        }
        ledger.finish("login/");
    }
}
