//! Batch framing and compression over the shared inputs; pairs with the Go benches.

mod common;

use std::hint::black_box;
use std::path::PathBuf;

use bedrock_net::{
    BatchCodec, BatchLimits, BatchPhase, CompressionAlgorithm, CompressionSettings, DecodeOutcome,
    VisitOutcome,
};
use bytes::Bytes;
use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use sha2::{Digest, Sha256};

/// Uses one explicit root for Criterion results and their wire-size sidecars.
fn output_directory() -> PathBuf {
    std::env::var_os("CRITERION_HOME").map_or_else(
        || {
            std::env::var_os("CARGO_TARGET_DIR")
                .map_or_else(|| PathBuf::from("target"), PathBuf::from)
                .join("criterion")
        },
        PathBuf::from,
    )
}

/// Binds untimed wire bytes to the freshly written estimates, never to an older run.
fn record_wire_size(
    dir: &std::path::Path,
    full_id: &str,
    wire_bytes: usize,
    previous: Option<std::time::SystemTime>,
) {
    let estimates = dir.join("estimates.json");
    let modified = std::fs::metadata(&estimates)
        .and_then(|meta| meta.modified())
        .ok();
    // Filtered, list-only and test-mode runs do not produce fresh estimates.
    if modified.is_none() || modified == previous {
        return;
    }
    let digest = Sha256::digest(std::fs::read(estimates).unwrap());
    let digest: String = digest.iter().map(|byte| format!("{byte:02x}")).collect();
    let record = serde_json::json!({
        "full_id": full_id,
        "wire_bytes": wire_bytes,
        "estimates_sha256": digest,
    });
    std::fs::write(
        dir.join("wire-size.json"),
        serde_json::to_vec(&record).unwrap(),
    )
    .unwrap();
}

/// Builds a connection codec with the selected outgoing compression.
fn negotiated(
    algorithm: CompressionAlgorithm,
    threshold: u16,
) -> BatchCodec<bedrock_net::Negotiated> {
    BatchCodec::new(BatchLimits::default()).negotiate(CompressionSettings {
        algorithm,
        threshold,
    })
}

/// Decodes frames with an unlimited codec of the same phase and requires exactly `want`.
/// Each benchmark checks its own output this way once, outside the timed loop.
fn verify<S: BatchPhase, P: AsRef<[u8]>>(codec: &BatchCodec<S>, frames: &[Bytes], want: &[P]) {
    let mut got = Vec::new();
    for frame in frames {
        match codec.decode(frame.clone()).unwrap() {
            DecodeOutcome::Packets { packets, .. } => got.extend(packets),
            DecodeOutcome::Dropped(reason) => panic!("own output dropped: {reason}"),
        }
    }
    assert!(
        got.len() == want.len()
            && got
                .iter()
                .zip(want)
                .all(|(got, want)| got.as_ref() == want.as_ref()),
        "own output does not decode to the input"
    );
}

/// Limits large enough to read back any benchmark output.
fn unlimited() -> BatchLimits {
    BatchLimits {
        max_encoded_bytes: usize::MAX,
        max_decoded_bytes: usize::MAX,
        ..BatchLimits::default()
    }
}

/// A negotiated codec that reads back any benchmark output.
fn reader(algorithm: CompressionAlgorithm) -> BatchCodec<bedrock_net::Negotiated> {
    BatchCodec::new(unlimited())
        .negotiate(CompressionSettings {
            algorithm,
            threshold: 0,
        })
        .with_incoming_decoded_limit(usize::MAX)
}

/// Consumes every packet so lazy iteration costs are measured like Go's `DecodeFunc` walk.
fn drain<S: BatchPhase>(codec: &mut BatchCodec<S>, wire: Bytes) {
    match codec
        .decode_with(wire, |packet| {
            black_box(packet);
        })
        .unwrap()
    {
        VisitOutcome::Packets { .. } => {}
        VisitOutcome::Dropped(reason) => panic!("bench batch dropped: {reason}"),
    }
}

/// Measures one codec group and records compression sizes outside the timed loop.
fn codec_group<S: BatchPhase>(
    c: &mut Criterion,
    group: &str,
    codec: impl Fn() -> BatchCodec<S>,
    reader: impl Fn() -> BatchCodec<S>,
) {
    let cases = common::Cases::load();
    let mut bench = c.benchmark_group(group);
    for case in cases.cases(group) {
        let compression = matches!(group, "Flate" | "Snappy");
        let result_dir = output_directory().join(group).join(case.name()).join("new");
        let previous = if compression {
            match std::fs::remove_file(result_dir.join("wire-size.json")) {
                Ok(()) => {}
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
                Err(err) => panic!("remove previous wire size: {err}"),
            }
            std::fs::metadata(result_dir.join("estimates.json"))
                .and_then(|meta| meta.modified())
                .ok()
        } else {
            None
        };
        let packets = cases.packets(&case.set);
        bench.throughput(Throughput::Bytes(common::size(&packets)));
        let mut codec = codec();
        let wire_bytes;
        match case.op.as_str() {
            "encode" | "compress" => {
                let mut frames = Vec::new();
                codec.encode_into(&packets, &mut frames).unwrap();
                verify(&reader(), &frames, &packets);
                wire_bytes = frames.iter().map(Bytes::len).sum();
                bench.bench_function(case.name(), |b| {
                    b.iter(|| {
                        codec.encode_into(&packets, &mut frames).unwrap();
                        black_box(&frames);
                    })
                });
            }
            "decode" | "decompress" => {
                let mut wire = codec.encode(&packets).unwrap();
                assert_eq!(wire.len(), 1, "decode input {} spans batches", case.set);
                let wire = wire.pop().unwrap();
                verify(&reader(), std::slice::from_ref(&wire), &packets);
                wire_bytes = wire.len();
                bench.bench_function(case.name(), |b| b.iter(|| drain(&mut codec, wire.clone())));
            }
            op => panic!("unknown op {op}"),
        }
        if compression {
            record_wire_size(
                &result_dir,
                &format!("{group}/{}", case.name()),
                wire_bytes,
                previous,
            );
        }
    }
    bench.finish();
}

fn framing(c: &mut Criterion) {
    codec_group(
        c,
        "BatchFraming",
        || BatchCodec::new(BatchLimits::default()),
        || BatchCodec::new(unlimited()),
    );
}

fn flate(c: &mut Criterion) {
    let threshold = common::Cases::load().u64("/compression_threshold") as u16;
    codec_group(
        c,
        "Flate",
        || negotiated(CompressionAlgorithm::Deflate, threshold),
        || reader(CompressionAlgorithm::Deflate),
    );
}

fn snappy(c: &mut Criterion) {
    let threshold = common::Cases::load().u64("/compression_threshold") as u16;
    codec_group(
        c,
        "Snappy",
        || negotiated(CompressionAlgorithm::Snappy, threshold),
        || reader(CompressionAlgorithm::Snappy),
    );
}

criterion_group! {
    name = benches;
    config = Criterion::default().output_directory(&output_directory());
    targets = framing, flate, snappy
}
criterion_main!(benches);
