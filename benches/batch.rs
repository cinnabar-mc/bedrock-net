//! Batch framing, compression and encryption over the shared inputs; pairs with the Go benches.

mod common;

use std::hint::black_box;
use std::time::{Duration, Instant};

use bedrock_net::encryption::{BatchDecryptor, BatchEncryptor};
use bedrock_net::{
    BatchCodec, BatchHeader, BatchLimits, BatchPhase, CompressionAlgorithm, CompressionSettings,
    DecodeOutcome,
};
use bytes::Bytes;
use criterion::{Criterion, Throughput, criterion_group, criterion_main};

/// Builds a connection codec with the selected outgoing compression.
fn negotiated(
    algorithm: CompressionAlgorithm,
    threshold: u16,
) -> BatchCodec<bedrock_net::Negotiated> {
    BatchCodec::new(BatchHeader::RakNet, BatchLimits::default()).negotiate(CompressionSettings {
        algorithm,
        threshold,
    })
}

/// Decodes frames with an unlimited codec of the same phase and requires exactly `want`.
/// Each benchmark checks its own output this way once, outside the timed loop.
fn verify<S: BatchPhase>(codec: &BatchCodec<S>, frames: &[Bytes], want: &[Vec<u8>]) {
    let mut got = Vec::new();
    for frame in frames {
        match codec.decode(frame.clone()).unwrap() {
            DecodeOutcome::Packets { packets, .. } => got.extend(packets.map(|p| p.to_vec())),
            DecodeOutcome::Dropped(reason) => panic!("own output dropped: {reason}"),
        }
    }
    assert!(got == want, "own output does not decode to the input");
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
    BatchCodec::new(BatchHeader::RakNet, unlimited())
        .negotiate(CompressionSettings {
            algorithm,
            threshold: 0,
        })
        .with_incoming_decoded_limit(usize::MAX)
}

/// Consumes every packet so lazy iteration costs are measured like Go's DecodeFunc walk.
fn drain<S: BatchPhase>(codec: &BatchCodec<S>, wire: Bytes) {
    match codec.decode(wire).unwrap() {
        DecodeOutcome::Packets { packets, .. } => {
            packets.for_each_slice(|packet| {
                black_box(packet);
            });
        }
        DecodeOutcome::Dropped(reason) => panic!("bench batch dropped: {reason}"),
    }
}

fn codec_group<S: BatchPhase>(
    c: &mut Criterion,
    group: &str,
    codec: impl Fn() -> BatchCodec<S>,
    reader: impl Fn() -> BatchCodec<S>,
) {
    let cases = common::Cases::load();
    let mut bench = c.benchmark_group(group);
    for case in cases.cases(group) {
        let packets = cases.packets(&case.set);
        bench.throughput(Throughput::Bytes(common::size(&packets)));
        let codec = codec();
        match case.op.as_str() {
            "encode" | "compress" => {
                let mut frames = Vec::new();
                codec.encode_into(&packets, &mut frames).unwrap();
                verify(&reader(), &frames, &packets);
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
                bench.bench_function(case.name(), |b| b.iter(|| drain(&codec, wire.clone())));
            }
            op => panic!("unknown op {op}"),
        }
    }
    bench.finish();
}

fn framing(c: &mut Criterion) {
    codec_group(
        c,
        "BatchFraming",
        || BatchCodec::new(BatchHeader::RakNet, BatchLimits::default()),
        || BatchCodec::new(BatchHeader::RakNet, unlimited()),
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

/// Encodes then encrypts complete batches in place, preserving the transport marker.
fn encrypt_message(
    codec: &BatchCodec<bedrock_net::Negotiated>,
    encryptor: &mut BatchEncryptor,
    packets: &[Vec<u8>],
) -> Vec<Bytes> {
    let mut frames = Vec::new();
    encrypt_into(codec, encryptor, packets, &mut frames);
    frames
}

/// Recycles consumed envelopes before encoding the next immediate send.
fn encrypt_into(
    codec: &BatchCodec<bedrock_net::Negotiated>,
    encryptor: &mut BatchEncryptor,
    packets: &[Vec<u8>],
    frames: &mut Vec<Bytes>,
) {
    codec.encode_into(packets, frames).unwrap();
    for message in frames {
        *message = encryptor
            .encrypt_batch(BatchHeader::RakNet, std::mem::take(message))
            .unwrap();
    }
}

/// Measures the negotiated uncompressed (0xff) path with batch encryption.
fn encryption(c: &mut Criterion) {
    let cases = common::Cases::load();
    let key = [cases.u64("/encryption_key_byte") as u8; 32];
    let mut bench = c.benchmark_group("Encryption");
    for case in cases.cases("Encryption") {
        let packets = cases.packets(&case.set);
        let bytes = common::size(&packets);
        bench.throughput(Throughput::Bytes(bytes));
        let codec = negotiated(CompressionAlgorithm::None, 0);
        // Two consecutive frames from a fresh stream must decrypt and decode to the input.
        let mut check = BatchEncryptor::new(key);
        let mut decryptor = BatchDecryptor::new(key);
        let frames: Vec<Bytes> = (0..2)
            .flat_map(|_| encrypt_message(&codec, &mut check, &packets))
            .map(|message| {
                decryptor
                    .decrypt_batch(BatchHeader::RakNet, message)
                    .unwrap()
            })
            .collect();
        let twice: Vec<Vec<u8>> = packets.iter().chain(&packets).cloned().collect();
        verify(&reader(CompressionAlgorithm::None), &frames, &twice);
        match case.op.as_str() {
            "encrypt" => {
                let mut encryptor = BatchEncryptor::new(key);
                let mut frames = Vec::new();
                bench.bench_function(case.name(), |b| {
                    b.iter(|| {
                        encrypt_into(&codec, &mut encryptor, &packets, &mut frames);
                        black_box(&frames);
                    })
                });
            }
            "decrypt" => {
                // Decryption consumes frames in stream order, so they are produced in
                // lockstep chunks outside the measured time.
                let mut encryptor = BatchEncryptor::new(key);
                let mut decryptor = BatchDecryptor::new(key);
                let chunk = ((64 << 20) / bytes.max(1)).clamp(1, 4096);
                bench.bench_function(case.name(), |b| {
                    b.iter_custom(|iters| {
                        let mut elapsed = Duration::ZERO;
                        let mut remaining = iters;
                        while remaining > 0 {
                            let n = remaining.min(chunk);
                            let frames: Vec<Bytes> = (0..n)
                                .flat_map(|_| encrypt_message(&codec, &mut encryptor, &packets))
                                .collect();
                            let start = Instant::now();
                            for message in frames {
                                let plain = decryptor
                                    .decrypt_batch(BatchHeader::RakNet, message)
                                    .unwrap();
                                drain(&codec, plain);
                            }
                            elapsed += start.elapsed();
                            remaining -= n;
                        }
                        elapsed
                    })
                });
            }
            op => panic!("unknown op {op}"),
        }
    }
    bench.finish();
}

criterion_group!(benches, framing, flate, snappy, encryption);
criterion_main!(benches);
