//! Shared-buffer forwarding over the same synthetic input as the Go raw codec benchmark.

use bedrock_client_tokio::connection::RawBatch;
use bedrock_net::{BatchCodec, BatchLimits, DecodeOutcome};
use bedrock_protocol::{packets, wire};
use bytes::Bytes;
use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use std::hint::black_box;

/// Builds 64 opaque 4-KiB packets or 64 selected `SetTime` packets, matching the Go benchmark.
fn body(selected: bool) -> Bytes {
    let raw = if selected {
        let mut raw = Vec::new();
        let mut writer = wire::Writer::new(&mut raw);
        writer.write_var_u32(packets::SetTime::ID).unwrap();
        packets::Packet::from(packets::SetTime {
            time: wire::ZigZag32(7),
        })
        .encode(&mut writer)
        .unwrap();
        Bytes::from(raw)
    } else {
        let mut raw = vec![0xff, 7];
        raw.resize(4096 + 2, 0xaa);
        Bytes::from(raw)
    };
    BatchCodec::new(BatchLimits::default())
        .encode(&vec![raw; 64])
        .unwrap()
        .remove(0)
}

/// Measures framing, raw views, selected decoding and outgoing framing without network scheduling.
fn raw(c: &mut Criterion) {
    let mut group = c.benchmark_group("RawBatch");
    for (name, selected) in [("forward_opaque", false), ("forward_selected", true)] {
        let body = body(selected);
        let codec = BatchCodec::new(BatchLimits::default());
        let limits = wire::Limits::receiving_from(wire::Peer::Server);
        group.throughput(Throughput::Bytes(body.len() as u64));
        group.bench_function(name, |b| {
            b.iter(|| {
                let DecodeOutcome::Packets { packets, .. } = codec.decode(body.clone()).unwrap()
                else {
                    panic!("plain batch dropped")
                };
                let batch = RawBatch::from_packets(packets, &limits, |_| selected).unwrap();
                assert_eq!(batch.packets().len(), 64);
                black_box(batch.packets());
                let output = codec.encode_raw_batch(batch.into_body()).unwrap();
                black_box(output);
            })
        });
    }
    group.finish();
}

criterion_group!(benches, raw);
criterion_main!(benches);
