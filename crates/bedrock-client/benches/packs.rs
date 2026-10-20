//! In-band pack chunk assembly and archive hashing; pairs with the Go benches.

#[path = "../../../benches/common/mod.rs"]
mod common;

use std::hint::black_box;

use bedrock_client::packs::{PackEvent, PackOffer, PackTransferLimits};
use bedrock_protocol::{
    packets,
    types::{PackInfoData, PackInstanceId},
    wire,
};
use bytes::Bytes;
use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use sha2::{Digest, Sha256};

const VERSION: &str = "1.0.0";

/// Drives one offered pack from DataInfo through every in-order chunk and the final stack.
fn assemble(id: uuid::Uuid, archive: &Bytes, hash: &Bytes, chunk_size: usize) {
    let mut info = PackInfoData::default();
    info.pack_id_version.pack_uuid = id;
    info.pack_id_version.pack_version.version = VERSION.into();
    info.pack_size = wire::U64LE(archive.len() as u64);
    let offer = PackOffer::new(
        packets::ResourcePacksInfo {
            resource_packs: vec![info],
            ..Default::default()
        },
        PackTransferLimits::default(),
    )
    .unwrap();
    let (mut transfer, _) = offer.start().unwrap();
    let name: String = format!("{id}_{VERSION}");
    let count = archive.len().div_ceil(chunk_size);
    let PackEvent::Send(_) = transfer
        .receive(
            packets::ResourcePackDataInfo {
                resource_name: name.clone().into(),
                chunk_size: wire::U32LE(chunk_size as u32),
                number_of_chunks: wire::U32LE(count as u32),
                file_size: wire::U64LE(archive.len() as u64),
                file_hash: hash.clone(),
                is_premium_pack: false,
                pack_type: wire::U8(6),
            }
            .into(),
        )
        .unwrap()
    else {
        panic!("data info did not request chunks");
    };
    for index in 0..count {
        let start = index * chunk_size;
        let chunk = archive.slice(start..(start + chunk_size).min(archive.len()));
        let event = transfer
            .receive(
                packets::ResourcePackChunkData {
                    resource_name: name.clone().into(),
                    chunk_id: wire::U32LE(index as u32),
                    byte_offset: wire::U64LE(start as u64),
                    chunk_data: chunk,
                }
                .into(),
            )
            .unwrap();
        black_box(event);
    }
    let PackEvent::Finished(complete) = transfer
        .receive(
            packets::ResourcePackStack {
                texture_pack_list: vec![PackInstanceId {
                    pack_id: id.to_string().into(),
                    version: VERSION.into(),
                    ..Default::default()
                }],
                ..Default::default()
            }
            .into(),
        )
        .unwrap()
    else {
        panic!("stack did not finish the transfer");
    };
    // Verify the assembled handoff on every iteration, as the paired Go benchmark does.
    let (_, handoff) = complete.into_parts();
    let archives = handoff.into_archives();
    assert!(archives.len() == 1 && archives[0].archive.len() == archive.len());
    assert_eq!(Sha256::digest(&archives[0].archive)[..], hash[..]);
    black_box(archives);
}

fn packs(c: &mut Criterion) {
    let cases = common::Cases::load();
    let chunk_size = cases.u64("/packs/chunk_size") as usize;
    let id = uuid::Uuid::from_u128(1);
    let mut bench = c.benchmark_group("Packs");
    for (name, size) in cases.archives() {
        let archive = Bytes::from(cases.archive(&name, size));
        let hash = Bytes::copy_from_slice(&Sha256::digest(&archive));
        bench.throughput(Throughput::Bytes(size as u64));
        bench.bench_function(format!("assemble_verify_{name}"), |b| {
            b.iter(|| assemble(id, &archive, &hash, chunk_size))
        });
        bench.bench_function(format!("sha256_{name}"), |b| {
            b.iter(|| assert!(Sha256::digest(&archive)[..] == hash[..]))
        });
    }
    bench.finish();
}

criterion_group!(benches, packs);
criterion_main!(benches);
