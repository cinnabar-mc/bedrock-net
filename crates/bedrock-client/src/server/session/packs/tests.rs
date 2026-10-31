//! Cross-language policy conformance against the actual existing pinned Go owners.

use super::*;
use serde::{Deserialize, Serialize};
use std::{
    io::Write,
    process::{Command, Stdio},
};

#[derive(Serialize)]
struct ChunkCase {
    size: u64,
    chunk_size: u32,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CountResult {
    count: u32,
    valid: bool,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DeliveryResult {
    default_chunk_size: u32,
    max_chunk_size: u32,
    counts: Vec<CountResult>,
}

#[test]
fn delivery_constants_and_chunk_indexes_match_actual_pinned_go_owner() {
    let Some(binary) = std::env::var_os("BEDROCK_NET_PACK_DELIVERY_ORACLE") else {
        // CI sets BEDROCK_NET_REQUIRE_FIXTURES so a dropped helper fails instead of skipping.
        assert!(
            std::env::var_os("BEDROCK_NET_REQUIRE_FIXTURES").is_none(),
            "missing fixture: BEDROCK_NET_PACK_DELIVERY_ORACLE; build tools/go-oracle/cmd/pack-delivery-check"
        );
        eprintln!(
            "missing fixture: BEDROCK_NET_PACK_DELIVERY_ORACLE; build tools/go-oracle/cmd/pack-delivery-check"
        );
        return;
    };
    // The same caller-authored inputs feed both languages; Go contains no duplicate test table.
    let cases = [
        (0, 1),
        (1, 0),
        (1, 1),
        (255, 256),
        (256, 256),
        (257, 256),
        (1_u64 << 31, 1),
        ((1_u64 << 31) + 1, 1),
        (u64::MAX, u32::MAX),
    ]
    .into_iter()
    .map(|(size, chunk_size)| ChunkCase { size, chunk_size })
    .collect::<Vec<_>>();
    let input = serde_json::to_vec(&cases).unwrap();
    let mut child = Command::new(binary)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("start the actual pinned Go delivery oracle");
    let written = child.stdin.take().unwrap().write_all(&input);
    let output = child.wait_with_output().expect("reap the delivery oracle");
    written.expect("write synthetic delivery cases");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let actual: DeliveryResult = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(DEFAULT_CHUNK_SIZE, actual.default_chunk_size);
    assert_eq!(MAX_CHUNK_SIZE, actual.max_chunk_size);
    assert_eq!(normalized_chunk_size(0), actual.default_chunk_size);
    assert_eq!(normalized_chunk_size(u32::MAX), actual.max_chunk_size);
    assert_eq!(actual.counts.len(), cases.len());
    for (input, output) in cases.iter().zip(actual.counts) {
        let expected = chunk_count(input.size, input.chunk_size);
        assert_eq!(expected.is_some(), output.valid);
        if let Some(expected) = expected {
            assert_eq!(expected, output.count);
        }
    }
}

/// Builds a synthetic advertised archive whose UUID contains alphabetic digits.
fn snapshot(size: usize) -> ServerPackSnapshot {
    let id = uuid::Uuid::parse_str("aabbccdd-eeff-4000-8000-aabbccddeeff").unwrap();
    ServerPackSnapshot {
        offer: packets::ResourcePacksInfo {
            resource_packs: if size == 0 {
                Vec::new()
            } else {
                vec![bedrock_protocol::types::PackInfoData {
                    pack_id_version: bedrock_protocol::types::PackIDVersionData {
                        pack_uuid: id,
                        pack_version: bedrock_protocol::types::SemVersionData {
                            version: "1.0.0".into(),
                        },
                    },
                    pack_size: wire::U64LE(size as u64),
                    ..Default::default()
                }]
            },
            ..Default::default()
        },
        stack: Default::default(),
        contents: if size == 0 {
            Vec::new()
        } else {
            vec![ServerPackContent::new(vec![1; size], 0, false)]
        },
    }
}

#[test]
fn delivery_checks_actual_chunks_against_metadata_and_archive_limits() {
    for size in [0, 1024] {
        let options = ServerPackDelivery {
            max_metadata_bytes: 64 * 1024,
            limits: PackTransferLimits {
                max_archive_bytes: Some(1024),
                ..Default::default()
            },
            ..Default::default()
        };
        assert!(
            Delivery::new(snapshot(size), options).is_ok(),
            "archive size {size}"
        );
    }
    assert!(
        Delivery::new(
            snapshot(70 * 1024),
            ServerPackDelivery {
                max_metadata_bytes: 64 * 1024,
                ..Default::default()
            }
        )
        .is_err()
    );
}

#[test]
fn download_and_chunk_routing_use_uuid_identity() {
    let delivery = Delivery::new(snapshot(1024), ServerPackDelivery::default()).unwrap();
    for name in [
        "aabbccdd-eeff-4000-8000-aabbccddeeff",
        "AABBCCDD-EEFF-4000-8000-AABBCCDDEEFF",
    ] {
        for check_version in [false, true] {
            assert_eq!(
                delivery
                    .lookup(&format!("{name}_1.0.0").into(), check_version)
                    .unwrap(),
                0
            );
            assert_eq!(delivery.lookup(&name.into(), check_version).unwrap(), 0);
        }
        assert!(
            delivery
                .lookup(&format!("{name}_2.0.0").into(), true)
                .is_err()
        );
        assert_eq!(
            delivery
                .lookup(&format!("{name}_2.0.0").into(), false)
                .unwrap(),
            0
        );
    }
}
