// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

use super::*;

#[cfg(feature = "nethernet")]
mod accepting_boundaries;

/// Uses the actual generated encoder, retaining the original complete header/body.
fn packet_bytes(header: wire::PacketHeader, packet: &packets::Packet) -> Bytes {
    let mut batch = Vec::new();
    wire::encode_frame_with(&mut batch, header, usize::MAX, |writer| {
        packet.encode(writer)
    })
    .unwrap();
    let batch = Bytes::from(batch);
    let mut reader = wire::Reader::from_shared(&batch);
    reader.read_var_u32().unwrap();
    batch.slice(reader.position()..)
}

#[test]
fn early_native_packets_keep_original_subclient_headers_and_fifo() {
    let first = packets::Packet::from(packets::SetTime {
        time: wire::ZigZag32(1),
    });
    let first_header = wire::PacketHeader {
        id: first.id() as u32,
        sender_subclient: 1,
        target_subclient: 2,
    };
    let second = packets::Packet::from(packets::SetTime {
        time: wire::ZigZag32(2),
    });
    let second_header = wire::PacketHeader::new(second.id() as u32);
    let original = [
        packet_bytes(first_header, &first),
        packet_bytes(second_header, &second),
    ];
    let mut deferred = DeferredFrames::new(BatchLimits::default().max_decoded_bytes);
    for bytes in &original {
        deferred.push(bytes.clone()).unwrap();
    }
    let retained = deferred.take();
    assert_eq!(
        retained.iter().map(deferred::encoded).collect::<Vec<_>>(),
        original
    );
    let decoded = retained
        .into_iter()
        .map(|frame| {
            let body = frame.body();
            let mut reader = wire::Reader::from_shared(&body);
            let packet = packets::Packet::decode_body(
                packets::PacketId::from_raw(frame.id()).unwrap(),
                &mut reader,
            )
            .unwrap();
            reader.expect_consumed().unwrap();
            (frame.header(), packet)
        })
        .collect::<Vec<_>>();
    assert_eq!(decoded, [(first_header, first), (second_header, second)]);
}

#[test]
fn early_native_packets_share_the_existing_aggregate_startup_byte_bound() {
    let maximum = BatchLimits::default().max_decoded_bytes;
    let chunk = packets::Packet::from(packets::LevelChunk {
        serialized_chunk_data: vec![0; maximum / 2].into(),
        ..Default::default()
    });
    let bytes = packet_bytes(wire::PacketHeader::new(chunk.id() as u32), &chunk);
    let mut deferred = DeferredFrames::new(maximum);
    deferred.push(bytes.clone()).unwrap();
    let error = deferred.push(bytes).unwrap_err();
    assert!(
        matches!(error.get_ref().and_then(|error| error.downcast_ref::<super::super::error::DeferredLimit>()), Some(super::super::error::DeferredLimit { maximum: limit, .. }) if *limit == maximum)
    );
    let retained = deferred.take();
    assert_eq!(retained.len(), 1);
    let body = retained[0].body();
    let mut reader = wire::Reader::from_shared(&body);
    assert_eq!(
        packets::Packet::decode_body(chunk.id(), &mut reader).unwrap(),
        chunk
    );
    reader.expect_consumed().unwrap();
}

#[test]
fn deferred_prefix_keeps_ignored_header_bits_without_reencoding() {
    let mut raw = Vec::new();
    wire::Writer::new(&mut raw)
        .write_var_u32(packets::SetTime::ID | (1 << 10) | (2 << 12) | (1 << 22))
        .unwrap();
    let mut body = Vec::new();
    packets::Packet::from(packets::SetTime {
        time: wire::ZigZag32(3),
    })
    .encode(&mut wire::Writer::new(&mut body))
    .unwrap();
    raw.extend_from_slice(&body);
    let raw = Bytes::from(raw);
    let mut deferred = DeferredFrames::new(BatchLimits::default().max_decoded_bytes);
    deferred.push(raw.clone()).unwrap();
    assert_eq!(deferred::encoded(&deferred.take().pop().unwrap()), raw);
}
