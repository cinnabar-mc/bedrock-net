use super::*;

/// Starts a two-pack exchange with optional relay metadata and no preloaded archives.
fn pending(metadata: bool) -> PackNegotiation {
    let info = packets::ResourcePacksInfo {
        resource_packs: vec![
            offer(uuid::Uuid::from_u128(1), 3),
            offer(uuid::Uuid::from_u128(2), 3),
        ],
        ..Default::default()
    };
    let offer = if metadata {
        PackOffer::new_with_metadata(info, PackTransferLimits::default())
    } else {
        PackOffer::new(info, PackTransferLimits::default())
    }
    .unwrap();
    offer.start().unwrap().0
}

/// Selects both advertised fixture archives in reverse application order.
fn selected() -> packets::ResourcePackStack {
    packets::ResourcePackStack {
        texture_pack_required: true,
        texture_pack_list: [2, 1]
            .map(|id| PackInstanceId {
                pack_id: uuid::Uuid::from_u128(id).to_string().into(),
                version: "1.0.0".into(),
                sub_pack_name: "selected".into(),
            })
            .to_vec(),
        ..Default::default()
    }
}

/// Supplies actual generated data metadata and checks its initial request effect.
fn begin(transfer: &mut PackNegotiation, id: u128) {
    assert!(matches!(transfer.receive(packets::ResourcePackDataInfo {
        resource_name: format!("{}_1.0.0", uuid::Uuid::from_u128(id)).into(),
        chunk_size: wire::U32LE(3), file_size: wire::U64LE(3),
        file_hash: Bytes::copy_from_slice(&Sha256::digest(b"abc")),
        ..Default::default()
    }.into()).unwrap(), PackEvent::Send(requests) if requests.len() == 1));
}

/// Supplies one full requested archive, with optional malformed length for terminal-state checks.
fn complete(
    transfer: &mut PackNegotiation,
    id: u128,
    data: &'static [u8],
) -> Result<PackEvent, PackError> {
    transfer.receive(
        packets::ResourcePackChunkData {
            resource_name: format!("{}_1.0.0", uuid::Uuid::from_u128(id)).into(),
            chunk_data: Bytes::from_static(data),
            ..Default::default()
        }
        .into(),
    )
}

/// An early selected stack must leave the original download usable for later replay.
#[test]
fn early_stack_does_not_seal_pending_downloads() {
    for metadata in [false, true] {
        for after_data_info in [false, true] {
            let mut transfer = pending(metadata);
            assert!(!transfer.ready_for_stack());
            if after_data_info {
                begin(&mut transfer, 1);
            }
            let stack = selected();
            let PackEvent::DeferredStack(deferred) =
                transfer.receive(stack.clone().into()).unwrap()
            else {
                panic!("an early stack must be returned for replay")
            };
            assert_eq!(*deferred, stack);
            assert!(!transfer.ready_for_stack());
            let unrelated = packets::Packet::from(packets::PlayStatus::default());
            assert!(
                matches!(transfer.receive(unrelated.clone()).unwrap(), PackEvent::Unhandled(packet) if *packet == unrelated)
            );
            if !after_data_info {
                begin(&mut transfer, 1);
            }
            assert!(sends(complete(&mut transfer, 1, b"abc").unwrap()).is_empty());
            assert!(
                !transfer.ready_for_stack(),
                "the other archive is still pending"
            );
            let cached = transfer
                .completed_archive(uuid::Uuid::from_u128(1))
                .unwrap();
            begin(&mut transfer, 2);
            let responses = sends(complete(&mut transfer, 2, b"abc").unwrap());
            assert!(matches!(
                responses.as_slice(),
                [packets::Packet::ResourcePackClientResponse(
                    packets::ResourcePackClientResponse {
                        response: ResourcePackClientResponseData::DownloadingFinished { .. }
                    }
                )]
            ));
            assert!(transfer.ready_for_stack());
            assert_eq!(cached.as_slice(), b"abc");
            drop(cached);
            let PackEvent::Finished(done) = transfer.receive((*deferred).into()).unwrap() else {
                panic!("replayed stack must complete")
            };
            let (response, handoff, retained) = done.into_parts_with_metadata();
            assert!(matches!(
                response.response,
                ResourcePackClientResponseData::ResourcePackStackFinished { .. }
            ));
            assert_eq!(retained.is_some(), metadata);
            if let Some(retained) = retained {
                assert_eq!(retained.stack, stack);
            }
            assert_eq!(
                handoff
                    .into_archives()
                    .iter()
                    .map(|a| a.pack_id)
                    .collect::<Vec<_>>(),
                [uuid::Uuid::from_u128(2), uuid::Uuid::from_u128(1)]
            );
            assert!(!transfer.ready_for_stack());
            assert!(
                transfer.receive(stack.into()).is_err(),
                "completion is single-use"
            );
        }
    }
}

/// Deferral postpones availability checks without weakening final required-stack validation.
#[test]
fn deferred_stack_is_validated_only_after_download_completion() {
    let mut transfer = pending(false);
    let mut stack = selected();
    stack.texture_pack_list[0].version = "unavailable".into();
    let PackEvent::DeferredStack(stack) = transfer.receive(stack.into()).unwrap() else {
        panic!("defer")
    };
    for id in [1, 2] {
        begin(&mut transfer, id);
        complete(&mut transfer, id, b"abc").unwrap();
    }
    assert!(transfer.ready_for_stack());
    assert!(transfer.receive((*stack).into()).is_err());
    assert!(!transfer.ready_for_stack());
    assert!(transfer.receive(selected().into()).is_err());
}

/// A malformed chunk remains terminal after an otherwise valid early stack was deferred.
#[test]
fn deferred_stack_does_not_reopen_a_failed_transfer() {
    let mut transfer = pending(false);
    assert!(matches!(
        transfer.receive(selected().into()).unwrap(),
        PackEvent::DeferredStack(_)
    ));
    begin(&mut transfer, 1);
    assert!(complete(&mut transfer, 1, b"a").is_err());
    assert!(!transfer.ready_for_stack());
    assert!(transfer.receive(selected().into()).is_err());
}
