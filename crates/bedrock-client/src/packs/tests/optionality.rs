//! Offer requirement and final-stack entry admission are separate wire facts.

use super::*;

/// Supplies one original acquired archive, then processes the server's real generated stack.
fn complete(
    offer_required: bool,
    stack_required: bool,
    extra: PackInstanceId,
) -> Result<PackComplete, PackError> {
    let id = uuid::Uuid::from_u128(1);
    let bytes = fixture_bytes(id);
    let mut offer = PackOffer::new_with_metadata(
        packets::ResourcePacksInfo {
            resource_pack_required: offer_required,
            resource_packs: vec![offer(id, bytes.len())],
            ..Default::default()
        },
        PackTransferLimits::default(),
    )?;
    offer.supply_preloaded(id, bytes)?;
    let (mut transfer, _) = offer.start()?;
    let stack = packets::ResourcePackStack {
        texture_pack_required: stack_required,
        texture_pack_list: vec![
            PackInstanceId {
                pack_id: id.to_string().into(),
                version: "1.0.0".into(),
                sub_pack_name: "original-selected".into(),
            },
            extra,
        ],
        ..Default::default()
    };
    let PackEvent::Finished(complete) = transfer.receive(server_wire(stack.into()))? else {
        panic!("the actual final stack must complete the original transfer");
    };
    Ok(complete)
}

/// Well-framed unused, invalid-identity and repeated rows follow the same final-stack policy.
fn extra_rows() -> [PackInstanceId; 3] {
    [
        PackInstanceId {
            pack_id: uuid::Uuid::from_u128(2).to_string().into(),
            version: "1.0.0".into(),
            ..Default::default()
        },
        PackInstanceId {
            pack_id: "not-a-pack-identity".into(),
            version: "1.0.0".into(),
            ..Default::default()
        },
        PackInstanceId {
            pack_id: uuid::Uuid::from_u128(1).to_string().into(),
            version: "1.0.0".into(),
            ..Default::default()
        },
    ]
}

/// Checks acquired bytes and retained actual metadata after optional rows are excluded.
fn optional_stack(offer_required: bool) {
    for extra in extra_rows() {
        let repeated = extra.pack_id.to_str().unwrap() == uuid::Uuid::from_u128(1).to_string();
        let complete = complete(offer_required, false, extra)
            .expect("an optional final stack must not require its unused or repeated rows");
        let (_, handoff, metadata) = complete.into_parts_with_metadata();
        assert_eq!(handoff.required(), offer_required);
        let archives = handoff.into_archives();
        assert_eq!(archives.len(), 1);
        assert_eq!(archives[0].archive, fixture_bytes(uuid::Uuid::from_u128(1)));
        assert_eq!(archives[0].sub_pack_name, "original-selected");
        let metadata = metadata.expect("original wire metadata was explicitly retained");
        assert_eq!(metadata.offer.resource_pack_required, offer_required);
        assert!(!metadata.stack.texture_pack_required);
        assert_eq!(metadata.offer.resource_packs.len(), 1);
        assert_eq!(
            metadata.stack.texture_pack_list.len(),
            if repeated { 2 } else { 1 }
        );
        assert_eq!(metadata.data.len(), 1);
        assert!(metadata.data[0].is_none(), "preload invented no DataInfo");
    }
}

#[test]
fn final_stack_optionality_required_offer_preserves_optional_selection() {
    optional_stack(true);
}

#[test]
fn final_stack_optionality_optional_offer_preserves_optional_selection() {
    optional_stack(false);
}

#[test]
fn final_stack_optionality_required_stack_still_refuses_unavailable_rows() {
    for offer_required in [false, true] {
        for extra in extra_rows().into_iter().take(2) {
            assert!(complete(offer_required, true, extra).is_err());
        }
    }
}
