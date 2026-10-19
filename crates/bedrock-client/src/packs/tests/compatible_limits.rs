use super::*;

#[test]
fn default_transfer_admits_valid_metadata_beyond_local_import_limits_without_allocating_archives() {
    let cases = [
        // These metadata-only fixtures cross the former local import defaults.
        ("count", vec![1; 33]),
        ("archive", vec![65 * 1024 * 1024]),
        ("stack", vec![64 * 1024 * 1024; 3]),
    ];
    let mut observations = Vec::new();
    for (name, sizes) in cases {
        let offers = sizes
            .iter()
            .enumerate()
            .map(|(index, size)| offer(uuid::Uuid::from_u128(index as u128 + 1), *size))
            .collect();
        let admitted = PackOffer::new(
            packets::ResourcePacksInfo {
                resource_packs: offers,
                ..Default::default()
            },
            PackTransferLimits::default(),
        )
        .unwrap();
        let retained = admitted.offers().count();
        let (_, response) = admitted.start().unwrap();
        let requested = match response.response {
            ResourcePackClientResponseData::Downloading {
                downloading_packs, ..
            } => downloading_packs.len(),
            _ => 0,
        };
        observations.push((name, retained == sizes.len() && requested == sizes.len()));
    }

    let id = uuid::Uuid::from_u128(100);
    let (mut transfer, _) = PackOffer::new(
        packets::ResourcePacksInfo {
            resource_packs: vec![offer(id, 1)],
            ..Default::default()
        },
        PackTransferLimits::default(),
    )
    .unwrap()
    .start()
    .unwrap();
    // DataInfo may correct an offer size. No chunk body or source archive is allocated here.
    let result = transfer.receive(
        packets::ResourcePackDataInfo {
            resource_name: format!("{id}_1.0.0").into(),
            chunk_size: wire::U32LE(u32::MAX),
            file_size: wire::U64LE(257 * 1024 * 1024),
            file_hash: Bytes::from_static(&[0; 32]),
            ..Default::default()
        }
        .into(),
    );
    observations.push((
        "corrected transfer size",
        matches!(result, Ok(PackEvent::Send(requests)) if requests.len() == 1),
    ));
    assert!(
        observations.iter().all(|(_, admitted)| *admitted),
        "valid server metadata inherited local import limits: {observations:?}"
    );
}
