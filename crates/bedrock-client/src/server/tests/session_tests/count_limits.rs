use super::*;
use crate::packs::builtin_packs;

/// Retains the original memory archive and its selected stack entry without copying pack metadata.
fn one_archive() -> ServerPackSnapshot {
    let mut source = snapshot();
    source.offer.resource_packs.truncate(1);
    source.contents.truncate(1);
    let id = source.offer.resource_packs[0]
        .pack_id_version
        .pack_uuid
        .to_string();
    source
        .stack
        .texture_pack_list
        .retain(|pack| pack.pack_id.to_str().unwrap() == id);
    source
}

/// Completes the original typed Login before asking the real delivery owner to admit one snapshot.
fn admits(source: ServerPackSnapshot) -> bool {
    let (server, _client, provider, now, utc) = ready_with_client(false);
    server
        .start_packs(
            source,
            ServerPackDelivery {
                limits: PackTransferLimits {
                    max_packs: Some(1),
                    ..Default::default()
                },
                chunk_size: CHUNK_BYTES,
                ..Default::default()
            },
            &provider,
            now,
            utc,
        )
        .is_ok()
}

/// Built-in stack selections need no offered archive and cannot consume the download-count budget.
#[test]
fn accepting_pack_count_limits_downloads_without_counting_builtin_stack_entries() {
    let plain = admits(one_archive());
    let two_downloads = admits(snapshot());
    let mut source = one_archive();
    let builtins = builtin_packs();
    assert_ne!(builtins.len(), 0, "current built-in catalog is required");
    source
        .stack
        .texture_pack_list
        .extend(builtins.map(|(id, version)| PackInstanceId {
            pack_id: id.to_string().into(),
            version: version.into(),
            sub_pack_name: Default::default(),
        }));
    let with_builtins = admits(source);

    assert!(plain, "one downloadable archive must fit its count budget");
    assert!(
        !two_downloads,
        "two downloadable archives exceed the budget"
    );
    assert!(
        with_builtins,
        "recognized built-in stack entries must not consume the archive count budget"
    );
}

/// Actual typed accepting admission retains complete metadata without allocating archive bodies.
#[test]
fn accepting_defaults_admit_complete_external_archive_metadata() {
    for sizes in [
        vec![1; 33],
        vec![65 * 1024 * 1024],
        vec![64 * 1024 * 1024; 3],
    ] {
        let mut source = ServerPackSnapshot {
            offer: packets::ResourcePacksInfo::default(),
            stack: packets::ResourcePackStack::default(),
            contents: Vec::new(),
        };
        for (index, size) in sizes.into_iter().enumerate() {
            let id = uuid::Uuid::from_u128(index as u128 + 1);
            let mut info = PackInfoData::default();
            info.pack_id_version.pack_uuid = id;
            info.pack_id_version.pack_version.version = "1.0.0".into();
            info.pack_size = wire::U64LE(size);
            source.offer.resource_packs.push(info);
            source.stack.texture_pack_list.push(PackInstanceId {
                pack_id: id.to_string().into(),
                version: "1.0.0".into(),
                ..Default::default()
            });
            source
                .contents
                .push(ServerPackContent::external(size, [0; 32], 6, false));
        }
        let (server, _client, provider, now, utc) = ready_with_client(false);
        assert!(
            server
                .start_packs(
                    source,
                    ServerPackDelivery {
                        chunk_size: CHUNK_BYTES,
                        ..Default::default()
                    },
                    &provider,
                    now,
                    utc
                )
                .is_ok(),
            "complete external archive metadata inherited local import limits"
        );
    }
}
