//! Owned wire leaves for opt-in metadata that outlives its decoded packet batch.

use bedrock_protocol::{packets, types, wire};
use bytes::Bytes;

/// Keeps exact wire bytes without retaining the source batch's unrelated packets.
fn string(value: wire::Str) -> wire::Str {
    Bytes::copy_from_slice(value.as_bytes()).into()
}

/// Detaches the original offer header and any retained admitted entries.
pub(super) fn offer(value: packets::ResourcePacksInfo) -> packets::ResourcePacksInfo {
    let packets::ResourcePacksInfo {
        resource_pack_required,
        has_addon_packs,
        has_scripts,
        force_disable_vibrant_visuals,
        world_template_id_and_version,
        resource_packs,
    } = value;
    let types::PackIdVersion {
        pack_uuid,
        pack_version: types::SemVersion { version },
    } = world_template_id_and_version;
    packets::ResourcePacksInfo {
        resource_pack_required,
        has_addon_packs,
        has_scripts,
        force_disable_vibrant_visuals,
        world_template_id_and_version: types::PackIdVersion {
            pack_uuid,
            pack_version: types::SemVersion {
                version: string(version),
            },
        },
        resource_packs: resource_packs.into_iter().map(pack).collect(),
    }
}

/// Detaches only admitted offer metadata; archive ownership stays with the transfer.
pub(super) fn pack(value: types::PackInfoData) -> types::PackInfoData {
    let types::PackInfoData {
        pack_id_version,
        pack_size,
        content_key,
        subpack_name,
        content_identity: types::ContentIdentity { identity },
        has_scripts,
        is_addon_pack,
        is_ray_tracing_capable,
        cdn_url,
    } = value;
    let types::PackIDVersionData {
        pack_uuid,
        pack_version: types::SemVersionData { version },
    } = pack_id_version;
    types::PackInfoData {
        pack_id_version: types::PackIDVersionData {
            pack_uuid,
            pack_version: types::SemVersionData {
                version: string(version),
            },
        },
        pack_size,
        content_key: string(content_key),
        subpack_name: string(subpack_name),
        content_identity: types::ContentIdentity {
            identity: string(identity),
        },
        has_scripts,
        is_addon_pack,
        is_ray_tracing_capable,
        cdn_url: string(cdn_url),
    }
}

/// Keeps validated transfer metadata after the original download consumed its packet.
pub(super) fn data(value: packets::ResourcePackDataInfo) -> packets::ResourcePackDataInfo {
    let packets::ResourcePackDataInfo {
        resource_name,
        chunk_size,
        number_of_chunks,
        file_size,
        file_hash,
        is_premium_pack,
        pack_type,
    } = value;
    packets::ResourcePackDataInfo {
        resource_name: string(resource_name),
        chunk_size,
        number_of_chunks,
        file_size,
        file_hash: Bytes::copy_from_slice(&file_hash),
        is_premium_pack,
        pack_type,
    }
}

/// Detaches final selected stack metadata after existing required/optional validation.
pub(super) fn stack(value: packets::ResourcePackStack) -> packets::ResourcePackStack {
    let packets::ResourcePackStack {
        texture_pack_required,
        texture_pack_list,
        base_game_version,
        experiments:
            types::Experiments {
                toggles,
                experiments_ever_toggled,
            },
        include_editor_packs,
    } = value;
    packets::ResourcePackStack {
        texture_pack_required,
        texture_pack_list: texture_pack_list
            .into_iter()
            .map(|value| {
                let types::PackInstanceId {
                    pack_id,
                    version,
                    sub_pack_name,
                } = value;
                types::PackInstanceId {
                    pack_id: string(pack_id),
                    version: string(version),
                    sub_pack_name: string(sub_pack_name),
                }
            })
            .collect(),
        base_game_version: string(base_game_version),
        experiments: types::Experiments {
            toggles: toggles
                .into_iter()
                .map(|value| {
                    let types::ExperimentToggle { name, enabled } = value;
                    types::ExperimentToggle {
                        name: string(name),
                        enabled,
                    }
                })
                .collect(),
            experiments_ever_toggled,
        },
        include_editor_packs,
    }
}
