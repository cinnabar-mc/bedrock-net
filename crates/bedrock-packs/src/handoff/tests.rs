use super::*;

#[test]
fn relay_archives_transfer_once_without_changing_server_required_identity_or_order() {
    let id = uuid::Uuid::nil();
    let server = ResourcePackArchive::unencrypted(id, "1.0.0".into(), String::new(), vec![1, 2]);
    let mut handoff = ResourcePackHandoff::from_archives(vec![server])
        .with_required(true)
        .with_relay_packs(vec![
            RelayPack {
                archive: vec![3, 4],
                above_server: false,
            },
            RelayPack {
                archive: vec![5, 6],
                above_server: true,
            },
        ]);
    let added = handoff.take_relay_packs();
    assert!(handoff.take_relay_packs().is_empty());
    assert!(handoff.required());
    assert_eq!(handoff.len(), 1);
    assert!(!handoff.is_empty());
    assert_eq!(added[0].archive, [3, 4]);
    assert!(!added[0].above_server);
    assert_eq!(added[1].archive, [5, 6]);
    assert!(added[1].above_server);
    let archives = handoff.into_archives();
    assert_eq!(archives.len(), 1);
    assert_eq!(archives[0].pack_id, id);
    assert_eq!(archives[0].archive, [1, 2]);
}
