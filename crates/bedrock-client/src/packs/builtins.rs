//! Version-bound stack identities exempted by the pinned behavior reference.

use serde::Deserialize;
use std::sync::LazyLock;

#[derive(Deserialize)]
struct Catalog {
    protocol_version: i32,
    baseline_module_version: String,
    packs: Vec<BuiltinPack>,
}

#[derive(Deserialize)]
struct BuiltinPack {
    id: uuid::Uuid,
    version: String,
}

static CATALOG: LazyLock<Catalog> = LazyLock::new(|| {
    serde_json::from_str(include_str!("../../data/builtin-packs.json"))
        .expect("checked built-in pack catalog")
});

/// Go module version that defines this catalog's compatibility baseline.
/// Consumers with a Go fallback can bind their dependency pin to this value.
pub fn behavioral_baseline() -> &'static str {
    &CATALOG.baseline_module_version
}

/// Recognizes exact built-in identities; downloaded overrides remain ordinary archives.
pub(super) fn contains(id: uuid::Uuid, version: &str) -> bool {
    CATALOG.protocol_version == bedrock_protocol::PROTOCOL_VERSION
        && CATALOG
            .packs
            .iter()
            .any(|pack| pack.id == id && pack.version == version)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catalog_matches_the_generated_protocol_and_behavioral_baseline() {
        assert_eq!(CATALOG.protocol_version, bedrock_protocol::PROTOCOL_VERSION);
        let manifest = include_str!("../../../../tools/go-oracle/go.mod");
        let baseline = manifest
            .lines()
            .find(|line| {
                line.split_whitespace()
                    .take(2)
                    .eq(["replace", "github.com/sandertv/gophertunnel"])
            })
            .expect("pinned behavioral baseline")
            .split_whitespace()
            .last()
            .unwrap();
        assert_eq!(CATALOG.baseline_module_version, baseline);
        let mut identities = std::collections::BTreeSet::new();
        for pack in &CATALOG.packs {
            assert!(identities.insert((pack.id, &pack.version)));
        }
    }
}
