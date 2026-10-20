//! Loads the shared inputs in `testdata/bench`, which the Go benches under `tools/go-oracle/bench` also read.

#![allow(dead_code)]

use std::collections::BTreeMap;
use std::path::PathBuf;

use serde_json::Value;

/// The shared manifest, `testdata/bench/cases.json`.
pub struct Cases {
    root: PathBuf,
    pub manifest: Value,
}

/// One benchmark operation over one packet set, named `op_set` on both sides.
pub struct Case {
    pub op: String,
    pub set: String,
}

impl Case {
    pub fn name(&self) -> String {
        format!("{}_{}", self.op, self.set)
    }
}

impl Cases {
    /// Reads the manifest relative to the workspace root.
    pub fn load() -> Self {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let root = root
            .ancestors()
            .find(|dir| dir.join("testdata/bench/cases.json").is_file())
            .expect("testdata/bench/cases.json above the crate")
            .join("testdata/bench");
        let manifest = serde_json::from_slice(&std::fs::read(root.join("cases.json")).unwrap())
            .expect("valid cases.json");
        Self { root, manifest }
    }

    pub fn read(&self, file: &str) -> Vec<u8> {
        std::fs::read(self.root.join(file)).unwrap()
    }

    /// Lists a manifest group's cases sorted by name, matching the Go side's order.
    pub fn cases(&self, group: &str) -> Vec<Case> {
        let mut out = Vec::new();
        for (key, sets) in self.manifest["benches"].as_object().unwrap() {
            let Some((g, op)) = key.split_once('/') else {
                continue;
            };
            if g != group {
                continue;
            }
            for set in sets.as_array().unwrap() {
                out.push(Case {
                    op: op.into(),
                    set: set.as_str().unwrap().into(),
                });
            }
        }
        assert!(!out.is_empty(), "cases.json lists no {group} cases");
        out.sort_by_key(Case::name);
        out
    }

    /// Expands a named packet set into its packets, in order.
    pub fn packets(&self, set: &str) -> Vec<Vec<u8>> {
        let spec = &self.manifest["packet_sets"][set];
        let base = split(&self.read(spec["file"].as_str().unwrap()));
        let repeat = spec["repeat"].as_u64().unwrap() as usize;
        let mut out = Vec::with_capacity(base.len() * repeat);
        for _ in 0..repeat {
            out.extend(base.iter().cloned());
        }
        out
    }

    /// Builds a pack archive of `size` bytes by repeating the pack source file.
    pub fn archive(&self, size: usize) -> Vec<u8> {
        let source = self.read(self.manifest["packs"]["source"].as_str().unwrap());
        let mut out = Vec::with_capacity(size);
        while out.len() < size {
            let take = source.len().min(size - out.len());
            out.extend_from_slice(&source[..take]);
        }
        out
    }

    pub fn archives(&self) -> BTreeMap<String, usize> {
        self.manifest["packs"]["archives"]
            .as_object()
            .unwrap()
            .iter()
            .map(|(name, size)| (name.clone(), size.as_u64().unwrap() as usize))
            .collect()
    }

    pub fn u64(&self, pointer: &str) -> u64 {
        self.manifest
            .pointer(pointer)
            .and_then(Value::as_u64)
            .unwrap()
    }

    pub fn str(&self, pointer: &str) -> &str {
        self.manifest
            .pointer(pointer)
            .and_then(Value::as_str)
            .unwrap()
    }
}

/// Total packet bytes, the throughput unit both sides report.
pub fn size(packets: &[Vec<u8>]) -> u64 {
    packets.iter().map(|packet| packet.len() as u64).sum()
}

/// Parses varuint32-length-prefixed entries.
fn split(mut data: &[u8]) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    while !data.is_empty() {
        let mut length = 0_u32;
        let mut shift = 0;
        loop {
            let byte = data[0];
            data = &data[1..];
            length |= u32::from(byte & 0x7f) << shift;
            shift += 7;
            if byte & 0x80 == 0 {
                break;
            }
        }
        let (entry, rest) = data.split_at(length as usize);
        out.push(entry.to_vec());
        data = rest;
    }
    out
}
