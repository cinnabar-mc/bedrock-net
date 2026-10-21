//! Actual Go comparisons for distinct typed, generic and standard JSON decoding contexts.
#![cfg(feature = "login")]

use base64::{Engine as _, engine::general_purpose::STANDARD};
use bedrock_net::login::parse_offline_request;
use serde_json::{Value, json};
use std::{
    io::{Read, Write},
    process::{Child, ChildStdin, ChildStdout, Command, Stdio},
    time::{Duration, UNIX_EPOCH},
};

struct Oracle {
    child: Child,
    input: Option<ChildStdin>,
    output: ChildStdout,
}

impl Oracle {
    /// Starts only the caller-configured synthetic helper; required-fixture runs cannot skip it.
    fn new() -> Option<Self> {
        let Some(binary) = std::env::var_os("BEDROCK_NET_GO_ORACLE") else {
            assert!(
                std::env::var_os("BEDROCK_NET_REQUIRE_FIXTURES").is_none(),
                "missing Go oracle"
            );
            return None;
        };
        let mut child = Command::new(binary)
            .arg("serve")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        Some(Self {
            input: child.stdin.take(),
            output: child.stdout.take().unwrap(),
            child,
        })
    }

    /// Reads the independently generated requests and actual pinned Go parser decisions.
    fn cases(&mut self) -> Vec<Value> {
        let request = serde_json::to_vec(&json!({"op":"offline_json_contexts"})).unwrap();
        let input = self.input.as_mut().unwrap();
        input
            .write_all(&(request.len() as u32).to_le_bytes())
            .unwrap();
        input.write_all(&request).unwrap();
        input.flush().unwrap();
        let mut size = [0; 4];
        self.output.read_exact(&mut size).unwrap();
        let mut response = vec![0; u32::from_le_bytes(size) as usize];
        self.output.read_exact(&mut response).unwrap();
        serde_json::from_slice(&response).unwrap()
    }
}

impl Drop for Oracle {
    /// Closes the helper's stdin and reaps its normal EOF exit without sending any signal.
    fn drop(&mut self) {
        drop(self.input.take());
        self.child.wait().unwrap();
    }
}

/// Compares every context, including ignored values, without skipping disagreements after a failure.
#[test]
fn offline_json_contexts_match_go() {
    let Some(mut oracle) = Oracle::new() else {
        return;
    };
    let fixtures = oracle.cases();
    assert_eq!(fixtures.len(), 128);
    let mut contexts = std::collections::BTreeMap::new();
    let mut mismatches = Vec::new();
    for case in fixtures {
        let context = case["context"].as_str().unwrap();
        assert!(matches!(
            context,
            "modern"
                | "legacy"
                | "header"
                | "metadata"
                | "outer"
                | "certificate"
                | "jwk"
                | "geometry"
        ));
        *contexts.entry(context.to_owned()).or_insert(0) += 1;
        let request = STANDARD.decode(case["request"].as_str().unwrap()).unwrap();
        let result = parse_offline_request(
            &request,
            UNIX_EPOCH + Duration::from_secs(1_800_000_000),
            request.len(),
            |_| panic!("numeric address"),
        );
        if result.is_ok() != case["accepted"].as_bool().unwrap() {
            mismatches.push(format!(
                "{context}/{}: {:?}",
                case["name"],
                result.as_ref().err()
            ));
        }
        if let Ok(login) = result {
            assert_eq!(login.display_name(), "MetadataName");
        }
    }
    assert_eq!(contexts.len(), 8);
    assert!(contexts.values().all(|count| *count == 16));
    assert!(
        mismatches.is_empty(),
        "JSON context mismatches: {mismatches:?}"
    );
}
