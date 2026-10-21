//! Actual Go comparisons for offline JOSE shapes and retained outer chain arrays.
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
    fn shapes(&mut self) -> Vec<Value> {
        let request = serde_json::to_vec(&json!({"op":"offline_shapes"})).unwrap();
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

/// Compares every case in the selected independent shape group and reports all mismatches.
fn compare(group: &str) {
    let Some(mut oracle) = Oracle::new() else {
        return;
    };
    let fixtures = oracle.shapes();
    assert!(
        fixtures
            .iter()
            .all(|case| matches!(case["group"].as_str(), Some("chain" | "header")))
    );
    let mut mismatches = Vec::new();
    let mut count = 0;
    for case in fixtures.iter().filter(|case| case["group"] == group) {
        count += 1;
        let request = STANDARD.decode(case["request"].as_str().unwrap()).unwrap();
        let result = parse_offline_request(
            &request,
            UNIX_EPOCH + Duration::from_secs(1_800_000_000),
            request.len(),
            |_| panic!("numeric address"),
        );
        if result.is_ok() != case["accepted"].as_bool().unwrap() {
            mismatches.push(format!("{}: {:?}", case["name"], result.as_ref().err()));
        }
        if let Ok(login) = result {
            assert_eq!(login.display_name(), "MetadataName");
        }
    }
    assert_eq!(count, if group == "chain" { 24 } else { 129 });
    assert!(mismatches.is_empty(), "{group} mismatches: {mismatches:?}");
}

/// Folded aliases reuse prior string slots through truncation and re-extension.
#[test]
fn chain_arrays_match_go() {
    compare("chain");
}

/// Modern headers still decode JOSE types while skipping signature and critical policy.
#[test]
fn jose_headers_match_go() {
    compare("header");
}
