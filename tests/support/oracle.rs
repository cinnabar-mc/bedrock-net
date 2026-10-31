//! Bounded, caller-owned subprocess I/O for the synthetic Go fixtures.

use serde_json::Value;
use std::{io, process::Stdio, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    process::{Child, ChildStdin, ChildStdout, Command},
    runtime::{Builder, Runtime},
};

/// One framed helper with bounded requests and explicit process cleanup.
pub struct Oracle {
    runtime: Runtime,
    child: Child,
    input: Option<ChildStdin>,
    output: ChildStdout,
    timeout: Duration,
}

impl Oracle {
    /// Starts the configured framed helper; designated fixture runs cannot silently skip it.
    pub fn configured() -> Option<Self> {
        let Some(binary) = std::env::var_os("BEDROCK_NET_GO_ORACLE") else {
            assert!(
                std::env::var_os("BEDROCK_NET_REQUIRE_FIXTURES").is_none(),
                "missing fixture: BEDROCK_NET_GO_ORACLE; build tools/go-oracle"
            );
            return None;
        };
        let mut command = Command::new(binary);
        command.arg("serve");
        Some(Self::spawn(command, Duration::from_secs(30)).expect("start go-oracle serve"))
    }

    /// Owns one helper, its pipes and the runtime that enforces each operation's cutoff.
    fn spawn(mut command: Command, timeout: Duration) -> io::Result<Self> {
        let runtime = Builder::new_current_thread().enable_all().build()?;
        let mut child = {
            let _entered = runtime.enter();
            command
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .kill_on_drop(true)
                .spawn()?
        };
        Ok(Self {
            input: child.stdin.take(),
            output: child.stdout.take().unwrap(),
            child,
            runtime,
            timeout,
        })
    }

    /// Writes and reads one complete frame under one deadline, reaping a failed helper.
    pub fn call(&mut self, request: Value) -> Value {
        self.exchange(request)
            .expect("complete framed Go oracle request")
    }

    /// Keeps writes, flush, response length and response body within the same operation budget.
    fn exchange(&mut self, request: Value) -> io::Result<Value> {
        let request = serde_json::to_vec(&request)?;
        let result = self.runtime.block_on(async {
            tokio::time::timeout(self.timeout, async {
                let input = self
                    .input
                    .as_mut()
                    .ok_or_else(|| io::Error::from(io::ErrorKind::BrokenPipe))?;
                input
                    .write_all(&(request.len() as u32).to_le_bytes())
                    .await?;
                input.write_all(&request).await?;
                input.flush().await?;
                let size = self.output.read_u32_le().await?;
                let mut response = vec![0; size as usize];
                self.output.read_exact(&mut response).await?;
                serde_json::from_slice(&response).map_err(io::Error::from)
            })
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "Go oracle request timed out"))?
        });
        if result.is_err() {
            self.stop();
        }
        result
    }

    /// Closes stdin and bounds normal exit; a helper ignoring EOF is terminated and reaped.
    pub fn finish(&mut self) -> io::Result<()> {
        self.input.take();
        let result = self.runtime.block_on(async {
            tokio::time::timeout(self.timeout, self.child.wait())
                .await
                .map_err(|_| {
                    io::Error::new(io::ErrorKind::TimedOut, "Go oracle shutdown timed out")
                })?
        });
        match result {
            Ok(status) if status.success() => Ok(()),
            Ok(status) => Err(io::Error::other(format!("Go oracle exited with {status}"))),
            Err(error) => {
                self.stop();
                Err(error)
            }
        }
    }

    /// Terminates only this owned child and reaps it before releasing its runtime and pipes.
    fn stop(&mut self) {
        self.input.take();
        let _ = self.child.start_kill();
        let _ = self.runtime.block_on(self.child.wait());
    }
}

impl Drop for Oracle {
    /// Cleanup during unwinding cannot wait indefinitely for cooperative helper shutdown.
    fn drop(&mut self) {
        self.stop();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::io::{Read, Write};

    /// Runs in an explicitly selected child test process, with no timer or sleeping thread.
    #[test]
    fn child_fixture() {
        let Ok(mode) = std::env::var("BEDROCK_ORACLE_STALL_FIXTURE") else {
            return;
        };
        println!("\nORACLE_READY");
        std::io::stdout().flush().unwrap();
        if mode != "write" {
            let mut size = [0; 4];
            std::io::stdin().read_exact(&mut size).unwrap();
            let mut request = vec![0; u32::from_le_bytes(size) as usize];
            std::io::stdin().read_exact(&mut request).unwrap();
            match mode.as_str() {
                "header" => std::io::stdout().write_all(&[2, 0]).unwrap(),
                "body" => std::io::stdout().write_all(&[2, 0, 0, 0, b'[']).unwrap(),
                "shutdown" => std::io::stdout()
                    .write_all(&[2, 0, 0, 0, b'[', b']'])
                    .unwrap(),
                _ => panic!("unknown fixture"),
            }
            std::io::stdout().flush().unwrap();
        }
        let (_sender, receiver) = std::sync::mpsc::channel::<()>();
        receiver.recv().unwrap();
    }

    /// Separates the test harness preamble from binary fixture output without buffering frames.
    fn stalled(mode: &str) -> Oracle {
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .args([
                "--exact",
                "oracle_support::tests::child_fixture",
                "--nocapture",
            ])
            .env("BEDROCK_ORACLE_STALL_FIXTURE", mode);
        let mut oracle = Oracle::spawn(command, Duration::from_millis(150)).unwrap();
        oracle.runtime.block_on(async {
            tokio::time::timeout(Duration::from_secs(5), async {
                let mut preamble = Vec::new();
                while !preamble.ends_with(b"ORACLE_READY\n") {
                    preamble.push(oracle.output.read_u8().await.unwrap());
                }
            })
            .await
            .unwrap();
        });
        oracle
    }

    #[test]
    fn blocked_writes_and_incomplete_responses_time_out_and_reap_the_child() {
        for mode in ["write", "header", "body"] {
            let mut oracle = stalled(mode);
            let error = oracle
                .exchange(json!({"padding":"x".repeat(1024 * 1024)}))
                .unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::TimedOut, "{mode}: {error}");
            assert!(
                oracle.child.try_wait().unwrap().is_some(),
                "{mode}: child was not reaped"
            );
        }
    }

    #[test]
    fn helper_ignoring_eof_times_out_and_is_reaped() {
        let mut oracle = stalled("shutdown");
        let response: Value = oracle.call(json!({"op":"fixture"}));
        assert_eq!(response, json!([]));
        let error = oracle.finish().unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert!(oracle.child.try_wait().unwrap().is_some());
    }
}
