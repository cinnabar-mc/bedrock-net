use super::{Error, admit_established_connection};
use std::{cell::Cell, time::Duration};
use tokio::sync::oneshot;

/// An already-ready establishment cannot escape its original deadline on a delayed outer poll.
#[tokio::test(start_paused = true)]
async fn ready_establishment_cannot_escape_original_connect_deadline() {
    for delay in [
        Duration::ZERO,
        Duration::from_secs(1),
        Duration::from_secs(2),
    ] {
        let closed = Cell::new(false);
        let deadline = tokio::time::Instant::now() + Duration::from_secs(1);
        let (complete, established) = oneshot::channel();
        let connecting = tokio::time::timeout_at(deadline, async {
            established.await.unwrap();
            admit_established_connection(deadline.into_std(), async {
                closed.set(true);
            })
            .await
        });
        complete.send(()).unwrap();
        if !delay.is_zero() {
            tokio::time::advance(delay).await;
        }
        let result = connecting.await.unwrap();
        if delay >= Duration::from_secs(1) {
            assert!(
                matches!(result, Err(Error::TimedOut)),
                "ready connection escaped its original connect deadline"
            );
            assert!(closed.get(), "late ready connection was not retired");
        } else {
            result.unwrap();
            assert!(
                !closed.get(),
                "timely connection was retired before handoff"
            );
        }
    }
}

mod ice;
