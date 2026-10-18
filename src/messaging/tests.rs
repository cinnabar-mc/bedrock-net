use super::{Error, admit_established_connection};
use std::{cell::Cell, time::Duration};
use tokio::sync::oneshot;

/// An already-ready establishment cannot escape its original deadline on a delayed outer poll.
#[tokio::test(start_paused = true)]
async fn ready_establishment_cannot_escape_original_connect_deadline() {
    for delayed_poll in [false, true] {
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
        if delayed_poll {
            tokio::time::advance(Duration::from_secs(2)).await;
        }
        let result = connecting.await.unwrap();
        if delayed_poll {
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
