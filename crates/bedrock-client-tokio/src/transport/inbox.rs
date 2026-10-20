// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! Bounded wire input retained while its original transport keeps progressing.

use bytes::Bytes;
#[cfg(any(test, feature = "nethernet", feature = "test-support"))]
use futures::{Stream, StreamExt};
#[cfg(any(test, feature = "nethernet", feature = "test-support"))]
use std::future::Future;
use std::{collections::VecDeque, io};

/// Bounded original wire prefix with one refused head, for transport integration fixtures.
pub struct Inbox {
    messages: VecDeque<Bytes>,
    bytes: usize,
    pending_message: Option<Bytes>,
    max_bytes: usize,
    max_packets: usize,
}

impl Default for Inbox {
    fn default() -> Self {
        let limits = bedrock_net::BatchLimits::default();
        Self {
            messages: VecDeque::new(),
            bytes: 0,
            pending_message: None,
            max_bytes: limits.max_encoded_bytes,
            max_packets: limits.max_packets,
        }
    }
}

impl Inbox {
    /// Binds the connection caller's existing wire/count limits without discarding admitted input.
    pub(super) fn configure_limits(&mut self, limits: bedrock_net::BatchLimits) {
        self.max_bytes = limits.max_encoded_bytes;
        self.max_packets = limits.max_packets;
    }
    /// Releases the charged FIFO prefix before its one unadmitted wire head.
    pub fn pop(&mut self) -> Option<Bytes> {
        if let Some(message) = self.messages.pop_front() {
            self.bytes -= message.len();
            Some(message)
        } else {
            self.pending_message.take()
        }
    }

    /// Retains one bounded wire message for the ordinary decoder to consume later.
    #[cfg(test)]
    pub fn push(&mut self, message: Bytes) -> io::Result<()> {
        match self.try_push(message)? {
            None => Ok(()),
            Some(_) => Err(Self::full_error()),
        }
    }

    /// Stops reads at the original FIFO bound or while its one legal refused head is retained.
    pub fn is_full(&self) -> bool {
        self.pending_message.is_some()
            || self.bytes >= self.max_bytes
            || self.messages.len() >= self.max_packets
    }

    /// Returns the same unadmitted head on aggregate pressure without changing the FIFO.
    pub fn try_push(&mut self, message: Bytes) -> io::Result<Option<Bytes>> {
        let bytes = self
            .bytes
            .checked_add(message.len())
            .ok_or_else(|| io::Error::other("native wire receive budget overflow"))?;
        if message.len() > self.max_bytes {
            return Err(Self::full_error());
        }
        if self.pending_message.is_some()
            || bytes > self.max_bytes
            || self.messages.len() >= self.max_packets
        {
            return Ok(Some(message));
        }
        self.bytes = bytes;
        self.messages.push_back(message);
        Ok(None)
    }

    /// Keeps a just-read legal head outside the full FIFO without accepting a successor.
    /// Callers stop application reads until pop releases this same retained body.
    #[cfg(any(test, feature = "nethernet", feature = "test-support"))]
    pub fn retain(&mut self, message: Bytes) -> io::Result<()> {
        if self.pending_message.is_some() {
            return Err(Self::full_error());
        }
        self.pending_message = self.try_push(message)?;
        Ok(())
    }

    /// Shares the original write-side EOF diagnostic between the concrete input owners.
    #[cfg(any(test, feature = "nethernet", feature = "test-support"))]
    pub fn closed_during_write() -> io::Error {
        io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "NetherNet peer closed during write",
        )
    }

    /// Preserves the strict admission failure diagnostic for all original callers.
    fn full_error() -> io::Error {
        io::Error::other("native wire receive queue is full")
    }

    /// Polls the same write while its independently driven actor retains paused input.
    #[cfg(any(test, feature = "nethernet", feature = "test-support"))]
    pub async fn send<T>(
        &mut self,
        sending: impl Future<Output = io::Result<T>> + Send,
        incoming: impl Stream<Item = io::Result<Bytes>> + Send,
    ) -> io::Result<T> {
        tokio::pin!(sending, incoming);
        loop {
            tokio::select! {
                biased;
                result = &mut sending => return result,
                message = incoming.next(), if !self.is_full() => {
                    self.retain(message.ok_or_else(Self::closed_during_write)??)?;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::sync::{mpsc, oneshot};

    #[test]
    fn byte_pressure_preserves_the_unadmitted_head_and_strict_fifo_contract() {
        let limit = bedrock_net::BatchLimits::default().max_encoded_bytes;
        let first = Bytes::from(vec![0xfe; limit.checked_sub(1).unwrap()]);
        let head = Bytes::from_static(b"head");
        assert!(head.len() <= limit);
        let mut inbox = Inbox::default();
        inbox.push(first.clone()).unwrap();
        assert!(!inbox.is_full());
        assert!(
            inbox.push(head.clone()).is_err(),
            "strict insertion must still reject aggregate overflow"
        );
        let head = inbox
            .try_push(head)
            .unwrap()
            .expect("the original body must survive aggregate refusal");
        assert_eq!(head.as_ref(), b"head");
        assert_eq!(inbox.pop().unwrap(), first);
        assert!(inbox.pop().is_none(), "refusal changed the original FIFO");
        assert!(!inbox.is_full());
        assert!(inbox.try_push(head).unwrap().is_none());
        assert_eq!(inbox.pop().unwrap().as_ref(), b"head");
        assert!(inbox.pop().is_none());
    }

    #[tokio::test(start_paused = true)]
    async fn write_completes_when_the_driver_must_deliver_input_before_accepting_it() {
        let (send, mut receive) = mpsc::channel(1);
        let (accepted, completion) = oneshot::channel();
        let peer = async move {
            send.send(Bytes::from_static(b"first")).await.unwrap();
            send.send(Bytes::from_static(b"second")).await.unwrap();
            let _ = accepted.send(());
        };
        let incoming = futures::stream::unfold(&mut receive, |receive| async move {
            receive.recv().await.map(|message| (Ok(message), receive))
        });
        let mut inbox = Inbox::default();
        let write = inbox.send(
            async { completion.await.map_err(io::Error::other) },
            incoming,
        );
        let result = tokio::time::timeout(std::time::Duration::from_secs(1), async {
            tokio::join!(write, peer).0
        })
        .await;
        assert!(
            result.is_ok(),
            "write waited for input that only its owner can consume"
        );
        result.unwrap().unwrap();
        assert_eq!(inbox.pop().unwrap(), b"first"[..]);
        let second = match inbox.pop() {
            Some(message) => message,
            None => receive.recv().await.unwrap(),
        };
        assert_eq!(second, b"second"[..]);
    }
}

#[cfg(test)]
mod backpressure_tests;
