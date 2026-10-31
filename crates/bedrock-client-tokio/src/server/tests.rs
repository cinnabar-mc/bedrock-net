// SPDX-License-Identifier: MIT

//! Cancellation and batch ordering on actual signed accepted HTTP/DTLS/SCTP owners.

use super::test_support::{
    SignedPair, TIMEOUT, drain, signed_pair_with_key, signed_pair_with_server_bind,
};
use super::*;
use crate::connection::send::SendOutcome;
use bedrock_net::{BatchCodec, BatchLimits, DecodeOutcome};
use bedrock_protocol::{
    packets::SetTime,
    wire::{self, Encode},
};
use nethernet_tokio::{SendPermit, SessionSender};
use p384::elliptic_curve::Generate;
use std::{
    future::poll_fn,
    net::{Ipv4Addr, UdpSocket},
    pin::pin,
    task::Poll,
    time::Duration,
};

const MARKER: &[u8] = b"prepared-send-reliable-marker";

mod batching;
mod limits_and_time;

/// Uses the fixture's one-batch deferred bound without importing application policy.
fn deferred_bound() -> usize {
    BatchLimits::default().max_decoded_bytes
}

/// A saved listener identity supplies the same proof to signaling and Bedrock after restart.
#[tokio::test]
async fn saved_listener_identity_reuses_one_proof_for_both_layers() {
    let directory = std::env::temp_dir().join(format!("bedrock-listener-{}", uuid::Uuid::new_v4()));
    let path = directory.join("identity.pem");
    let (key, identity) = super::load_identity(&path, "self").await.unwrap();
    let (reloaded, signaling) = super::load_identity(&path, "self").await.unwrap();
    assert_eq!(key.verifying_key(), reloaded.verifying_key());
    assert_eq!(identity.verifying_key(), reloaded.verifying_key());
    assert_eq!(signaling.verifying_key(), reloaded.verifying_key());
    std::fs::remove_dir_all(directory).unwrap();
}

/// Establishes the real signed association before retaining application queue capacity.
async fn signed_pair() -> SignedPair {
    signed_pair_with_key(Arc::new(SigningKey::generate()), deferred_bound())
        .await
        .0
}

#[tokio::test]
async fn actual_accepting_owner_keeps_the_original_incoming_packet_count_policy() {
    tokio::time::timeout(TIMEOUT, async {
        let mut pair = signed_pair().await;
        let limits = BatchLimits::default();
        let count = limits.max_packets + 1;
        let packets = vec![raw_packet(1); count];
        let mut messages = BatchCodec::new(BatchLimits {
                max_packets: count,
                ..limits
            },
        )
        .encode(&packets)
        .unwrap();
        assert_eq!(messages.len(), 1);
        pair.client.send(messages.remove(0)).await.unwrap();
        let received = pair
            .wire
            .receive_raw(tokio::time::Instant::now().into_std() + TIMEOUT)
            .await;
        assert!(pair.finish().await, "original signed accepting owners leaked");
        let error = received.expect_err("the serving role lost its original incoming count policy");
        assert!(matches!(
            error.get_ref().and_then(|error| error.downcast_ref::<bedrock_net::BatchError>()),
            Some(bedrock_net::BatchError::TooManyPackets { maximum }) if *maximum == limits.max_packets
        ));
    })
    .await
    .expect("finite actual accepting count policy fixture stalled");
}

#[tokio::test]
async fn cancelled_borrows_retain_reservation_permit_receipt_and_batch_order() {
    tokio::time::timeout(TIMEOUT, async {
        let mut pair = signed_pair().await;
        let deadline = tokio::time::Instant::now().into_std() + TIMEOUT;
        let first = [raw_packet(1), raw_packet(4)];
        let second = raw_packet(2);
        let mut held = fill_capacity(&pair.sender).await;
        let empty_complete = {
            let mut empty = pair.wire.prepare_packets(Vec::new(), deadline).unwrap();
            let complete = empty.next().await.unwrap().is_none();
            empty.finish().unwrap();
            complete
        };
        let reserve_pending = {
            let mut sending = pair
                .wire
                .prepare_packets(
                    vec![
                        SetTime {
                            time: wire::ZigZag32(1),
                        }
                        .into(),
                        SetTime {
                            time: wire::ZigZag32(4),
                        }
                        .into(),
                    ],
                    deadline,
                )
                .unwrap();
            let mut next = pin!(sending.next());
            poll_fn(|cx| Poll::Ready(next.as_mut().poll(cx).is_pending())).await
        };
        let mut later = Box::pin(pair.sender.reserve_send(None));
        let later_pending = poll_fn(|cx| Poll::Ready(later.as_mut().poll(cx).is_pending())).await;
        drop(held.pop());
        let same_reservation_granted = {
            let mut sending = pair.wire.resume_send().unwrap();
            let granted = {
                let mut next = pin!(sending.next());
                poll_fn(|cx| {
                    Poll::Ready(matches!(next.as_mut().poll(cx), Poll::Ready(Ok(Some(_)))))
                })
                .await
            };
            drop(later);
            {
                let _capacity = sending.next().await.unwrap().unwrap();
            }
            granted
        };
        let permit_retained = {
            let mut extra = pin!(pair.sender.reserve_send(None));
            poll_fn(|cx| Poll::Ready(extra.as_mut().poll(cx).is_pending())).await
        };
        let receipt_pending = {
            let mut sending = pair.wire.resume_send().unwrap();
            sending.next().await.unwrap().unwrap().commit().unwrap();
            // Current-thread execution has not yielded since synchronous commit, so the real actor reply is pending.
            let mut next = pin!(sending.next());
            poll_fn(|cx| Poll::Ready(next.as_mut().poll(cx).is_pending())).await
        };
        let mut sending = pair.wire.resume_send().unwrap();
        let original_deadline = sending.deadline();
        let completed = sending.next().await.unwrap().is_none();
        sending.finish().unwrap();
        let first_received = decode_batch(pair.client.recv().await.unwrap().unwrap());

        {
            let mut sending = pair.wire.prepare_raw(second.clone(), deadline).unwrap();
            sending.next().await.unwrap().unwrap().commit().unwrap();
        }
        let settlement_pending = {
            let mut retirement = pair.wire.begin_send_retirement(deadline);
            let mut finish = pin!(retirement.finish());
            poll_fn(|cx| Poll::Ready(finish.as_mut().poll(cx).is_pending())).await
        };
        let outcome = pair
            .wire
            .begin_send_retirement(deadline + TIMEOUT)
            .finish()
            .await
            .unwrap();
        let repeated = pair
            .wire
            .begin_send_retirement(deadline + TIMEOUT)
            .finish()
            .await
            .unwrap();
        let second_received = decode_batch(pair.client.recv().await.unwrap().unwrap());
        pair.wire.resume_send().unwrap().finish().unwrap();
        let sealed = pair.wire.prepare_raw(raw_packet(3), deadline).is_err();
        drop(held);
        pair.sender
            .send_before(Bytes::from_static(MARKER), deadline)
            .await
            .unwrap();
        let marker = pair.client.recv().await.unwrap().unwrap();
        let cleanup = pair.finish().await;
        assert!(
            cleanup,
            "actual original transport cleanup did not complete"
        );
        assert!(
            reserve_pending && later_pending && same_reservation_granted && permit_retained,
            "cancellation lost the actual fair reservation or retained permit"
        );
        assert!(
            receipt_pending && settlement_pending,
            "the actual committed receipt was not observed pending"
        );
        assert!(empty_complete && completed && original_deadline == deadline && sealed);
        assert_eq!(outcome, SendOutcome::Complete);
        assert_eq!(repeated, outcome);
        assert_eq!(first_received, first);
        assert_eq!(second_received, [second]);
        assert_eq!(marker.as_ref(), MARKER);
    })
    .await
    .expect("finite actual prepared-send cancellation fixture stalled");
}

#[tokio::test]
async fn original_granted_capacity_cutoff_cannot_be_renewed_or_commit_after_retirement() {
    tokio::time::timeout(TIMEOUT, async {
        let mut pair = signed_pair().await;
        tokio::time::pause();
        let cutoff = tokio::time::Instant::now().into_std() + Duration::from_millis(10);
        let expired = {
            let mut sending = pair.wire.prepare_raw(raw_packet(1), cutoff).unwrap();
            let capacity = sending.next().await.unwrap().unwrap();
            tokio::time::advance(Duration::from_millis(11)).await;
            capacity.commit().unwrap_err().kind()
        };
        let first = pair
            .wire
            .begin_send_retirement(cutoff + TIMEOUT)
            .finish()
            .await
            .unwrap_err()
            .kind();
        let repeated = pair
            .wire
            .begin_send_retirement(cutoff + TIMEOUT + TIMEOUT)
            .finish()
            .await
            .unwrap_err()
            .kind();
        let sealed = pair
            .wire
            .prepare_raw(raw_packet(2), cutoff + TIMEOUT)
            .is_err();
        tokio::time::resume();
        pair.sender.send(Bytes::from_static(MARKER)).await.unwrap();
        let marker = pair.client.recv().await.unwrap().unwrap();
        let cleanup = pair.finish().await;
        assert!(
            cleanup,
            "actual original transport cleanup did not complete"
        );
        assert_eq!(expired, io::ErrorKind::TimedOut);
        assert_eq!(first, expired);
        assert_eq!(repeated, expired);
        assert!(sealed);
        assert_eq!(
            marker.as_ref(),
            MARKER,
            "an expired original packet preceded the reliable marker"
        );
    })
    .await
    .expect("finite actual prepared-send cutoff fixture stalled");
}

#[tokio::test]
async fn failed_original_receipt_is_cached_without_repolling_its_completed_future() {
    tokio::time::timeout(TIMEOUT, async {
        let mut pair = signed_pair().await;
        let deadline = tokio::time::Instant::now().into_std() + TIMEOUT;
        let first = {
            let mut sending = pair.wire.prepare_raw(raw_packet(1), deadline).unwrap();
            sending.next().await.unwrap().unwrap().commit().unwrap();
            // No yield follows commit: actual global close reaches the actor before its queued command.
            pair.sender.start_close();
            sending
                .next()
                .await
                .err()
                .expect("original actor refused the closed command")
                .kind()
        };
        let repeated = pair
            .wire
            .resume_send()
            .unwrap()
            .next()
            .await
            .err()
            .expect("original failure is retained")
            .kind();
        let retired = pair
            .wire
            .begin_send_retirement(deadline)
            .finish()
            .await
            .expect_err("failed receipt cannot prove complete")
            .kind();
        let retired_again = pair
            .wire
            .begin_send_retirement(deadline + TIMEOUT)
            .finish()
            .await
            .expect_err("settlement failure is retained")
            .kind();
        let cleanup = pair.finish().await;
        assert!(
            cleanup,
            "actual original transport cleanup did not complete"
        );
        assert_eq!(repeated, first);
        assert_eq!(retired, first);
        assert_eq!(retired_again, first);
    })
    .await
    .expect("finite actual failed receipt fixture stalled");
}

#[tokio::test]
async fn accepting_finish_close_waits_for_the_original_socket_retirement() {
    tokio::time::timeout(TIMEOUT, async {
        let reservation = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let address = reservation.local_addr().unwrap();
        drop(reservation);
        let (mut pair, _) =
            signed_pair_with_server_bind(Arc::new(SigningKey::generate()), address, deferred_bound()).await;
        let deadline = tokio::time::Instant::now().into_std() + TIMEOUT;
        let prefix = [raw_packet(1), raw_packet(2)];
        for message in BatchCodec::new(BatchLimits::default())
            .encode(&prefix)
            .unwrap()
        {
            pair.client.send(message).await.unwrap();
        }
        let first = pair.wire.receive_raw(deadline).await.unwrap();
        let SignedPair {
            wire,
            sender,
            client,
            mut listener,
            signaling,
        } = pair;
        let mut retired = wire.begin_close();
        let second = retired.receive_raw(deadline).await.unwrap();
        let (initially_pending, held_before_completion, finished) = {
            let mut finish = pin!(retired.finish_close(deadline));
            let first_poll = poll_fn(|cx| Poll::Ready(finish.as_mut().poll(cx))).await;
            // The current-thread actor cannot retire its original socket during this synchronous probe.
            let held = matches!(UdpSocket::bind(address), Err(error) if error.kind() == io::ErrorKind::AddrInUse);
            let pending = first_poll.is_pending();
            let result = match first_poll {
                Poll::Pending => finish.await,
                Poll::Ready(result) => result,
            };
            (pending, held, result)
        };
        let released_at_completion = UdpSocket::bind(address).is_ok();
        let eof = retired.receive_raw(deadline).await;
        let mut client = client.close();
        let reliable = drain(&mut client.reliable).await;
        let unreliable = drain(&mut client.unreliable).await;
        drop(retired);
        drop(client);
        drop(sender);
        listener.close().await.unwrap();
        drop(listener);
        let signaling = Arc::try_unwrap(signaling)
            .unwrap_or_else(|_| panic!("fixture retained original HTTP signaling"));
        signaling.shutdown().await;
        let released_after_cleanup = UdpSocket::bind(address).is_ok();

        assert!(reliable && unreliable && released_after_cleanup);
        assert_eq!([first, second], prefix);
        assert!(matches!(eof, Err(error) if error.kind() == io::ErrorKind::UnexpectedEof));
        assert!(finished.is_ok(), "original retirement failed: {finished:?}");
        assert!(held_before_completion, "the fixture lost its original live UDP socket");
        assert!(
            initially_pending && released_at_completion,
            "finish_close returned before physical retirement: pending={initially_pending}, released={released_at_completion}"
        );
    })
    .await
    .expect("finite actual accepting physical retirement fixture stalled");
}

/// Retains actual public permits until another real reservation is Pending.
async fn fill_capacity(sender: &SessionSender) -> Vec<SendPermit> {
    let mut held = Vec::new();
    loop {
        let mut reservation = pin!(sender.reserve_send(None));
        match poll_fn(|cx| Poll::Ready(reservation.as_mut().poll(cx))).await {
            Poll::Ready(Ok(permit)) => held.push(permit),
            Poll::Ready(Err(error)) => panic!("actual reservation failed: {error}"),
            Poll::Pending => return held,
        }
    }
}

/// Serializes legal distinct payloads using the generated packet/header owner.
fn raw_packet(time: i32) -> Bytes {
    let mut bytes = Vec::new();
    let mut writer = wire::Writer::with_limit(&mut bytes, BatchLimits::default().max_decoded_bytes);
    writer
        .write_var_u32(wire::PacketHeader::new(SetTime::ID).to_raw())
        .unwrap();
    SetTime {
        time: wire::ZigZag32(time),
    }
    .encode(&mut writer)
    .unwrap();
    Bytes::from(bytes)
}

/// Decodes one original unprefixed wire message.
fn decode_batch(message: Bytes) -> Vec<Bytes> {
    match BatchCodec::new(BatchLimits::default())
        .decode(message)
        .unwrap()
    {
        DecodeOutcome::Packets { packets, .. } => packets.collect(),
        DecodeOutcome::Dropped(_) => panic!("plaintext fixture message was dropped"),
    }
}
