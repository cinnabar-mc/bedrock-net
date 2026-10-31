// SPDX-License-Identifier: MIT

use super::*;

#[tokio::test]
async fn oversized_generated_entry_rolls_back_without_losing_valid_siblings_or_batch_order() {
    tokio::time::timeout(TIMEOUT, async {
        let mut pair = signed_pair().await;
        let deadline = tokio::time::Instant::now().into_std() + TIMEOUT;
        let oversized: packets::Packet = packets::ResourcePackChunkData {
            resource_name: Bytes::from_static(b"synthetic-pack").into(),
            chunk_id: wire::U32LE(0),
            byte_offset: wire::U64LE(0),
            chunk_data: Bytes::from(vec![0; BatchLimits::default().max_decoded_bytes]),
        }
        .into();
        let all_failed = pair
            .wire
            .prepare_packets(vec![oversized.clone()], deadline)
            .is_err();
        let no_retained_send = pair.wire.resume_send().is_err();
        let valid = |time| {
            SetTime {
                time: wire::ZigZag32(time),
            }
            .into()
        };
        let prepared = pair
            .wire
            .prepare_packets(vec![valid(1), oversized, valid(2)], deadline)
            .map(drop);
        if let Err(error) = prepared {
            assert!(
                pair.finish().await,
                "original signed accepting owners leaked"
            );
            panic!("an oversized generated entry must not discard valid siblings: {error}");
        }
        let mut sending = pair.wire.resume_send().unwrap();
        while let Some(capacity) = sending.next().await.unwrap() {
            capacity.commit().unwrap();
        }
        sending.finish().unwrap();
        let received = decode_batch(pair.client.recv().await.unwrap().unwrap());
        assert!(
            pair.finish().await,
            "original signed accepting owners leaked"
        );
        assert!(all_failed && no_retained_send);
        assert_eq!(received, [raw_packet(1), raw_packet(2)]);
    })
    .await
    .expect("finite actual generated-entry bound fixture stalled");
}

#[tokio::test]
async fn expired_runtime_deadline_does_not_consume_the_original_buffered_packet() {
    let prefix = [raw_packet(1), raw_packet(2)];
    let (mut pair, first) = tokio::time::timeout(TIMEOUT, async {
        let mut pair = signed_pair().await;
        let mut batches = BatchCodec::new(BatchLimits::default())
            .encode(&prefix)
            .unwrap();
        assert_eq!(batches.len(), 1);
        pair.client.send(batches.remove(0)).await.unwrap();
        let first = pair
            .wire
            .receive_raw(tokio::time::Instant::now().into_std() + TIMEOUT)
            .await
            .unwrap();
        (pair, first)
    })
    .await
    .expect("finite actual buffered-packet setup stalled");
    assert_eq!(first, prefix[0]);
    tokio::time::pause();
    let deadline = tokio::time::Instant::now().into_std() + Duration::from_secs(1);
    tokio::time::advance(Duration::from_secs(2)).await;
    let expired = {
        let mut receive = pin!(pair.wire.receive_raw(deadline));
        poll_fn(|cx| Poll::Ready(receive.as_mut().poll(cx))).await
    };
    let buffered = if matches!(&expired, Poll::Ready(Err(error)) if error.kind() == io::ErrorKind::TimedOut)
    {
        let mut receive = pin!(
            pair.wire
                .receive_raw(tokio::time::Instant::now().into_std() + TIMEOUT)
        );
        Some(poll_fn(|cx| Poll::Ready(receive.as_mut().poll(cx))).await)
    } else {
        None
    };
    tokio::time::resume();
    assert!(
        tokio::time::timeout(TIMEOUT, pair.finish()).await.unwrap(),
        "original signed accepting owners leaked"
    );
    assert!(matches!(expired, Poll::Ready(Err(error)) if error.kind() == io::ErrorKind::TimedOut));
    assert!(matches!(buffered, Some(Poll::Ready(Ok(packet))) if packet == prefix[1]));
}

#[tokio::test(start_paused = true)]
async fn ready_wait_result_is_rejected_when_the_original_runtime_cutoff_has_arrived() {
    let deadline = tokio::time::Instant::now().into_std() + TIMEOUT;
    let (complete, result) = tokio::sync::oneshot::channel::<()>();
    let mut waiting = pin!(wait(deadline, result));
    let first = poll_fn(|cx| Poll::Ready(waiting.as_mut().poll(cx))).await;
    assert!(first.is_pending());
    tokio::time::advance(TIMEOUT).await;
    complete.send(()).unwrap();
    let ready = poll_fn(|cx| Poll::Ready(waiting.as_mut().poll(cx))).await;
    assert!(matches!(ready, Poll::Ready(Err(error)) if error.kind() == io::ErrorKind::TimedOut));
}
