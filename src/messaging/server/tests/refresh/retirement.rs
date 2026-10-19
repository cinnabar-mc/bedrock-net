use super::*;

/// Retiring an exact receipt releases pending and completed owners without disturbing another socket.
#[tokio::test]
async fn explicit_turn_retirement_preserves_original_socket_and_rejects_foreign_receipts() {
    tokio::time::timeout(Duration::from_secs(15), async {
        let (mut first, mut first_peer, _) = cached_server(7).await;
        let (mut second, mut second_peer, _) = cached_server(8).await;
        let deadline = Instant::now() + Duration::from_secs(10);
        let first_receipt = first.begin_turn_refresh(deadline).unwrap();
        let second_receipt = second.begin_turn_refresh(deadline).unwrap();
        let cross_refused = matches!(
            first.cancel_turn_refresh(&second_receipt),
            Err(Error::Admission)
        );
        let first_preserved = matches!(first.begin_turn_refresh(deadline), Err(Error::Admission));
        let first_request = written_request(&mut first, &mut first_peer, &first_receipt).await;
        let second_request = written_request(&mut second, &mut second_peer, &second_receipt).await;
        let pending_retired = first.cancel_turn_refresh(&first_receipt).is_ok();
        let repeated_refused = matches!(
            first.cancel_turn_refresh(&first_receipt),
            Err(Error::Admission)
        );
        let retired_finish_refused = matches!(
            first.finish_turn_refresh(&first_receipt).await,
            Err(Error::Admission)
        );
        let late_marker = completed_while_maintaining(
            &mut first,
            &mut first_peer,
            &json!({"jsonrpc":"2.0","id":first_request["id"],"result":credentials("retired-late",30)}).to_string(),
        ).await;
        let completed_receipt = first.begin_turn_refresh(deadline).unwrap();
        let completed_request = written_request(&mut first, &mut first_peer, &completed_receipt).await;
        let completed_marker = completed_while_maintaining(
            &mut first,
            &mut first_peer,
            &json!({"jsonrpc":"2.0","id":completed_request["id"],"result":credentials("retired-completed",30)}).to_string(),
        ).await;
        let completed_retired = first.cancel_turn_refresh(&completed_receipt).is_ok();
        let completed_finish_refused = matches!(
            first.finish_turn_refresh(&completed_receipt).await,
            Err(Error::Admission)
        );
        let second_marker = completed_while_maintaining(
            &mut second,
            &mut second_peer,
            &json!({"jsonrpc":"2.0","id":second_request["id"],"result":credentials("untouched-second",30)}).to_string(),
        ).await;
        let second_cross_refused = matches!(
            second.cancel_turn_refresh(&completed_receipt),
            Err(Error::Admission)
        );
        let second_result = second.finish_turn_refresh(&second_receipt).await;
        let next_receipt = first.begin_turn_refresh(deadline).unwrap();
        let next_request = written_request(&mut first, &mut first_peer, &next_receipt).await;
        let next_marker = completed_while_maintaining(
            &mut first,
            &mut first_peer,
            &json!({"jsonrpc":"2.0","id":next_request["id"],"result":credentials("after-retirement",30)}).to_string(),
        ).await;
        let stale_refused = matches!(
            first.cancel_turn_refresh(&first_receipt),
            Err(Error::Admission)
        );
        let next_result = first.finish_turn_refresh(&next_receipt).await;
        let (first_close, second_close) = tokio::join!(
            close_server(first, first_peer),
            close_server(second, second_peer)
        );

        assert!(first_close.0.is_ok() && first_close.1);
        assert!(second_close.0.is_ok() && second_close.1);
        assert!(cross_refused && first_preserved && pending_retired && repeated_refused);
        assert!(retired_finish_refused && completed_retired && completed_finish_refused);
        assert!(second_cross_refused && stale_refused);
        assert_eq!(first_request["id"], second_request["id"]);
        for (reply, _, _) in [late_marker, completed_marker, second_marker, next_marker] {
            assert_eq!(reply, json!({"jsonrpc":"2.0","id":"refresh-result-observed","result":null}));
        }
        assert_eq!(second_result.unwrap().servers()[0].username(), "untouched-second");
        assert_eq!(next_result.unwrap().servers()[0].username(), "after-retirement");
    })
    .await
    .expect("finite explicit TURN retirement fixture stalled");
}
