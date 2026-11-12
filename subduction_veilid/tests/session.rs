//! Integration tests for the session layer (fragmentation, reliability,
//! limits, and close propagation) over veilid-core's mock network.

#![allow(
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::unwrap_used,
    missing_docs,
    unreachable_pub
)]

mod common;

use common::{
    init_tracing, payload, start_endpoint, start_endpoint_with, step, test_endpoint_config,
};
use subduction_veilid::{
    endpoint::VeilidEndpoint,
    error::{ConnectError, StreamError},
    frame::{MAX_CHUNK_SIZE, NackReason},
    session::{CLOSE_NORMAL, CLOSE_TOO_BIG, Session},
};
use testresult::TestResult;

use std::time::Duration;

/// Open a session from `client` to `server` and accept it, without
/// establishing it (pre-authentication limits apply).
async fn pair_unestablished(
    client: &VeilidEndpoint,
    server: &VeilidEndpoint,
) -> (Session, Session) {
    let blob = server.route_blob();
    let (opened, accepted) = step("open + accept", async {
        tokio::join!(client.open_session(&blob), server.accept())
    })
    .await;
    (
        opened.expect("open session"),
        accepted.expect("accept session"),
    )
}

/// Open a session from `client` to `server`, accept it, and mark both ends
/// established (as the handshake would).
async fn pair(client: &VeilidEndpoint, server: &VeilidEndpoint) -> (Session, Session) {
    let (c, s) = pair_unestablished(client, server).await;
    c.mark_established();
    s.mark_established();
    (c, s)
}

#[tokio::test]
async fn small_messages_both_directions() -> TestResult {
    init_tracing();
    let server = start_endpoint().await;
    let client = start_endpoint().await;
    let (c, s) = pair(&client, &server).await;

    assert!(c.is_initiator());
    assert!(!s.is_initiator());
    assert_eq!(c.id(), s.id());

    step("c->s", c.send(b"hello")).await?;
    assert_eq!(step("s recv", s.recv()).await?, b"hello");

    step("s->c", s.send(b"world")).await?;
    assert_eq!(step("c recv", c.recv()).await?, b"world");

    // Empty messages survive as empty messages.
    step("c->s empty", c.send(b"")).await?;
    assert_eq!(step("s recv empty", s.recv()).await?, b"");

    // Ordering across many messages.
    for i in 0u8..20 {
        step("c->s seq", c.send(&[i])).await?;
    }
    for i in 0u8..20 {
        assert_eq!(step("s recv seq", s.recv()).await?, [i]);
    }

    server.shutdown().await;
    client.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn multi_fragment_messages_both_directions() -> TestResult {
    init_tracing();
    let server = start_endpoint().await;
    let client = start_endpoint().await;
    let (c, s) = pair(&client, &server).await;

    // 200 KiB: 7 fragments.
    let big = payload(200 * 1024, 1);
    assert!(big.len() > 6 * MAX_CHUNK_SIZE);
    step("c->s big", c.send(&big)).await?;
    assert_eq!(step("s recv big", s.recv()).await?, big);

    let big2 = payload(200 * 1024 + 17, 2);
    step("s->c big", s.send(&big2)).await?;
    assert_eq!(step("c recv big", c.recv()).await?, big2);

    // Exactly one full chunk, and one byte over.
    for len in [MAX_CHUNK_SIZE, MAX_CHUNK_SIZE + 1] {
        let msg = payload(len, 3);
        step("c->s boundary", c.send(&msg)).await?;
        assert_eq!(step("s recv boundary", s.recv()).await?, msg);
    }

    // Concurrent senders on one session are serialised, not interleaved.
    let a = payload(100 * 1024, 4);
    let b = payload(90 * 1024, 5);
    let (ra, rb) = step("concurrent sends", async {
        tokio::join!(c.send(&a), c.send(&b))
    })
    .await;
    ra?;
    rb?;
    let first = step("recv 1", s.recv()).await?;
    let second = step("recv 2", s.recv()).await?;
    assert!(
        (first == a && second == b) || (first == b && second == a),
        "messages must arrive whole"
    );

    server.shutdown().await;
    client.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn oversize_message_rejected_locally() -> TestResult {
    init_tracing();
    let mut config = test_endpoint_config();
    config.max_message_size = 64 * 1024;
    let server = start_endpoint().await;
    let client = start_endpoint_with(config).await;
    let (c, s) = pair(&client, &server).await;

    let err = c.send(&payload(64 * 1024 + 1, 0)).await.unwrap_err();
    assert!(
        matches!(err, StreamError::FrameTooLarge { actual, max } if actual == 64 * 1024 + 1 && max == 64 * 1024),
        "unexpected error: {err:?}"
    );

    // Nothing was sent; the session is still usable.
    assert!(!c.is_closed());
    step("send after reject", c.send(b"still here")).await?;
    assert_eq!(step("recv", s.recv()).await?, b"still here");

    server.shutdown().await;
    client.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn oversize_message_rejected_by_receiver() -> TestResult {
    init_tracing();
    let mut config = test_endpoint_config();
    config.max_message_size = 64 * 1024;
    let server = start_endpoint_with(config).await;
    let client = start_endpoint().await;
    let (c, s) = pair(&client, &server).await;

    let err = step("oversize send", c.send(&payload(100 * 1024, 0)))
        .await
        .unwrap_err();
    assert!(
        matches!(err, StreamError::Rejected(NackReason::TooLarge)),
        "unexpected error: {err:?}"
    );
    assert!(c.is_closed());

    // The receiver closed its side with 1009 and never delivered anything.
    match step("server recv", s.recv()).await {
        Err(StreamError::Closed { code, .. }) => assert_eq!(code, CLOSE_TOO_BIG),
        other => panic!("expected close, got {other:?}"),
    }

    server.shutdown().await;
    client.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn close_propagates_to_peer() -> TestResult {
    init_tracing();
    let server = start_endpoint().await;
    let client = start_endpoint().await;
    let (c, s) = pair(&client, &server).await;

    step("send", c.send(b"last words")).await?;
    c.close();
    assert!(c.is_closed());

    // Messages received before the close are still delivered, then the close.
    assert_eq!(step("recv before close", s.recv()).await?, b"last words");
    match step("recv close", s.recv()).await {
        Err(StreamError::Closed { code, .. }) => assert_eq!(code, CLOSE_NORMAL),
        other => panic!("expected close, got {other:?}"),
    }

    // Sending on a closed session fails, on either side.
    assert!(matches!(
        c.send(b"x").await,
        Err(StreamError::Closed { .. })
    ));
    assert!(matches!(
        s.send(b"x").await,
        Err(StreamError::Closed { .. })
    ));

    common::eventually("sessions removed", || async {
        server.session_count() == 0 && client.session_count() == 0
    })
    .await;

    server.shutdown().await;
    client.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn dropping_last_handle_closes_session() -> TestResult {
    init_tracing();
    let server = start_endpoint().await;
    let client = start_endpoint().await;
    let (c, s) = pair(&client, &server).await;

    drop(c);
    assert!(matches!(
        step("recv after drop", s.recv()).await,
        Err(StreamError::Closed { .. })
    ));

    server.shutdown().await;
    client.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn endpoint_shutdown_closes_sessions_and_accept() -> TestResult {
    init_tracing();
    let server = start_endpoint().await;
    let client = start_endpoint().await;
    let (c, _s) = pair(&client, &server).await;

    server.shutdown().await;
    assert!(server.is_closed());
    assert!(server.accept().await.is_none());

    // The client learns about it through the CLOSE frame.
    assert!(matches!(
        step("client recv", c.recv()).await,
        Err(StreamError::Closed { .. })
    ));

    // The server's route is gone.
    let err = client.open_session(&server.route_blob()).await.unwrap_err();
    assert!(
        matches!(err, ConnectError::InvalidRoute(_) | ConnectError::Open(_)),
        "unexpected error: {err:?}"
    );

    client.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn invalid_route_blob_rejected() -> TestResult {
    init_tracing();
    let client = start_endpoint().await;
    let err = client.open_session(b"not a route blob").await.unwrap_err();
    assert!(
        matches!(err, ConnectError::InvalidRoute(_)),
        "unexpected error: {err:?}"
    );
    client.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn session_limit_refuses_further_opens() -> TestResult {
    init_tracing();
    let mut config = test_endpoint_config();
    config.max_sessions = 1;
    let server = start_endpoint_with(config).await;
    let client = start_endpoint().await;

    let (_c, _s) = pair(&client, &server).await;

    let mut fast = test_endpoint_config();
    fast.max_send_attempts = 2;
    fast.max_busy_wait = Duration::from_millis(500);
    let client2 = start_endpoint_with(fast).await;
    let err = step("second open", client2.open_session(&server.route_blob()))
        .await
        .unwrap_err();
    assert!(
        matches!(
            err,
            ConnectError::Open(StreamError::Rejected(NackReason::Busy))
        ),
        "unexpected error: {err:?}"
    );
    assert_eq!(server.session_count(), 1);

    server.shutdown().await;
    client.shutdown().await;
    client2.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn unestablished_session_defers_large_messages() -> TestResult {
    init_tracing();
    let server = start_endpoint().await;
    let mut fast = test_endpoint_config();
    fast.max_busy_wait = Duration::from_millis(500);
    let client = start_endpoint_with(fast).await;
    let (c, s) = pair_unestablished(&client, &server).await;
    assert!(!s.is_established());

    // Handshake-sized messages flow before establishment.
    step("small", c.send(b"challenge")).await?;
    assert_eq!(step("recv small", s.recv()).await?, b"challenge");

    // A large message is refused as busy (not consumed, nothing buffered)
    // until the receiver is established; the sender gives up after
    // `max_busy_wait`.
    let big = payload(200 * 1024, 9);
    let err = step("big before establish", c.send(&big))
        .await
        .unwrap_err();
    assert!(
        matches!(err, StreamError::Rejected(NackReason::Busy)),
        "unexpected error: {err:?}"
    );

    server.shutdown().await;
    client.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn large_message_racing_establishment_is_delivered() -> TestResult {
    init_tracing();
    let server = start_endpoint().await;
    let client = start_endpoint().await;
    let (c, s) = pair_unestablished(&client, &server).await;

    // The sender starts before the receiver is established (as when the
    // handshake response races the receiver marking the session): the
    // deferred fragment is retried and delivered once established.
    let big = payload(200 * 1024, 10);
    let send = tokio::spawn({
        let c = c.clone();
        let big = big.clone();
        async move { c.send(&big).await }
    });
    tokio::time::sleep(Duration::from_millis(300)).await;
    s.mark_established();
    step("send completes", send).await??;
    assert_eq!(step("recv big", s.recv()).await?, big);

    server.shutdown().await;
    client.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn unestablished_inbound_session_expires() -> TestResult {
    init_tracing();
    let mut config = test_endpoint_config();
    config.handshake_timeout = Duration::from_millis(500);
    let server = start_endpoint_with(config).await;
    let client = start_endpoint().await;

    // Never accepted, never established.
    let c = step("open", client.open_session(&server.route_blob())).await?;
    assert_eq!(server.session_count(), 1);
    common::eventually("inbound session expired", || async {
        server.session_count() == 0
    })
    .await;
    // The initiator is told via CLOSE.
    assert!(matches!(
        step("client recv", c.recv()).await,
        Err(StreamError::Closed { .. })
    ));
    // The expired session is skipped by accept.
    assert!(
        tokio::time::timeout(Duration::from_millis(200), server.accept())
            .await
            .is_err()
    );

    server.shutdown().await;
    client.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn slow_consumer_applies_backpressure_without_failing() -> TestResult {
    init_tracing();
    let mut config = test_endpoint_config();
    config.inbound_queue_capacity = 2;
    config.max_buffered_bytes = 64 * 1024;
    let server = start_endpoint_with(config).await;
    let mut sender_config = test_endpoint_config();
    // Fewer attempts than the stall lasts in backoff rounds: busy refusals
    // must not consume the attempt budget.
    sender_config.max_send_attempts = 1;
    sender_config.max_backoff = Duration::from_millis(100);
    let client = start_endpoint_with(sender_config).await;
    let (c, s) = pair(&client, &server).await;

    let msgs: Vec<Vec<u8>> = (0u8..6).map(|i| payload(40 * 1024, i)).collect();
    let send = tokio::spawn({
        let c = c.clone();
        let msgs = msgs.clone();
        async move {
            for m in &msgs {
                c.send(m).await?;
            }
            Ok::<_, StreamError>(())
        }
    });

    // The consumer stalls; the sender is held back, not failed.
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert!(
        !send.is_finished(),
        "sender should be blocked by backpressure"
    );
    assert!(!c.is_closed());

    for m in &msgs {
        assert_eq!(&step("recv", s.recv()).await?, m);
    }
    step("sender done", send).await??;

    server.shutdown().await;
    client.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn keepalive_detects_vanished_peer() -> TestResult {
    init_tracing();
    let server = start_endpoint().await;
    let mut config = test_endpoint_config();
    config.keepalive_interval = Some(Duration::from_millis(200));
    config.call_timeout = Duration::from_secs(1);
    config.max_send_attempts = 2;
    let client = start_endpoint_with(config).await;
    let (c, _s) = pair(&client, &server).await;

    // Keepalives on a healthy session keep it open.
    tokio::time::sleep(Duration::from_millis(700)).await;
    assert!(!c.is_closed());

    // The server's Veilid node goes away without sending CLOSE frames.
    server.api().clone().shutdown().await;

    // The receive-only client notices through its keepalive.
    assert!(matches!(
        step("client recv", c.recv()).await,
        Err(StreamError::Closed { .. })
    ));

    client.shutdown().await;
    Ok(())
}
