//! Liveness bounds over veilid-core's mock network: a pending OPEN to a dead
//! route fails fast, repeated dead-route reports for a vanished peer end
//! with the session closed (never an endless re-import loop), a live peer
//! survives the same reports, and a session dialled by DHT address notices
//! that the peer restarted and can be redialled.
//!
//! A vanished peer is simulated with [`BoundEndpoint::go_silent`]: its node
//! keeps its routes but answers nothing (app calls to it time out), as a
//! crashed or unreachable node would on the real network.

#![allow(
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::unwrap_used,
    missing_docs,
    unreachable_pub
)]

mod common;

use std::time::{Duration, Instant};

use common::{
    BoundEndpoint, eventually, init_tracing, pair, start_endpoint_with, step, test_endpoint_config,
};
use subduction_core::{handshake::audience::Audience, nonce_cache::NonceCache, peer::id::PeerId};
use subduction_crypto::signer::memory::MemorySigner;
use subduction_veilid::{
    address::VeilidAddress,
    client::{ConnectResult, connect_address},
    endpoint::{AddressKeyStore, VeilidEndpoint},
    error::ConnectError,
    server::{AcceptResult, accept_one},
};
use testresult::TestResult;

/// The `RouteId` an endpoint on `importer` uses for `blob` (the mock hands
/// out the same id for every import of one blob).
fn imported_id(importer: &BoundEndpoint, blob: &[u8]) -> subduction_veilid::veilid_core::RouteId {
    importer
        .endpoint
        .api()
        .import_remote_private_route(blob.to_vec())
        .expect("import peer route")
}

#[tokio::test]
async fn open_fails_fast_when_route_reported_dead() -> TestResult {
    init_tracing();
    let mut config = test_endpoint_config();
    config.open_timeout = Duration::from_secs(15);
    let client = BoundEndpoint::start(config).await;
    let peer = BoundEndpoint::start(test_endpoint_config()).await;
    peer.go_silent();
    let blob = peer.endpoint.route_blob();

    let open = tokio::spawn({
        let endpoint = client.endpoint.clone();
        let blob = blob.clone();
        async move { endpoint.open_session(&blob).await }
    });
    eventually("OPEN pending", || async {
        client.endpoint.session_count() == 1
    })
    .await;

    // Veilid reports the peer's route dead while the OPEN is pending: no
    // recovery, the OPEN fails at once.
    let reported = Instant::now();
    client.route_change(Vec::new(), vec![imported_id(&client, &blob)]);
    let err = step("OPEN fails", open).await?.unwrap_err();
    assert!(
        matches!(err, ConnectError::RouteDead(_)),
        "unexpected: {err:?}"
    );
    assert!(
        reported.elapsed() < Duration::from_secs(2),
        "OPEN took {:?} to fail",
        reported.elapsed()
    );
    eventually("session dropped", || async {
        client.endpoint.session_count() == 0
    })
    .await;

    client.shutdown().await;
    peer.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn open_to_silent_peer_times_out() -> TestResult {
    init_tracing();
    let mut config = test_endpoint_config();
    config.open_timeout = Duration::from_millis(1200);
    // Retries alone would take far longer than `open_timeout`.
    config.call_timeout = Duration::from_secs(5);
    config.max_send_attempts = 10;
    let client = BoundEndpoint::start(config).await;
    let peer = BoundEndpoint::start(test_endpoint_config()).await;
    peer.go_silent();

    let started = Instant::now();
    let err = step(
        "OPEN times out",
        client.endpoint.open_session(&peer.endpoint.route_blob()),
    )
    .await
    .unwrap_err();
    let took = started.elapsed();
    assert!(
        matches!(err, ConnectError::OpenTimeout(_)),
        "unexpected: {err:?}"
    );
    assert!(
        took >= Duration::from_millis(1100) && took < Duration::from_secs(3),
        "OPEN took {took:?}"
    );
    assert_eq!(client.endpoint.session_count(), 0);

    client.shutdown().await;
    peer.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn repeated_dead_route_reports_for_silent_peer_close_session() -> TestResult {
    init_tracing();
    let mut config = test_endpoint_config();
    config.keepalive_interval = Some(Duration::from_millis(200));
    config.call_timeout = Duration::from_millis(300);
    config.max_send_attempts = 3;
    config.route_recovery_timeout = Duration::from_secs(1);
    let server = BoundEndpoint::start(config).await;
    let mut peer_config = test_endpoint_config();
    peer_config.keepalive_interval = None;
    let peer = BoundEndpoint::start(peer_config).await;
    let (_c, s) = pair(&peer.endpoint, &server.endpoint).await;
    let route = s.remote_route_id().expect("route");

    peer.go_silent();
    let started = Instant::now();
    // Veilid keeps reporting the peer's route dead (as it did every ~15 s
    // on the real network); before the fix every report re-imported the
    // route and restarted the keepalive's retries, forever.
    let reporter = tokio::spawn({
        let server = server.clone();
        async move {
            loop {
                server.route_change(Vec::new(), vec![route.clone()]);
                tokio::time::sleep(Duration::from_millis(150)).await;
            }
        }
    });

    eventually("session closed", || async { s.is_closed() }).await;
    let took = started.elapsed();
    reporter.abort();
    // keepalive_interval + route_recovery_timeout (+ scheduling slack).
    assert!(took < Duration::from_secs(4), "closing took {took:?}");
    assert_eq!(server.endpoint.session_count(), 0);

    server.shutdown().await;
    peer.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn repeated_dead_route_reports_for_live_peer_keep_session() -> TestResult {
    init_tracing();
    let mut config = test_endpoint_config();
    config.keepalive_interval = Some(Duration::from_millis(200));
    config.route_recovery_timeout = Duration::from_secs(3);
    let server = BoundEndpoint::start(config.clone()).await;
    let peer = BoundEndpoint::start(config).await;
    let (c, s) = pair(&peer.endpoint, &server.endpoint).await;
    let route = s.remote_route_id().expect("route");

    // The peer is alive (it keeps pinging us), but Veilid keeps reporting
    // our copy of its route dead.
    for _ in 0..10 {
        server.route_change(Vec::new(), vec![route.clone()]);
        tokio::time::sleep(Duration::from_millis(150)).await;
    }
    eventually("route usable again", || async { !s.is_route_lost() }).await;
    assert!(!s.is_closed(), "a live peer's session must survive");

    step("s->c", s.send(b"still here")).await?;
    assert_eq!(step("c recv", c.recv()).await?, b"still here");
    step("c->s", c.send(b"me too")).await?;
    assert_eq!(step("s recv", s.recv()).await?, b"me too");
    assert_eq!(server.endpoint.session_count(), 1);

    server.shutdown().await;
    peer.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn lost_open_is_retransmitted_within_open_timeout() -> TestResult {
    init_tracing();
    let mut config = test_endpoint_config();
    // `call_timeout` alone would spend the whole `open_timeout` on one
    // attempt; each attempt gets a third of it instead.
    config.call_timeout = Duration::from_secs(5);
    config.open_timeout = Duration::from_secs(3);
    let client = BoundEndpoint::start(config).await;
    let peer = BoundEndpoint::start(test_endpoint_config()).await;
    peer.go_silent();

    let open = tokio::spawn({
        let endpoint = client.endpoint.clone();
        let blob = peer.endpoint.route_blob();
        async move { endpoint.open_session(&blob).await }
    });
    // The first OPEN is lost; the peer is back before the second attempt.
    tokio::time::sleep(Duration::from_millis(600)).await;
    peer.go_live();
    let (opened, accepted) = step("open + accept", async {
        tokio::join!(open, peer.endpoint.accept())
    })
    .await;
    let c = opened?.expect("OPEN retransmitted and acknowledged");
    let s = accepted.expect("accepted");
    step("c->s", c.send(b"hello")).await?;
    assert_eq!(step("s recv", s.recv()).await?, b"hello");

    client.shutdown().await;
    peer.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn cancelled_open_leaves_no_session() -> TestResult {
    init_tracing();
    let mut config = test_endpoint_config();
    config.open_timeout = Duration::from_secs(30);
    let client = BoundEndpoint::start(config).await;
    let peer = BoundEndpoint::start(test_endpoint_config()).await;
    peer.go_silent();

    let open = tokio::spawn({
        let endpoint = client.endpoint.clone();
        let blob = peer.endpoint.route_blob();
        async move { endpoint.open_session(&blob).await }
    });
    eventually("OPEN pending", || async {
        client.endpoint.session_count() == 1
    })
    .await;
    // E.g. a caller's own timeout around the dial fires.
    open.abort();
    eventually("cancelled session dropped", || async {
        client.endpoint.session_count() == 0
    })
    .await;

    client.shutdown().await;
    peer.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn keepalive_rides_out_lost_replies() -> TestResult {
    init_tracing();
    let mut config = test_endpoint_config();
    config.keepalive_interval = Some(Duration::from_millis(200));
    config.call_timeout = Duration::from_millis(300);
    config.max_send_attempts = 6;
    config.initial_backoff = Duration::from_millis(100);
    config.max_backoff = Duration::from_millis(200);
    // Shorter than the outage: the keepalive must not be bounded by it
    // while the route itself is fine.
    config.route_recovery_timeout = Duration::from_secs(1);
    let server = BoundEndpoint::start(config).await;
    let mut peer_config = test_endpoint_config();
    peer_config.keepalive_interval = None;
    let peer = BoundEndpoint::start(peer_config).await;
    let (c, s) = pair(&peer.endpoint, &server.endpoint).await;

    // Several keepalive attempts in a row get no reply, then the peer
    // answers again (within the keepalive's attempts).
    peer.go_silent();
    tokio::time::sleep(Duration::from_millis(1500)).await;
    peer.go_live();
    tokio::time::sleep(Duration::from_secs(2)).await;
    assert!(
        !s.is_closed(),
        "a live session must survive a few lost replies"
    );

    step("s->c", s.send(b"still here")).await?;
    assert_eq!(step("c recv", c.recv()).await?, b"still here");

    server.shutdown().await;
    peer.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn both_sides_losing_each_others_route_recover_by_probing() -> TestResult {
    init_tracing();
    let mut config = test_endpoint_config();
    // No traffic at all: neither side hears from the other unless it
    // probes.
    config.keepalive_interval = None;
    config.route_recovery_timeout = Duration::from_millis(1500);
    let a = BoundEndpoint::start(config.clone()).await;
    let b = BoundEndpoint::start(config).await;
    let (c, s) = pair(&a.endpoint, &b.endpoint).await;
    let a_route = s.remote_route_id().expect("route");
    let b_route = c.remote_route_id().expect("route");

    // Network churn: Veilid reports each side's copy of the other's route
    // dead twice, with nothing heard in between (the second report finds
    // the peer "silent" and declares the route lost).
    for _ in 0..2 {
        a.route_change(Vec::new(), vec![b_route.clone()]);
        b.route_change(Vec::new(), vec![a_route.clone()]);
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    // Well past the recovery deadline: the probes found the (live) peers.
    tokio::time::sleep(Duration::from_millis(2500)).await;
    assert!(!c.is_closed() && !s.is_closed(), "live peers must recover");
    assert!(!c.is_route_lost() && !s.is_route_lost());

    step("c->s", c.send(b"ping")).await?;
    assert_eq!(step("s recv", s.recv()).await?, b"ping");
    step("s->c", s.send(b"pong")).await?;
    assert_eq!(step("c recv", c.recv()).await?, b"pong");

    a.shutdown().await;
    b.shutdown().await;
    Ok(())
}

/// `connect_address` from `client` to `address`, served by `server`
/// (running `accept_one`). The server's side of the connection is returned
/// too: dropping it closes the session.
async fn dial(
    client: &VeilidEndpoint,
    server: &VeilidEndpoint,
    address: &VeilidAddress,
    server_signer: &MemorySigner,
    client_signer: &MemorySigner,
) -> Result<(ConnectResult, AcceptResult), ConnectError> {
    let server_peer = PeerId::from(server_signer.verifying_key());
    let accept = tokio::spawn({
        let endpoint = server.clone();
        let signer = server_signer.clone();
        async move {
            accept_one(
                &endpoint,
                &signer,
                &NonceCache::default(),
                server_peer,
                None,
                Duration::from_secs(60),
            )
            .await
        }
    });
    let connected = step(
        "connect by address",
        connect_address::<MemorySigner>(
            client,
            address,
            client_signer,
            Audience::known(server_peer),
        ),
    )
    .await?;
    let accepted = step("accept", accept)
        .await
        .expect("accept task")
        .expect("accepted");
    assert_eq!(connected.authenticated.peer_id(), server_peer);
    Ok((connected, accepted))
}

#[tokio::test]
async fn restarted_peer_is_noticed_and_redialled_by_address() -> TestResult {
    init_tracing();
    let dir = tempfile::tempdir()?;
    let mut server_config = test_endpoint_config();
    server_config.address_key_store = AddressKeyStore::File(dir.path().join("address.key"));
    server_config.keepalive_interval = None;

    let mut client_config = test_endpoint_config();
    client_config.keepalive_interval = Some(Duration::from_millis(300));
    client_config.call_timeout = Duration::from_secs(1);
    client_config.open_timeout = Duration::from_secs(3);
    // Long: the session must close because the peer is found to have
    // restarted, not because this expires.
    client_config.route_recovery_timeout = Duration::from_secs(30);
    let client = BoundEndpoint::start(client_config).await;

    let server_signer = MemorySigner::from_bytes(&[61; 32]);
    let server_peer = PeerId::from(server_signer.verifying_key());
    let client_signer = MemorySigner::from_bytes(&[62; 32]);

    // First incarnation of the server.
    let first = BoundEndpoint::start(server_config.clone()).await;
    let address = step("first published", first.endpoint.wait_address_published())
        .await
        .expect("publishing enabled");
    let first_blob = first.endpoint.route_blob();

    let (connected, _first_side) = dial(
        &client.endpoint,
        &first.endpoint,
        &address,
        &server_signer,
        &client_signer,
    )
    .await?;
    let listener = tokio::spawn(connected.listener_task);
    let _sender = tokio::spawn(connected.sender_task);

    // The server restarts (same address keys, new route) ...
    let second = start_endpoint_with(server_config).await;
    step("second published", second.wait_address_published()).await;
    assert_ne!(second.route_blob(), first_blob);
    // ... and its first incarnation vanished without a CLOSE: silent, its
    // route gone, so the client's copy is reported dead and cannot be
    // re-imported.
    first.go_silent();
    let imported = imported_id(&client, &first_blob);
    first
        .endpoint
        .api()
        .release_private_route(first.endpoint.route_id())?;
    client
        .endpoint
        .api()
        .release_private_route(imported.clone())?;
    let lost = Instant::now();
    client.route_change(Vec::new(), vec![imported]);

    // The client re-resolves the address, switches to the new route, and
    // the restarted server answers "unknown session": the session closes
    // promptly.
    let _ended = step("client's session closes", listener).await?;
    assert!(
        lost.elapsed() < Duration::from_secs(10),
        "took {:?} (the recovery deadline is 30 s)",
        lost.elapsed()
    );
    eventually("client dropped the session", || async {
        client.endpoint.session_count() == 0
    })
    .await;

    // Redialling the same address reaches the restarted server.
    let (redialled, _second_side) = dial(
        &client.endpoint,
        &second,
        &address,
        &server_signer,
        &client_signer,
    )
    .await?;
    assert_eq!(redialled.authenticated.peer_id(), server_peer);

    client.shutdown().await;
    second.shutdown().await;
    first.shutdown().await;
    Ok(())
}
