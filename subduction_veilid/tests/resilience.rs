//! Route-churn resilience over veilid-core's mock network: sessions survive
//! a peer route reported dead, own-route reallocation (`ROUTE_UPDATE`), and
//! close only once a lost route fails to come back in time.
//!
//! Route deaths are simulated by injecting `VeilidUpdate::RouteChange`
//! through a [`VeilidDispatcher`](subduction_veilid::endpoint::VeilidDispatcher),
//! exactly as Veilid delivers them.

#![allow(
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::unwrap_used,
    missing_docs,
    unreachable_pub
)]

mod common;

use std::time::Duration;

use common::{
    BoundEndpoint, eventually, init_tracing, pair, start_endpoint, start_endpoint_with, step,
    test_endpoint_config,
};
use subduction_veilid::error::StreamError;
use testresult::TestResult;

#[tokio::test]
async fn dead_imported_route_is_reimported_and_session_survives() -> TestResult {
    init_tracing();
    let mut config = test_endpoint_config();
    // Short, so a session wrongly left in the route-lost state would close
    // during the test.
    config.route_recovery_timeout = Duration::from_millis(300);
    let server = BoundEndpoint::start(config).await;
    let client = start_endpoint().await;
    let (c, s) = pair(&client, &server.endpoint).await;

    let route = s
        .remote_route_id()
        .expect("server has a route to the client");
    // Veilid (wrongly, as after a relay change) declares the client's route
    // dead on the server.
    server.route_change(Vec::new(), vec![route]);

    tokio::time::sleep(Duration::from_millis(600)).await;
    assert!(!s.is_closed(), "session must survive a dead remote route");
    assert!(!s.is_route_lost());
    assert!(s.remote_route_id().is_some());
    assert_eq!(server.endpoint.session_count(), 1);

    step("s->c after route death", s.send(b"still talking")).await?;
    assert_eq!(step("c recv", c.recv()).await?, b"still talking");
    step("c->s after route death", c.send(b"me too")).await?;
    assert_eq!(step("s recv", s.recv()).await?, b"me too");

    server.shutdown().await;
    client.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn failing_remote_route_is_reimported_on_send() -> TestResult {
    init_tracing();
    let server = start_endpoint().await;
    let client = start_endpoint().await;
    let (c, s) = pair(&client, &server).await;

    // The server's import of the client's route vanishes underneath it:
    // the next send fails with InvalidTarget, re-imports, and goes through.
    let route = s.remote_route_id().expect("route");
    server.api().release_private_route(route)?;

    step("send after losing the import", s.send(b"hello again")).await?;
    assert_eq!(step("c recv", c.recv()).await?, b"hello again");
    assert!(!s.is_closed());

    server.shutdown().await;
    client.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn own_route_reallocation_is_announced_with_route_update() -> TestResult {
    init_tracing();
    let client = BoundEndpoint::start(test_endpoint_config()).await;
    let server = start_endpoint().await;
    let (c, s) = pair(&client.endpoint, &server).await;

    let old_blob = client.endpoint.route_blob();
    let server_view = s.remote_route_id().expect("route");

    // The client's own private route dies.
    client.route_change(vec![client.endpoint.route_id()], Vec::new());

    eventually("client reallocated its route", || async {
        client.endpoint.route_blob() != old_blob
    })
    .await;
    eventually("server switched to the client's new route", || async {
        s.remote_route_id().is_some_and(|r| r != server_view)
    })
    .await;

    // Both directions keep working; nothing was closed.
    step("s->c over the new route", s.send(b"found you")).await?;
    assert_eq!(step("c recv", c.recv()).await?, b"found you");
    step("c->s", c.send(b"hi")).await?;
    assert_eq!(step("s recv", s.recv()).await?, b"hi");
    assert!(!c.is_closed());
    assert!(!s.is_closed());
    assert_eq!(server.session_count(), 1);
    assert_eq!(client.endpoint.session_count(), 1);

    client.shutdown().await;
    server.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn sends_wait_for_route_update_after_failed_reimport() -> TestResult {
    init_tracing();
    // The client's route is released without it noticing, then Veilid
    // reports it dead on the client: a send from the server finds the route
    // unusable and not re-importable, waits, and completes once the client's
    // ROUTE_UPDATE arrives.
    let client = BoundEndpoint::start(test_endpoint_config()).await;
    let server = start_endpoint().await;
    let (c, s) = pair(&client.endpoint, &server).await;

    let old_route = client.endpoint.route_id();
    client
        .endpoint
        .api()
        .release_private_route(old_route.clone())?;
    // (The mock keeps imported copies of a route alive on their own, so drop
    // the server's import too, as the real network would.)
    server
        .api()
        .release_private_route(s.remote_route_id().expect("route"))?;

    let send = tokio::spawn({
        let s = s.clone();
        async move { s.send(b"waited for you").await }
    });
    eventually("server session waits in route-lost state", || async {
        s.is_route_lost()
    })
    .await;
    assert!(!send.is_finished());

    client.route_change(vec![old_route], Vec::new());
    step("send completes after ROUTE_UPDATE", send).await??;
    assert_eq!(step("c recv", c.recv()).await?, b"waited for you");
    assert!(!s.is_route_lost());

    client.shutdown().await;
    server.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn lost_route_closes_session_after_recovery_timeout() -> TestResult {
    init_tracing();
    let mut config = test_endpoint_config();
    config.route_recovery_timeout = Duration::from_millis(1500);
    // Frequent keepalives must not tear a recovering session down early.
    config.keepalive_interval = Some(Duration::from_millis(100));
    let server = BoundEndpoint::start(config).await;
    let client = start_endpoint_with(test_endpoint_config()).await;
    let (_c, s) = pair(&client, &server.endpoint).await;

    // The client's route really is gone (re-import fails) and the client
    // never announces a new one.
    let route = s.remote_route_id().expect("route");
    client.api().release_private_route(client.route_id())?;
    server.endpoint.api().release_private_route(route.clone())?;
    server.route_change(Vec::new(), vec![route]);

    eventually("route lost", || async { s.is_route_lost() }).await;
    let send = tokio::spawn({
        let s = s.clone();
        async move { s.send(b"anyone there?").await }
    });
    tokio::time::sleep(Duration::from_millis(600)).await;
    assert!(!s.is_closed(), "closed before the recovery timeout");
    assert!(
        !send.is_finished(),
        "send must wait while the route is lost"
    );

    let result = step("send gives up", send).await?;
    assert!(
        matches!(result, Err(StreamError::Closed { .. })),
        "unexpected: {result:?}"
    );
    assert!(s.is_closed());
    assert!(matches!(
        step("recv", s.recv()).await,
        Err(StreamError::Closed { .. })
    ));
    assert_eq!(server.endpoint.session_count(), 0);

    server.shutdown().await;
    client.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn shared_dead_route_keeps_one_reference_per_session() -> TestResult {
    init_tracing();
    let server = BoundEndpoint::start(test_endpoint_config()).await;
    let client = start_endpoint().await;
    // Two sessions from the same peer: the server imports the same blob
    // twice and gets the same RouteId for both.
    let (c1, s1) = pair(&client, &server.endpoint).await;
    let (c2, s2) = pair(&client, &server.endpoint).await;
    let route = s1.remote_route_id().expect("route");
    assert_eq!(s2.remote_route_id(), Some(route.clone()));

    // Veilid reports the shared import dead (it has already dropped it).
    server.endpoint.api().release_private_route(route.clone())?;
    server.route_change(Vec::new(), vec![route.clone()]);

    // (The update is handled asynchronously by the dispatch task.)
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(s1.remote_route_id(), Some(route.clone()));
    assert_eq!(s2.remote_route_id(), Some(route.clone()));

    // Closing one session must not release the route the other still uses:
    // each holds its own reference after the recovery.
    s1.close();
    eventually("client sees the close", || async { c1.is_closed() }).await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(
        server
            .endpoint
            .api()
            .release_private_route(route.clone())
            .is_ok(),
        "the route was released while session 2 still used it"
    );

    // Session 2 keeps working (re-importing what we just took away).
    step("s2 send", s2.send(b"still here")).await?;
    assert_eq!(step("c2 recv", c2.recv()).await?, b"still here");
    assert!(!s2.is_closed());

    server.shutdown().await;
    client.shutdown().await;
    Ok(())
}
