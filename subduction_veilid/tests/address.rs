//! Stable DHT addresses over veilid-core's mock network (which simulates the
//! DHT): publish, resolve, connect, stability across restarts, and
//! republishing after a route reallocation.

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
    BoundEndpoint, eventually, init_tracing, start_endpoint, start_endpoint_with, step,
    test_endpoint_config,
};
use subduction_core::{handshake::audience::Audience, nonce_cache::NonceCache, peer::id::PeerId};
use subduction_crypto::signer::memory::MemorySigner;
use subduction_veilid::{
    address::{ResolveError, VeilidAddress},
    client::connect_address,
    endpoint::{AddressKeyStore, VeilidEndpoint},
    error::ConnectError,
    server::accept_one,
    veilid_core::DHTSchema,
};
use testresult::TestResult;

async fn published(endpoint: &VeilidEndpoint) -> VeilidAddress {
    step("address published", endpoint.wait_address_published())
        .await
        .expect("publishing enabled")
}

#[tokio::test]
async fn address_is_published_and_resolves_to_current_blob() -> TestResult {
    init_tracing();
    let server = start_endpoint().await;
    let client = start_endpoint().await;

    let address = published(&server).await;
    assert!(address.is_record());
    assert_eq!(server.address(), Some(address.clone()));
    // String form round-trips (this is what users pass around).
    let parsed: VeilidAddress = address.to_string().parse()?;
    assert_eq!(parsed, address);

    assert_eq!(client.resolve(&parsed).await?, server.route_blob());
    // Resolving our own address answers locally.
    assert_eq!(server.resolve(&address).await?, server.route_blob());
    // A route blob address resolves to itself.
    let blob_address = server.route_address();
    assert_eq!(client.resolve(&blob_address).await?, server.route_blob());

    // Open a raw session by address.
    let (opened, accepted) = step("open by address + accept", async {
        tokio::join!(client.open_session_to(&address), server.accept())
    })
    .await;
    let (c, s) = (opened?, accepted.expect("accepted"));
    c.mark_established();
    s.mark_established();
    step("send", c.send(b"via dht")).await?;
    assert_eq!(step("recv", s.recv()).await?, b"via dht");

    server.shutdown().await;
    client.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn connect_address_runs_the_handshake() -> TestResult {
    init_tracing();
    let server = start_endpoint().await;
    let client = start_endpoint().await;
    let address = published(&server).await;

    let server_signer = MemorySigner::from_bytes(&[51; 32]);
    let server_peer = PeerId::from(server_signer.verifying_key());
    let client_signer = MemorySigner::from_bytes(&[52; 32]);
    let client_peer = PeerId::from(client_signer.verifying_key());

    let accept = tokio::spawn({
        let server = server.clone();
        async move {
            let nonce_cache = NonceCache::default();
            accept_one(
                &server,
                &server_signer,
                &nonce_cache,
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
            &client,
            &address,
            &client_signer,
            Audience::known(server_peer),
        ),
    )
    .await?;
    let accepted = step("accept", accept).await??;
    assert_eq!(connected.authenticated.peer_id(), server_peer);
    assert_eq!(accepted.peer_id, client_peer);

    server.shutdown().await;
    client.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn address_is_stable_across_restarts() -> TestResult {
    init_tracing();
    let dir = tempfile::tempdir()?;
    let mut config = test_endpoint_config();
    config.address_key_store = AddressKeyStore::File(dir.path().join("address.key"));

    let client = start_endpoint().await;

    let first = start_endpoint_with(config.clone()).await;
    let address = published(&first).await;
    let first_blob = first.route_blob();
    assert_eq!(client.resolve(&address).await?, first_blob);
    first.shutdown().await;

    // A fresh node (new route) with the same key store.
    let second = start_endpoint_with(config).await;
    let again = published(&second).await;
    assert_eq!(again, address, "address must survive a restart");
    let second_blob = second.route_blob();
    assert_ne!(second_blob, first_blob);
    assert_eq!(client.resolve(&address).await?, second_blob);

    // Dialling the old address reaches the new node.
    let (opened, accepted) = step("open by address + accept", async {
        tokio::join!(client.open_session_to(&address), second.accept())
    })
    .await;
    let (c, s) = (opened?, accepted.expect("accepted"));
    step("send", c.send(b"welcome back")).await?;
    assert_eq!(step("recv", s.recv()).await?, b"welcome back");

    second.shutdown().await;
    client.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn address_is_republished_after_route_reallocation() -> TestResult {
    init_tracing();
    let server = BoundEndpoint::start(test_endpoint_config()).await;
    let client = start_endpoint().await;

    let address = published(&server.endpoint).await;
    let old_blob = server.endpoint.route_blob();
    assert_eq!(client.resolve(&address).await?, old_blob);

    server.route_change(vec![server.endpoint.route_id()], Vec::new());
    eventually("route reallocated", || async {
        server.endpoint.route_blob() != old_blob
    })
    .await;
    assert_eq!(published(&server.endpoint).await, address);
    let new_blob = server.endpoint.route_blob();
    eventually("address resolves to the new route", || async {
        client.resolve(&address).await.ok() == Some(new_blob.clone())
    })
    .await;

    // A stale blob no longer works, but the address does.
    let err = client.open_session(&old_blob).await.unwrap_err();
    assert!(
        matches!(err, ConnectError::InvalidRoute(_) | ConnectError::Open(_)),
        "unexpected: {err:?}"
    );
    let (opened, accepted) = step("open by address + accept", async {
        tokio::join!(client.open_session_to(&address), server.endpoint.accept())
    })
    .await;
    opened?;
    accepted.expect("accepted");

    server.shutdown().await;
    client.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn publishing_can_be_disabled() -> TestResult {
    init_tracing();
    let mut config = test_endpoint_config();
    config.publish_address = false;
    let endpoint = start_endpoint_with(config).await;
    assert!(endpoint.wait_address_published().await.is_none());
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(endpoint.address().is_none());
    endpoint.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn resolving_an_empty_or_unknown_record_fails() -> TestResult {
    init_tracing();
    let owner = start_endpoint().await;
    let client = start_endpoint().await;

    // A record that exists but holds no route.
    let routing = owner.api().routing_context()?;
    let descriptor = routing
        .create_dht_record(owner.route_id().kind(), DHTSchema::dflt(1)?, None)
        .await?;
    let empty = VeilidAddress::Record(descriptor.key());
    let err = client.resolve(&empty).await.unwrap_err();
    assert!(
        matches!(err, ResolveError::NotPublished),
        "unexpected: {err:?}"
    );
    let err = client.open_session_to(&empty).await.unwrap_err();
    assert!(
        matches!(err, ConnectError::Resolve(ResolveError::NotPublished)),
        "unexpected: {err:?}"
    );

    // A malformed value.
    routing
        .set_dht_value(descriptor.key(), 0, b"\x09junk".to_vec(), None)
        .await?;
    let err = client.resolve(&empty).await.unwrap_err();
    assert!(
        matches!(err, ResolveError::Malformed),
        "unexpected: {err:?}"
    );

    owner.shutdown().await;
    client.shutdown().await;
    Ok(())
}
