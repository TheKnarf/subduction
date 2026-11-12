//! Integration tests for the Veilid transport.
//!
//! Exercises the full flow over veilid-core's in-process mock network:
//! endpoint setup, session open/accept, Ed25519 handshake, and data sync via
//! Subduction's protocol.

#![allow(
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::unwrap_used,
    missing_docs,
    unreachable_pub
)]

mod common;

use std::{collections::BTreeSet, sync::Arc, time::Duration};

use common::{eventually, init_tracing, start_endpoint, step};
use future_form::Sendable;
use rand::RngCore;
use sedimentree_core::{
    blob::Blob, depth::CountLeadingZeroBytes, id::SedimentreeId, loose_commit::id::CommitId,
};
use subduction_core::{
    connection::test_utils::TokioSpawn,
    handler::sync::SyncHandler,
    handshake::audience::{Audience, DiscoveryId},
    nonce_cache::NonceCache,
    peer::id::PeerId,
    policy::open::OpenPolicy,
    storage::memory::MemoryStorage,
    subduction::{Subduction, builder::SubductionBuilder},
    timeout::call::CallTimeout,
    transport::message::MessageTransport,
};
use subduction_crypto::signer::memory::MemorySigner;
use subduction_veilid::{
    endpoint::VeilidEndpoint, error::ConnectError, server::accept_one, transport::VeilidTransport,
};
use subduction_websocket::timeout::FuturesTimerTimeout;
use testresult::TestResult;

const REQUEST_TIMEOUT: CallTimeout = CallTimeout::TimeoutMillis(10_000);
const HANDSHAKE_MAX_DRIFT: Duration = Duration::from_secs(60);

type TestSubduction = Arc<
    Subduction<
        'static,
        Sendable,
        MemoryStorage,
        MessageTransport<VeilidTransport>,
        SyncHandler<
            Sendable,
            MemoryStorage,
            MessageTransport<VeilidTransport>,
            OpenPolicy,
            CountLeadingZeroBytes,
            TokioSpawn,
        >,
        OpenPolicy,
        MemorySigner,
        FuturesTimerTimeout,
        TokioSpawn,
        CountLeadingZeroBytes,
    >,
>;

fn signer(seed: u8) -> MemorySigner {
    MemorySigner::from_bytes(&[seed; 32])
}

fn random_commit_id() -> CommitId {
    let mut bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    CommitId::new(bytes)
}

fn random_blob(size: usize) -> Blob {
    let mut bytes = vec![0u8; size];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    Blob::new(bytes)
}

fn spawn_subduction(sig: &MemorySigner, discovery_id: Option<DiscoveryId>) -> TestSubduction {
    let mut builder = SubductionBuilder::new()
        .signer(sig.clone())
        .storage(MemoryStorage::default(), Arc::new(OpenPolicy))
        .spawner(TokioSpawn)
        .timer(FuturesTimerTimeout);

    if let Some(id) = discovery_id {
        builder = builder.discovery_id(id);
    }

    let (subduction, _handler, listener_fut, manager_fut) =
        builder.build::<Sendable, MessageTransport<VeilidTransport>>();

    tokio::spawn(listener_fut);
    tokio::spawn(manager_fut);

    subduction
}

// ─── Test Helpers ────────────────────────────────────────────────────────────

struct TestServer {
    subduction: TestSubduction,
    endpoint: VeilidEndpoint,
    peer_id: PeerId,
}

impl TestServer {
    async fn start(seed: u8, service_name: Option<&str>) -> Self {
        let sig = signer(seed);
        let peer_id = PeerId::from(sig.verifying_key());

        let discovery_id = service_name.map(|s| DiscoveryId::new(s.as_bytes()));
        let discovery_audience = discovery_id.map(Audience::discover_id);
        let subduction = spawn_subduction(&sig, discovery_id);

        let endpoint = start_endpoint().await;

        let accept_subduction = subduction.clone();
        let accept_ep = endpoint.clone();
        let nonce_cache = NonceCache::default();
        tokio::spawn(async move {
            loop {
                match accept_one(
                    &accept_ep,
                    &sig,
                    &nonce_cache,
                    peer_id,
                    discovery_audience,
                    HANDSHAKE_MAX_DRIFT,
                )
                .await
                {
                    Ok(result) => {
                        tokio::spawn(result.listener_task);
                        tokio::spawn(result.sender_task);
                        let auth = result.authenticated.map(MessageTransport::new);
                        if let Err(e) = accept_subduction.add_connection(auth).await {
                            tracing::error!("add_connection error: {e}");
                        }
                    }
                    Err(subduction_veilid::error::AcceptError::NoIncoming) => break,
                    Err(e) => tracing::warn!("accept error: {e}"),
                }
            }
        });

        Self {
            subduction,
            endpoint,
            peer_id,
        }
    }
}

struct TestClient {
    subduction: TestSubduction,
    peer_id: PeerId,
    endpoint: VeilidEndpoint,
}

impl TestClient {
    async fn connect_with(seed: u8, server: &TestServer, audience: Audience) -> Self {
        let sig = signer(seed);
        let peer_id = PeerId::from(sig.verifying_key());
        let subduction = spawn_subduction(&sig, None);
        let endpoint = start_endpoint().await;

        let result = step(
            "client connect",
            subduction_veilid::client::connect(
                &endpoint,
                &server.endpoint.route_blob(),
                &sig,
                audience,
            ),
        )
        .await
        .expect("client connect");

        tokio::spawn(result.listener_task);
        tokio::spawn(result.sender_task);
        let auth = result.authenticated.map(MessageTransport::new);
        subduction
            .add_connection(auth)
            .await
            .expect("add_connection");

        Self {
            subduction,
            peer_id,
            endpoint,
        }
    }

    async fn connect(seed: u8, server: &TestServer) -> Self {
        Self::connect_with(seed, server, Audience::known(server.peer_id)).await
    }
}

async fn wait_connected(server: &TestServer, client: &TestClient) {
    eventually("peers see each other", || async {
        server
            .subduction
            .connected_peer_ids()
            .await
            .contains(&client.peer_id)
            && client
                .subduction
                .connected_peer_ids()
                .await
                .contains(&server.peer_id)
    })
    .await;
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[tokio::test]
async fn handshake_connects_peers() -> TestResult {
    init_tracing();

    let server = TestServer::start(0, None).await;
    let client = TestClient::connect(1, &server).await;
    wait_connected(&server, &client).await;

    client.endpoint.shutdown().await;
    server.endpoint.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn bidirectional_sync_with_multi_fragment_blobs() -> TestResult {
    init_tracing();

    let server = TestServer::start(20, None).await;
    let client = TestClient::connect(21, &server).await;
    wait_connected(&server, &client).await;

    // Client -> server: a small and a large (multi-fragment) commit.
    let sed_id = SedimentreeId::new([99u8; 32]);
    client
        .subduction
        .add_commit(sed_id, random_commit_id(), BTreeSet::new(), random_blob(64))
        .await?;
    client
        .subduction
        .add_commit(
            sed_id,
            random_commit_id(),
            BTreeSet::new(),
            random_blob(200 * 1024),
        )
        .await?;

    let (had_success, _, call_errs, io_errs) = step(
        "client full sync",
        client.subduction.full_sync_with_all_peers(REQUEST_TIMEOUT),
    )
    .await;
    assert!(call_errs.is_empty(), "call errors: {call_errs:?}");
    assert!(io_errs.is_empty(), "io errors: {io_errs:?}");
    assert!(had_success, "sync should succeed");

    eventually("server has both commits", || async {
        server
            .subduction
            .get_commits(sed_id)
            .await
            .is_some_and(|c| c.len() >= 2)
    })
    .await;

    // Server -> client: another large commit, pulled by the client.
    server
        .subduction
        .add_commit(
            sed_id,
            random_commit_id(),
            BTreeSet::new(),
            random_blob(150 * 1024),
        )
        .await?;

    let result = step(
        "client pull",
        client
            .subduction
            .sync_with_all_peers(sed_id, true, REQUEST_TIMEOUT),
    )
    .await?;
    assert!(
        result.values().any(|(success, _, _)| *success),
        "pull should succeed"
    );

    eventually("client has all three commits", || async {
        client
            .subduction
            .get_commits(sed_id)
            .await
            .is_some_and(|c| c.len() >= 3)
    })
    .await;

    client.endpoint.shutdown().await;
    server.endpoint.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn disconnect_propagates_to_server() -> TestResult {
    init_tracing();

    let server = TestServer::start(30, None).await;
    let client = TestClient::connect(31, &server).await;
    wait_connected(&server, &client).await;

    client.subduction.disconnect_all().await?;

    eventually("server drops the client", || async {
        !server
            .subduction
            .connected_peer_ids()
            .await
            .contains(&client.peer_id)
    })
    .await;
    eventually("server session table empty", || async {
        server.endpoint.session_count() == 0
    })
    .await;

    // The same identity can reconnect afterwards.
    let client2 = TestClient::connect(31, &server).await;
    wait_connected(&server, &client2).await;

    client.endpoint.shutdown().await;
    client2.endpoint.shutdown().await;
    server.endpoint.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn server_shutdown_propagates_to_client() -> TestResult {
    init_tracing();

    let server = TestServer::start(40, None).await;
    let client = TestClient::connect(41, &server).await;
    wait_connected(&server, &client).await;

    server.endpoint.shutdown().await;

    eventually("client drops the server", || async {
        !client
            .subduction
            .connected_peer_ids()
            .await
            .contains(&server.peer_id)
    })
    .await;

    client.endpoint.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn wrong_audience_rejected() -> TestResult {
    init_tracing();

    let server = TestServer::start(50, None).await;
    let client_ep = start_endpoint().await;

    // Expect a different server identity than the one we reach.
    let wrong = PeerId::from(signer(99).verifying_key());
    let result = step(
        "connect with wrong audience",
        subduction_veilid::client::connect(
            &client_ep,
            &server.endpoint.route_blob(),
            &signer(51),
            Audience::known(wrong),
        ),
    )
    .await;
    assert!(
        matches!(result, Err(ConnectError::Handshake(_))),
        "connection with wrong audience should fail: {result:?}"
    );

    // The failed session does not linger on either side.
    eventually("sessions cleaned up", || async {
        server.endpoint.session_count() == 0 && client_ep.session_count() == 0
    })
    .await;

    client_ep.shutdown().await;
    server.endpoint.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn discovery_mode_handshake() -> TestResult {
    init_tracing();

    let service = "test.veilid.discover";
    let server = TestServer::start(60, Some(service)).await;
    let client =
        TestClient::connect_with(61, &server, Audience::discover(service.as_bytes())).await;
    wait_connected(&server, &client).await;

    client.endpoint.shutdown().await;
    server.endpoint.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn discovery_wrong_service_name_rejected() -> TestResult {
    init_tracing();

    let server = TestServer::start(70, Some("service-alpha")).await;
    let client_ep = start_endpoint().await;

    let result = step(
        "connect with wrong service",
        subduction_veilid::client::connect(
            &client_ep,
            &server.endpoint.route_blob(),
            &signer(71),
            Audience::discover(b"service-beta"),
        ),
    )
    .await;
    assert!(result.is_err(), "wrong service name should fail");

    client_ep.shutdown().await;
    server.endpoint.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn multiple_clients_converge() -> TestResult {
    init_tracing();

    let server = TestServer::start(80, None).await;
    let c1 = TestClient::connect(81, &server).await;
    let c2 = TestClient::connect(82, &server).await;
    wait_connected(&server, &c1).await;
    wait_connected(&server, &c2).await;

    let sed_id = SedimentreeId::new([7u8; 32]);
    c1.subduction
        .add_commit(
            sed_id,
            random_commit_id(),
            BTreeSet::new(),
            random_blob(128),
        )
        .await?;
    c2.subduction
        .add_commit(
            sed_id,
            random_commit_id(),
            BTreeSet::new(),
            random_blob(128),
        )
        .await?;

    for c in [&c1, &c2] {
        let (ok, _, call_errs, io_errs) = step(
            "push",
            c.subduction.full_sync_with_all_peers(REQUEST_TIMEOUT),
        )
        .await;
        assert!(ok && call_errs.is_empty() && io_errs.is_empty());
    }
    for c in [&c1, &c2] {
        step(
            "pull",
            c.subduction
                .sync_with_all_peers(sed_id, true, REQUEST_TIMEOUT),
        )
        .await?;
    }

    for c in [&c1, &c2] {
        eventually("client converged", || async {
            c.subduction
                .get_commits(sed_id)
                .await
                .is_some_and(|commits| commits.len() >= 2)
        })
        .await;
    }

    c1.endpoint.shutdown().await;
    c2.endpoint.shutdown().await;
    server.endpoint.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn endpoint_shutdown_stops_accept() -> TestResult {
    init_tracing();

    let server = TestServer::start(90, None).await;
    let blob = server.endpoint.route_blob();
    server.endpoint.shutdown().await;

    let client_ep = start_endpoint().await;
    let result = step(
        "connect to shut-down endpoint",
        subduction_veilid::client::connect(
            &client_ep,
            &blob,
            &signer(91),
            Audience::known(server.peer_id),
        ),
    )
    .await;
    assert!(
        result.is_err(),
        "should not be able to connect to a shut-down endpoint"
    );

    client_ep.shutdown().await;
    Ok(())
}
