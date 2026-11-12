//! Shared helpers for the integration tests.
//!
//! Every test runs against veilid-core's in-process mock network (enabled
//! through the `mock-api` dev-dependency feature), so endpoints in one test
//! process can reach each other without any real networking.

#![allow(dead_code, clippy::expect_used, unreachable_pub)]

use std::{
    sync::{
        OnceLock,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use subduction_veilid::{
    endpoint::{EndpointConfig, VeilidDispatcher, VeilidEndpoint},
    session::Session,
    veilid_core::{RouteId, VeilidConfig, VeilidRouteChange, VeilidUpdate},
};

/// Generous upper bound for any single step of a test.
pub const STEP_TIMEOUT: Duration = Duration::from_secs(20);

pub fn init_tracing() {
    static ONCE: OnceLock<()> = OnceLock::new();
    ONCE.get_or_init(|| {
        tracing_subscriber::fmt()
            .with_env_filter(
                tracing_subscriber::EnvFilter::try_from_default_env()
                    .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
            )
            .with_test_writer()
            .init();
    });
}

/// A Veilid config with a process-unique `program_name` + `namespace`, as
/// `api_startup` requires for concurrently running nodes.
pub fn unique_veilid_config() -> VeilidConfig {
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    let n = NEXT.fetch_add(1, Ordering::Relaxed);
    VeilidConfig {
        program_name: "subduction-veilid-test".to_owned(),
        namespace: format!("node-{}-{n}", std::process::id()),
        ..VeilidConfig::default()
    }
}

/// Endpoint config with short timeouts so failures surface quickly.
pub fn test_endpoint_config() -> EndpointConfig {
    let mut config = EndpointConfig::default();
    config.call_timeout = Duration::from_secs(5);
    config.handshake_timeout = Duration::from_secs(10);
    config.route_allocation_timeout = Duration::from_secs(10);
    config.close_timeout = Duration::from_secs(2);
    config.max_busy_wait = Duration::from_secs(5);
    config
}

pub async fn start_endpoint_with(config: EndpointConfig) -> VeilidEndpoint {
    VeilidEndpoint::start(unique_veilid_config(), config, None)
        .await
        .expect("start veilid endpoint")
}

pub async fn start_endpoint() -> VeilidEndpoint {
    start_endpoint_with(test_endpoint_config()).await
}

/// Await `fut`, failing the test if it takes longer than [`STEP_TIMEOUT`].
pub async fn step<F: Future>(what: &str, fut: F) -> F::Output {
    tokio::time::timeout(STEP_TIMEOUT, fut)
        .await
        .unwrap_or_else(|_| panic!("timed out: {what}"))
}

/// Poll `cond` until it holds or [`STEP_TIMEOUT`] elapses.
pub async fn eventually<F, Fut>(what: &str, mut cond: F)
where
    F: FnMut() -> Fut,
    Fut: Future<Output = bool>,
{
    step(what, async {
        while !cond().await {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await;
}

/// Deterministic pseudo-random payload.
pub fn payload(len: usize, seed: u8) -> Vec<u8> {
    (0..len)
        .map(|i| u8::try_from(i % 251).expect("< 251") ^ seed)
        .collect()
}

/// An endpoint bound (in "bring your own node" mode) to a Veilid node whose
/// updates go through `dispatcher`, so tests can inject synthetic updates
/// such as route changes.
pub struct BoundEndpoint {
    pub endpoint: VeilidEndpoint,
    pub dispatcher: VeilidDispatcher,
}

impl BoundEndpoint {
    pub async fn start(config: EndpointConfig) -> Self {
        let dispatcher = VeilidDispatcher::new();
        let api = subduction_veilid::veilid_core::api_startup(
            dispatcher.update_callback(None),
            unique_veilid_config(),
        )
        .await
        .expect("start veilid node");
        api.attach().await.expect("attach");
        let endpoint = VeilidEndpoint::bind(api, &dispatcher, config)
            .await
            .expect("bind endpoint");
        Self {
            endpoint,
            dispatcher,
        }
    }

    /// Inject a `RouteChange` as Veilid would deliver it.
    pub fn route_change(&self, dead_routes: Vec<RouteId>, dead_remote_routes: Vec<RouteId>) {
        let change = VeilidRouteChange {
            dead_routes,
            dead_remote_routes,
        };
        let _passed_on = self
            .dispatcher
            .handle_update(VeilidUpdate::RouteChange(Box::new(change)));
    }

    /// Shut the endpoint and its Veilid node down.
    pub async fn shutdown(&self) {
        self.endpoint.shutdown().await;
        self.endpoint.api().clone().shutdown().await;
    }
}

/// Open a session from `client` to `server`, accept it, and mark both ends
/// established (as the handshake would).
pub async fn pair(client: &VeilidEndpoint, server: &VeilidEndpoint) -> (Session, Session) {
    let blob = server.route_blob();
    let (opened, accepted) = step("open + accept", async {
        tokio::join!(client.open_session(&blob), server.accept())
    })
    .await;
    let (c, s) = (
        opened.expect("open session"),
        accepted.expect("accept session"),
    );
    c.mark_established();
    s.mark_established();
    (c, s)
}
