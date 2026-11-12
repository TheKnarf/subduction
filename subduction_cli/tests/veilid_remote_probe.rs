//! Manual probe for multi-machine Veilid testing.
//!
//! Real Veilid traffic needs the public Veilid network, so this cannot run in
//! CI. Instead, start `subduction_cli server --veilid --longpoll ...` on two
//! machines (one dialing the other with `--veilid-peer <route>`), then run this
//! probe on each machine against its _local_ server:
//!
//! ```sh
//! PROBE_URL=http://127.0.0.1:8080 PROBE_SERVICE=veilid-e2e \
//! PROBE_TAG=mac PROBE_PAYLOAD_SIZE=200000 PROBE_EXPECT=2 \
//!   cargo test --release -p subduction_cli --test veilid_remote_probe -- --ignored --nocapture
//! ```
//!
//! The probe pushes one commit (tagged with `PROBE_TAG`, padded to
//! `PROBE_PAYLOAD_SIZE` bytes so it spans many 32 KiB Veilid fragments) into a
//! fixed sedimentree, then polls the local server until it holds at least
//! `PROBE_EXPECT` commits — i.e. until the other machine's commit has arrived
//! over Veilid.

#![allow(
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::unwrap_used,
    missing_docs,
    unreachable_pub
)]

use std::{collections::BTreeSet, sync::Arc, time::Duration};

use future_form::Sendable;
use sedimentree_core::{
    blob::Blob, depth::CountLeadingZeroBytes, id::SedimentreeId, loose_commit::id::CommitId,
};
use subduction_core::{
    connection::test_utils::TokioSpawn,
    handler::sync::SyncHandler,
    policy::open::OpenPolicy,
    storage::memory::MemoryStorage,
    subduction::{Subduction, builder::SubductionBuilder},
    timeout::call::CallTimeout,
    timestamp::TimestampSeconds,
    transport::message::MessageTransport,
};
use subduction_crypto::signer::memory::MemorySigner;
use subduction_http_longpoll::{
    client::HttpLongPollClient, http_client::reqwest_client::ReqwestHttpClient,
    transport::HttpLongPollTransport,
};
use subduction_websocket::timeout::FuturesTimerTimeout;

const SYNC_TIMEOUT: CallTimeout = CallTimeout::TimeoutMillis(60_000);

type ProbeSubduction = Arc<
    Subduction<
        'static,
        Sendable,
        MemoryStorage,
        MessageTransport<HttpLongPollTransport>,
        SyncHandler<
            Sendable,
            MemoryStorage,
            MessageTransport<HttpLongPollTransport>,
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

fn env_or(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_owned())
}

async fn connect(base_url: &str, seed: u8, service_name: &str) -> ProbeSubduction {
    let signer = MemorySigner::from_bytes(&[seed; 32]);
    let (subduction, _handler, listener_fut, manager_fut): (ProbeSubduction, _, _, _) =
        SubductionBuilder::new()
            .signer(signer.clone())
            .storage(MemoryStorage::default(), Arc::new(OpenPolicy))
            .spawner(TokioSpawn)
            .timer(FuturesTimerTimeout)
            .build::<Sendable, MessageTransport<HttpLongPollTransport>>();
    tokio::spawn(listener_fut);
    tokio::spawn(manager_fut);

    let lp = HttpLongPollClient::new(base_url, ReqwestHttpClient::new());
    let result = lp
        .connect_discover(&signer, service_name, TimestampSeconds::now())
        .await
        .expect("HTTP long-poll connect");
    tokio::spawn(result.poll_task);
    tokio::spawn(result.send_task);
    subduction
        .add_connection(result.authenticated.map(MessageTransport::new))
        .await
        .expect("add_connection");
    subduction
}

#[tokio::test]
#[ignore = "manual multi-machine probe; needs real Veilid servers (see module docs)"]
async fn veilid_remote_probe() {
    let url = env_or("PROBE_URL", "http://127.0.0.1:8080");
    let service = env_or("PROBE_SERVICE", "veilid-e2e");
    let tag = env_or("PROBE_TAG", "probe");
    let size: usize = env_or("PROBE_PAYLOAD_SIZE", "200000").parse().expect("size");
    let expect: usize = env_or("PROBE_EXPECT", "2").parse().expect("expect");
    let wait_secs: u64 = env_or("PROBE_WAIT_SECS", "300").parse().expect("wait");

    let sed_id = SedimentreeId::new([0x7e; 32]);

    // Payload: tag, then deterministic filler up to `size` bytes.
    let mut payload = format!("commit from {tag}:").into_bytes();
    let mut i: u32 = 0;
    while payload.len() < size {
        payload.extend_from_slice(&i.to_be_bytes());
        i = i.wrapping_add(1);
    }
    payload.truncate(size.max(tag.len()));
    let head = CommitId::new({
        // The tag prefix makes each machine's commit id distinct.
        let mut bytes = [0u8; 32];
        let n = payload.len().min(32);
        bytes[..n].copy_from_slice(&payload[..n]);
        bytes
    });

    let pusher = connect(&url, 0xA0, &service).await;
    pusher
        .add_commit(sed_id, head, BTreeSet::new(), Blob::new(payload.clone()))
        .await
        .expect("add commit");
    let (ok, _, call_errs, io_errs) = pusher.full_sync_with_all_peers(SYNC_TIMEOUT).await;
    assert!(ok && call_errs.is_empty() && io_errs.is_empty(), "push failed");
    eprintln!(
        "probe[{tag}]: pushed {} byte commit {head:?} to {url}",
        payload.len()
    );

    let verifier = connect(&url, 0xA1, &service).await;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(wait_secs);
    loop {
        if let Err(e) = verifier.sync_with_all_peers(sed_id, true, SYNC_TIMEOUT).await {
            eprintln!("probe[{tag}]: sync error: {e:?}");
        }
        let commits = verifier.get_commits(sed_id).await.unwrap_or_default();
        eprintln!("probe[{tag}]: local server holds {} commit(s)", commits.len());
        if commits.len() >= expect {
            let sizes: Vec<usize> = verifier
                .get_blobs(sed_id)
                .await
                .ok()
                .flatten()
                .map(|blobs| blobs.iter().map(|b| b.as_slice().len()).collect())
                .unwrap_or_default();
            eprintln!("probe[{tag}]: SUCCESS — blob sizes {sizes:?}");
            return;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "probe[{tag}]: timed out after {wait_secs}s with {} commit(s)",
            commits.len()
        );
        tokio::time::sleep(Duration::from_secs(5)).await;
    }
}
