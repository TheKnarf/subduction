//! Manual probe for multi-machine Veilid testing.
//!
//! Real Veilid traffic needs the public Veilid network, so this cannot run in
//! CI. Instead, start `subduction_cli server --veilid --longpoll ...` on each
//! machine (all but one dialing another with `--veilid-peer <address>`, using
//! the `veilid_address` from that machine's ready file), then run this probe
//! on each machine against its _local_ server:
//!
//! ```sh
//! PROBE_URL=http://127.0.0.1:8080 PROBE_SERVICE=veilid-e2e \
//! PROBE_TAG=mac PROBE_PAYLOAD_SIZE=200000 PROBE_EXPECT=2 \
//!   cargo test --release -p subduction_cli --test veilid_remote_probe -- --ignored --nocapture
//! ```
//!
//! Each round pushes one commit (tagged with `PROBE_TAG` and the round
//! number, padded to `PROBE_PAYLOAD_SIZE` bytes so it spans many 32 KiB
//! Veilid fragments) into a fixed sedimentree, then polls the local server
//! until it holds at least `PROBE_EXPECT * round` commits, i.e. until every
//! other machine's commit for that round has arrived over Veilid, and prints
//! the round's latency.
//!
//! | Variable | Default | Meaning |
//! |----------|---------|---------|
//! | `PROBE_URL` | `http://127.0.0.1:8080` | Local server (long-poll) |
//! | `PROBE_SERVICE` | `veilid-e2e` | Discovery service name of the local server |
//! | `PROBE_TAG` | `probe` | Distinct per machine (first 28 bytes make the commit id) |
//! | `PROBE_PAYLOAD_SIZE` | `200000` | Commit size in bytes |
//! | `PROBE_EXPECT` | `2` | Number of machines taking part |
//! | `PROBE_ROUNDS` | `1` | Rounds to run (soak mode when > 1) |
//! | `PROBE_INTERVAL_SECS` | `60` | Time between the starts of consecutive rounds |
//! | `PROBE_WAIT_SECS` | `300` | Deadline for each round |
//! | `PROBE_TREE` | `126` | Byte (0-255) the sedimentree id is filled with |
//!
//! Soak mode (`PROBE_ROUNDS` > 1) exercises Veilid route churn and the
//! server's reconnect supervisor: start all machines' probes at about the
//! same time with the same settings, and let them run for an hour or more.
//! Counts are cumulative over the sedimentree, so use a fresh
//! `PROBE_TREE` (or fresh server data directories) for each run.

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

/// Distinct commit id per tag and round: round number (big-endian), then
/// the first 28 bytes of the tag.
fn commit_id(tag: &str, round: u32) -> CommitId {
    let mut bytes = [0u8; 32];
    bytes[..4].copy_from_slice(&round.to_be_bytes());
    let tag = tag.as_bytes();
    let n = tag.len().min(28);
    bytes[4..4 + n].copy_from_slice(&tag[..n]);
    CommitId::new(bytes)
}

/// Commit payload: tag and round, then deterministic filler up to `size`
/// bytes (never shorter than the tag prefix).
fn payload(tag: &str, round: u32, size: usize) -> Vec<u8> {
    let mut payload = format!("commit from {tag} round {round}:").into_bytes();
    let prefix = payload.len();
    let mut i: u32 = 0;
    while payload.len() < size {
        payload.extend_from_slice(&i.to_be_bytes());
        i = i.wrapping_add(1);
    }
    payload.truncate(size.max(prefix));
    payload
}

#[tokio::test]
#[ignore = "manual multi-machine probe; needs real Veilid servers (see module docs)"]
async fn veilid_remote_probe() {
    let url = env_or("PROBE_URL", "http://127.0.0.1:8080");
    let service = env_or("PROBE_SERVICE", "veilid-e2e");
    let tag = env_or("PROBE_TAG", "probe");
    let size: usize = env_or("PROBE_PAYLOAD_SIZE", "200000")
        .parse()
        .expect("size");
    let expect: usize = env_or("PROBE_EXPECT", "2").parse().expect("expect");
    let wait_secs: u64 = env_or("PROBE_WAIT_SECS", "300").parse().expect("wait");
    let rounds: u32 = env_or("PROBE_ROUNDS", "1").parse().expect("rounds");
    let interval_secs: u64 = env_or("PROBE_INTERVAL_SECS", "60")
        .parse()
        .expect("interval");
    let tree: u8 = env_or("PROBE_TREE", "126").parse().expect("tree");

    let sed_id = SedimentreeId::new([tree; 32]);
    let interval = Duration::from_secs(interval_secs);
    let mut latencies = Vec::new();

    for round in 1..=rounds {
        let round_start = tokio::time::Instant::now();
        let head = commit_id(&tag, round);
        let payload = payload(&tag, round, size);
        let want = expect * round as usize;

        // Fresh long-poll connections each round: a soak can outlive idle
        // long-poll sessions.
        let pusher = connect(&url, 0xA0, &service).await;
        pusher
            .add_commit(sed_id, head, BTreeSet::new(), Blob::new(payload.clone()))
            .await
            .expect("add commit");
        let (ok, _, call_errs, io_errs) = pusher.full_sync_with_all_peers(SYNC_TIMEOUT).await;
        assert!(
            ok && call_errs.is_empty() && io_errs.is_empty(),
            "probe[{tag}] round {round}: push failed"
        );
        eprintln!(
            "probe[{tag}] round {round}/{rounds}: pushed {} byte commit {head:?} to {url}",
            payload.len()
        );

        let verifier = connect(&url, 0xA1, &service).await;
        let deadline = round_start + Duration::from_secs(wait_secs);
        loop {
            if let Err(e) = verifier
                .sync_with_all_peers(sed_id, true, SYNC_TIMEOUT)
                .await
            {
                eprintln!("probe[{tag}] round {round}: sync error: {e:?}");
            }
            let commits = verifier.get_commits(sed_id).await.unwrap_or_default();
            eprintln!(
                "probe[{tag}] round {round}: local server holds {}/{want} commit(s)",
                commits.len()
            );
            if commits.len() >= want {
                let latency = round_start.elapsed();
                latencies.push(latency);
                eprintln!(
                    "probe[{tag}] round {round}/{rounds}: OK after {:.1}s",
                    latency.as_secs_f64()
                );
                break;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "probe[{tag}] round {round}: timed out after {wait_secs}s with {}/{want} commit(s)",
                commits.len()
            );
            tokio::time::sleep(Duration::from_secs(5)).await;
        }

        if round < rounds {
            tokio::time::sleep_until(round_start + interval).await;
        }
    }

    let secs: Vec<String> = latencies
        .iter()
        .map(|l| format!("{:.1}", l.as_secs_f64()))
        .collect();
    let max = latencies.iter().max().copied().unwrap_or_default();
    eprintln!(
        "probe[{tag}]: SUCCESS, {rounds} round(s); latencies (s) [{}]; max {:.1}s",
        secs.join(", "),
        max.as_secs_f64()
    );
}
