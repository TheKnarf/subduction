//! Server-side accept for the Veilid transport.
//!
//! Accepts incoming sessions, runs the Subduction handshake to authenticate
//! the remote peer, and creates [`Authenticated`] connections ready for use
//! with Subduction.

use core::time::Duration;

use future_form::Sendable;
use futures::future::BoxFuture;
use subduction_core::{
    authenticated::Authenticated,
    handshake::{self, audience::Audience},
    nonce_cache::NonceCache,
    peer::id::PeerId,
    timestamp::TimestampSeconds,
};
use subduction_crypto::signer::Signer;

use crate::{
    endpoint::VeilidEndpoint,
    error::{AcceptError, RunError},
    handshake::VeilidHandshake,
    transport::VeilidTransport,
};

/// Result of accepting a single incoming connection.
pub struct AcceptResult {
    /// The authenticated connection.
    pub authenticated: Authenticated<VeilidTransport, Sendable>,

    /// The remote peer's identity (as proven by the handshake).
    pub peer_id: PeerId,

    /// Background listener task -- must be spawned.
    pub listener_task: BoxFuture<'static, Result<(), RunError>>,

    /// Background sender task -- must be spawned.
    pub sender_task: BoxFuture<'static, Result<(), RunError>>,
}

impl core::fmt::Debug for AcceptResult {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("AcceptResult")
            .field("peer_id", &self.peer_id)
            .finish_non_exhaustive()
    }
}

/// Accept a single incoming Veilid session and authenticate it.
///
/// Waits for an inbound session and runs the Subduction handshake, bounded by
/// the endpoint's
/// [`handshake_timeout`](crate::endpoint::EndpointConfig::handshake_timeout)
/// so a peer that opens a session and goes silent cannot stall an accept
/// loop.
///
/// # Errors
///
/// [`AcceptError::NoIncoming`] once the endpoint is shut down (stop
/// accepting). Any other error concerns only this one session; keep
/// accepting.
///
/// # Example
///
/// ```ignore
/// loop {
///     let result = match accept_one(
///         &endpoint, &signer, &nonce_cache, our_peer_id, None, Duration::from_secs(600),
///     ).await {
///         Ok(r) => r,
///         Err(AcceptError::NoIncoming) => break,
///         Err(e) => { tracing::warn!("{e}"); continue; }
///     };
///     tokio::spawn(result.listener_task);
///     tokio::spawn(result.sender_task);
///     subduction.add_connection(result.authenticated).await?;
/// }
/// ```
pub async fn accept_one<S>(
    endpoint: &VeilidEndpoint,
    signer: &S,
    nonce_cache: &NonceCache,
    our_peer_id: PeerId,
    discovery_audience: Option<Audience>,
    handshake_max_drift: Duration,
) -> Result<AcceptResult, AcceptError>
where
    S: Signer<Sendable>,
{
    let session = endpoint.accept().await.ok_or(AcceptError::NoIncoming)?;

    tracing::info!(session = %session.id(), "veilid: accepted session, starting handshake");

    let now = TimestampSeconds::now();

    let handshake = handshake::respond::<Sendable, _, _, _, _>(
        VeilidHandshake::new(session),
        |veilid_handshake, peer_id| {
            let session = veilid_handshake.into_session();
            // Authenticated: lift the pre-handshake size limits.
            session.mark_established();
            let (conn, outbound_rx) = VeilidTransport::new(peer_id, session.clone());

            let listener_task: BoxFuture<'static, Result<(), RunError>> =
                Box::pin(crate::tasks::listener_task(conn.clone(), session.clone()));
            let sender_task: BoxFuture<'static, Result<(), RunError>> =
                Box::pin(crate::tasks::sender_task(session, outbound_rx));

            (conn, (listener_task, sender_task))
        },
        signer,
        nonce_cache,
        our_peer_id,
        discovery_audience,
        now,
        handshake_max_drift,
    );

    let (authenticated, (listener_task, sender_task)) =
        tokio::time::timeout(endpoint.config().handshake_timeout, handshake)
            .await
            .map_err(|_| AcceptError::HandshakeTimeout)?
            .map_err(Box::new)?;

    let peer_id = authenticated.peer_id();
    tracing::info!(peer_id = %peer_id, "veilid: handshake complete, authenticated");

    Ok(AcceptResult {
        authenticated,
        peer_id,
        listener_task,
        sender_task,
    })
}
