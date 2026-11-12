//! Client-side connection establishment for the Veilid transport.
//!
//! Connects to a remote peer by its [`VeilidAddress`] (stable DHT address or
//! raw private route blob) and returns an [`Authenticated`] connection with
//! background listener and sender tasks.

use future_form::Sendable;
use futures::future::BoxFuture;
use subduction_core::{
    authenticated::Authenticated,
    handshake::{self, audience::Audience},
    timestamp::TimestampSeconds,
};
use subduction_crypto::{nonce::Nonce, signer::Signer};

use crate::{
    address::VeilidAddress,
    endpoint::VeilidEndpoint,
    error::{ConnectError, RunError},
    handshake::VeilidHandshake,
    transport::VeilidTransport,
};

/// Result of a successful connection attempt.
///
/// Contains the authenticated connection plus two background task futures
/// that must be spawned externally for the connection to function.
pub struct ConnectResult {
    /// The authenticated connection, ready for use with Subduction.
    pub authenticated: Authenticated<VeilidTransport, Sendable>,

    /// Background task that receives from the session.
    /// Must be spawned (e.g., via `tokio::spawn`).
    pub listener_task: BoxFuture<'static, Result<(), RunError>>,

    /// Background task that sends over the session.
    /// Must be spawned (e.g., via `tokio::spawn`).
    pub sender_task: BoxFuture<'static, Result<(), RunError>>,
}

impl core::fmt::Debug for ConnectResult {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ConnectResult")
            .field("authenticated", &self.authenticated)
            .finish_non_exhaustive()
    }
}

/// Connect to a remote peer via Veilid.
///
/// Imports the peer's private route blob, opens a session (sending our own
/// route blob so the peer can answer), and runs the Subduction handshake to
/// mutually authenticate both peers. Veilid private routes carry no peer
/// identity, so the handshake is the _only_ authentication.
///
/// The handshake is bounded by the endpoint's
/// [`handshake_timeout`](crate::endpoint::EndpointConfig::handshake_timeout).
///
/// # Errors
///
/// Returns an error if the route blob is invalid, the session cannot be
/// opened, or the handshake fails or times out.
///
/// # Example
///
/// ```ignore
/// let result = connect(&endpoint, &remote_blob, &signer, Audience::known(peer_id)).await?;
/// tokio::spawn(result.listener_task);
/// tokio::spawn(result.sender_task);
/// subduction.add_connection(result.authenticated).await?;
/// ```
pub async fn connect<S>(
    endpoint: &VeilidEndpoint,
    remote_route_blob: &[u8],
    signer: &S,
    audience: Audience,
) -> Result<ConnectResult, ConnectError>
where
    S: Signer<Sendable>,
{
    let session = endpoint.open_session(remote_route_blob).await?;
    handshake_over(endpoint, session, signer, audience).await
}

/// Connect to a remote peer by [`VeilidAddress`].
///
/// A DHT address is resolved to the peer's _current_ route blob on every
/// call (with a forced network refresh), so redialling a peer by its stable
/// address keeps working after it reallocates its route or restarts. A
/// route blob address behaves like [`connect`].
///
/// # Errors
///
/// [`ConnectError::Resolve`] if the address cannot be resolved (e.g.
/// `TryAgain` while our node is still attaching, or the peer has not
/// published yet), otherwise as [`connect`].
///
/// # Example
///
/// ```ignore
/// let address: VeilidAddress = "VLD0:...".parse()?;
/// let result = connect_address(&endpoint, &address, &signer, Audience::known(peer_id)).await?;
/// ```
pub async fn connect_address<S>(
    endpoint: &VeilidEndpoint,
    address: &VeilidAddress,
    signer: &S,
    audience: Audience,
) -> Result<ConnectResult, ConnectError>
where
    S: Signer<Sendable>,
{
    let session = endpoint.open_session_to(address).await?;
    handshake_over(endpoint, session, signer, audience).await
}

/// Run the initiator's handshake over a freshly opened session.
async fn handshake_over<S>(
    endpoint: &VeilidEndpoint,
    session: crate::session::Session,
    signer: &S,
    audience: Audience,
) -> Result<ConnectResult, ConnectError>
where
    S: Signer<Sendable>,
{
    tracing::info!(session = %session.id(), "veilid: session opened, starting handshake");

    let now = TimestampSeconds::now();
    let nonce = Nonce::random();

    let handshake = handshake::initiate::<Sendable, _, _, _, _>(
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
        audience,
        now,
        nonce,
    );

    // Dropping the handshake future on timeout drops the session, which
    // closes it and notifies the peer.
    let (authenticated, (listener_task, sender_task)) =
        tokio::time::timeout(endpoint.config().handshake_timeout, handshake)
            .await
            .map_err(|_| ConnectError::HandshakeTimeout)?
            .map_err(Box::new)?;

    tracing::info!(peer_id = %authenticated.peer_id(), "veilid: handshake complete, authenticated");

    Ok(ConnectResult {
        authenticated,
        listener_task,
        sender_task,
    })
}
