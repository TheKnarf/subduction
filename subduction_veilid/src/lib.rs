//! # Subduction Veilid Transport
//!
//! A transport layer for the Subduction sync protocol over [Veilid] private
//! routes.
//!
//! Veilid is a privacy-preserving peer-to-peer network: nodes are reachable
//! through _private routes_ (published as opaque _route blobs_) that hide
//! their IP address, and messages are end-to-end encrypted and relayed over
//! several hops. This crate bridges Veilid's app-call messaging to
//! Subduction's [`Transport`](subduction_core::transport::Transport) trait.
//!
//! # Authentication
//!
//! Veilid private routes are anonymous: an inbound app call does not identify
//! its sender. The Subduction handshake (`Signed<Challenge>` /
//! `Signed<Response>`) run over each session is therefore the **only**
//! authentication of the remote peer.
//!
//! # Architecture
//!
//! Veilid delivers every inbound message through one update callback, so a
//! [`VeilidEndpoint`](endpoint::VeilidEndpoint) owns the node's private route
//! and demultiplexes app calls into [`Session`](session::Session)s. A session
//! is a reliable, ordered message channel built from acknowledged app calls
//! (each at most 32 KiB, so messages are fragmented):
//!
//! ```text
//! Veilid update callback --> VeilidDispatcher --> [dispatch task]
//!                                                   | OPEN: new session -> accept queue
//!                                                   | DATA/CLOSE: -> session pump
//!                                                   v
//!                             [session pump] reassemble --> Session::recv()
//!
//! [handshake: Challenge/Response exchange over the session]
//!       |
//!       v
//! send()  --> outbound_tx --> [sender task] --> Session::send --> app_call(DATA)...
//! Session::recv --> [listener task] --> inbound_writer --> recv()
//! ```
//!
//! Sessions survive route churn: a dead peer route is re-imported, a dead own
//! route is reallocated and announced to peers (`ROUTE_UPDATE`), and the
//! endpoint publishes its current route under a stable DHT
//! [`address`](address::VeilidAddress). See the crate README for the session
//! wire protocol and the route-change rules.
//!
//! # Example
//!
//! ```ignore
//! use subduction_veilid::{client, VeilidAddress, endpoint::{EndpointConfig, VeilidEndpoint, node_config}};
//! use subduction_core::handshake::audience::Audience;
//!
//! let config = node_config("subduction", "", &data_dir);
//! let endpoint = VeilidEndpoint::start(config, EndpointConfig::default(), None).await?;
//! // Stable across route changes and restarts:
//! println!("our address: {}", endpoint.wait_address_published().await.unwrap());
//!
//! let peer: VeilidAddress = peer_address_string.parse()?;
//! let result = client::connect_address(&endpoint, &peer, &signer, Audience::known(peer_id)).await?;
//! tokio::spawn(result.listener_task);
//! tokio::spawn(result.sender_task);
//! subduction.add_connection(result.authenticated).await?;
//! ```
//!
//! [Veilid]: https://veilid.com/

extern crate alloc;

pub mod address;
pub mod client;
pub mod data_dir;
pub mod endpoint;
pub mod error;
pub mod frame;
pub mod handshake;
pub mod session;
pub mod tasks;
pub mod transport;

mod reassembly;

#[cfg(feature = "server")]
pub mod server;

pub use address::VeilidAddress;
pub use reassembly::ReassemblyError;

/// Re-export of the `veilid-core` version this crate is built against.
pub use veilid_core;
