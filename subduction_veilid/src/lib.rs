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
//! See the crate README for the session wire protocol.
//!
//! # Example
//!
//! ```ignore
//! use subduction_veilid::{client, endpoint::{EndpointConfig, VeilidEndpoint, node_config}};
//! use subduction_core::handshake::audience::Audience;
//!
//! let config = node_config("subduction", "", &data_dir);
//! let endpoint = VeilidEndpoint::start(config, EndpointConfig::default(), None).await?;
//! println!("our route blob: {:?}", endpoint.route_blob());
//!
//! let result = client::connect(&endpoint, &peer_route_blob, &signer, Audience::known(peer_id)).await?;
//! tokio::spawn(result.listener_task);
//! tokio::spawn(result.sender_task);
//! subduction.add_connection(result.authenticated).await?;
//! ```
//!
//! [Veilid]: https://veilid.com/

extern crate alloc;

pub mod client;
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

pub use reassembly::ReassemblyError;

/// Re-export of the `veilid-core` version this crate is built against.
pub use veilid_core;
