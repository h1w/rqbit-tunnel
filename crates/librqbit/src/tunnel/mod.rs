// tunnel subsystem — still scaffolding; suppress dead-code and related lints
// until full integration lands.
//
// TODO(plan-C+): narrow once remaining scaffolding is wired. The carrier
// masquerade modules (carrier, carrier_wire, carrier_peer, carrier_identity,
// carrier_chunk) do NOT depend on this blanket for their own items (verified
// by `cargo check --all-targets` with the blanket removed: zero warnings from
// those five files — the few genuine items they did have are now individually
// `#[allow(dead_code)]`/`#[cfg(test)]`-annotated in carrier_peer.rs and
// carrier_wire.rs). Removing the blanket crate-wide currently surfaces ~29
// pre-existing dead-code/unused-variable items spread across 10 unrelated
// files (client.rs, client_mux.rs, client_pool.rs, config.rs, egress.rs,
// server.rs, socks.rs, socks_udp.rs, peer_wire_crypto.rs, test_capture.rs) —
// e.g. unused `EgressPolicy::public_internet_only`/`EgressTcp`/
// `EgressUdpAssociation`, `TunnelServer::peer_count`/`is_admitted`,
// `CarrierPool::carrier_count`/`live_count`, `ClientMux`'s `rtt`/`controller`/
// `paced`/`pacing_rate` fields (production-dead; read only by `#[cfg(test)]`
// accessors), `config::MIN_WINDOW`/`MAX_WINDOW`, etc. That is a large,
// orthogonal cleanup outside this task's scope (E2E capture gate + minimal
// piece cover) — narrow it in a follow-up once those call sites are wired up
// for real use rather than papering over each with a targeted allow.
#![allow(dead_code)]
#![allow(unused_variables)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::collapsible_if)]
#![allow(clippy::derivable_impls)]
#![allow(clippy::explicit_auto_deref)]
#![allow(clippy::field_reassign_with_default)]
#![allow(clippy::let_and_return)]
#![allow(clippy::needless_range_loop)]
#![allow(clippy::needless_return)]
#![allow(clippy::never_loop)]
#![allow(clippy::while_let_loop)]

pub(crate) mod carrier;
pub(crate) mod carrier_chunk;
pub(crate) mod carrier_identity;
pub(crate) mod carrier_peer;
pub(crate) mod carrier_wire;
pub(crate) mod client;
pub(crate) mod client_mux;
pub(crate) mod client_pool;
pub(crate) mod client_supervisor;
pub(crate) mod config;
pub(crate) mod crypto;
pub(crate) mod egress;
pub(crate) mod flow;
pub(crate) mod frame;
pub mod options;
pub(crate) mod peer_wire_crypto;
pub(crate) mod relay;
pub(crate) mod server;
pub mod service;
pub(crate) mod socks;
pub(crate) mod socks_udp;
#[cfg(test)]
pub(crate) mod test_capture;
