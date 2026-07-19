// tunnel subsystem — still scaffolding; suppress dead-code and related lints
// until full integration lands.
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
#![allow(clippy::useless_borrows_in_formatting)]
#![allow(clippy::while_let_loop)]

pub(crate) mod carrier;
pub(crate) mod carrier_peer;
pub(crate) mod client;
pub(crate) mod crypto;
pub(crate) mod egress;
pub(crate) mod frame;
pub mod options;
pub(crate) mod peer_wire_crypto;
pub(crate) mod server;
pub mod service;
pub(crate) mod socks;
pub(crate) mod socks_udp;
#[cfg(test)]
pub(crate) mod test_capture;
