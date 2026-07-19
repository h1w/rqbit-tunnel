# librqbit

A fully featured, easy to use torrent downloading library used as a backbone of [rqbit](https://github.com/ikatson/rqbit).

## Basic example
See [examples on GitHub](https://github.com/ikatson/rqbit/tree/main/crates/librqbit/examples).

## Tunnel support

`librqbit` powers rqbit's encrypted TCP tunnel mode.  The tunnel does not
use the DHT or trackers for the carrier swarm; it operates over a dedicated
peer-wire session between client and server with Noise encryption.
The server allowlists client public keys for access control.

```rust
use librqbit::TunnelOptions;

// Client side — connect to a VPS relay
let opts = TunnelOptions::client(
    "vps.example.com:4242".parse().unwrap(),
    client_key,         // 32-byte private key
    server_pubkey,      // 32-byte server public key
    pairing_bytes,      // JSON pairing bundle
    socks_listen_addr,  // local SOCKS5 bind address
);

// Server side — accept authenticated client connections
let opts = TunnelOptions::server(
    peer_listen_addr,
    server_key,         // 32-byte private key
    allowed_keys,       // allowed client public keys
    carrier_root,       // carrier torrent storage
);
```

See the main [rqbit README](https://github.com/ikatson/rqbit#tunnel-mode)
for CLI deployment examples.

## Documentation
[librqbit at docs.rs](https://docs.rs/librqbit/latest/librqbit/)