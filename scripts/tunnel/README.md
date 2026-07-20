# rqbit tunnel — quickstart

An encrypted SOCKS5 tunnel between a desktop **client** (behind NAT) and a
reachable **server** (a VPS). Traffic between them is a private BitTorrent v2
(BEP 52) carrier wrapped in MSE/PE, so on the wire it looks like an encrypted
BitTorrent peer connection; a second Noise layer authenticates and encrypts
every frame. The server egresses your traffic to the internet.

It is **one binary** — `rqbit`. Server and client differ only by flags; these
scripts wrap them so you don't have to remember any.

## 1. Server (on the VPS, Linux)

Put the `rqbit` binary next to these scripts, then:

```bash
./server-quickstart.sh
```

It generates keys once (no Python needed — `rqbit tunnel keygen`), starts the
server, and prints a **CLIENT SETUP** block: two key file contents
(`client.key`, `server.pub`) and the exact client command. Copy those to your
desktop.

Open the tunnel port on your VPS firewall (default `4242/tcp`).

## 2. Client (desktop, Linux or Windows)

Put the `rqbit` binary + the `client.key` and `server.pub` files (from step 1)
next to these scripts, then:

- **Linux:** `./client-run.sh <server-ip>:4242`
- **Windows:** double-click **`client-run.bat`** and paste `<server-ip>:4242`.

Then set your browser/app **SOCKS5** proxy to **`127.0.0.1:1080`** (for browsers,
enable "proxy DNS when using SOCKS v5" — the server resolves names). Test:

```bash
curl --socks5-hostname 127.0.0.1:1080 https://checkip.amazonaws.com   # → your VPS IP
```

## Notes

- **No pairing file.** The carrier identity is derived from the server key on
  both sides, so you only exchange `server.pub` (to the client) and `client.pub`
  (into the server's allowed-clients list — the quickstart does this for you).
- **Keys:** `*.key` are secret (mode 0600); only `*.pub` are safe to share.
  Regenerate anytime with `rqbit tunnel keygen --output-dir DIR`.
- **Multiple clients:** generate more client keys and add each `client.pub` line
  to `~/.rqbit-tunnel/keys/allowed-clients.txt` on the server, then restart it.
- **What this does NOT hide:** the *shape* of the traffic. It is one long-lived,
  high-throughput connection to one IP with no swarm/DHT — traffic analysis can
  still tell it apart from real BitTorrent. This blends at the protocol level,
  not the behavioural level.
