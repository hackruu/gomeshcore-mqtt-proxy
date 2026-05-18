# gomeshcore-mqtt-proxy

A transparent MQTT multiplexing proxy for [MeshCore](https://meshcore.co.uk) nodes. Devices connect via plain TCP MQTT and their publishes are fanned out to any number of upstream brokers — plain TCP brokers and MeshCore community WS brokers — without any firmware changes.

This proxy was built specifically to enable [Waev.app](https://waev.app) community telemetry on MeshCore repeaters that cannot reach it on their own, for one of several reasons:

- **No WebSocket transport** — Waev.app requires MQTT over WSS (WebSocket + TLS), but many repeater firmwares only support plain TCP MQTT.
- **No preset for Waev.app** — older or custom firmware builds may not have community broker addresses baked in.
- **Not enough upstream slots** — resource-constrained hardware (limited RAM/flash) may only support a couple upstream MQTT connections in firmware, leaving no room for an additional community broker.

The proxy can be use transparently on the local network. Devices continue talking plain TCP MQTT to what they think is their regular broker; the proxy forwards every message to the original broker and to Waev.app simultaneously.

## How it works

```
MeshCore node (TCP :1883, meshcore:meshcore)
    │
    ▼
[gomeshcore-mqtt-proxy]
    │
    ├─► MQTT_BROKER_0  tcp://...   (plain TCP, MQTT v3.1.1)
    ├─► MQTT_BROKER_1  tcp://...   (optional, any number)
    │
    ├─► WS_BROKER_0    wss://...   (MQTT v5, Ed25519 JWT auth, per-node)
    └─► WS_BROKER_1    wss://...   (optional, any number)
```

- Devices authenticate with known credentials (as MeshCore firmware expects).
- The proxy intercepts DNS so devices reach it instead of the real broker. Their real IP is set explicitly via `MQTT_BROKER_0_ADDR` to bypass DNS.
- Each MeshCore node's public key is extracted from its MQTT topic (`meshcore/MOW/<PUBKEY>/…`). The proxy looks up the matching keypair and creates per-node WS connections with a fresh Ed25519 JWT on every connection.
- WS connections are created lazily on first publish from each node, then cached for the lifetime of the proxy.
- TCP upstream connections are also lazy — they dial on first message, not at startup.

## Requirements

- Docker + Docker Compose

## Quick start

```bash
cp .env.example .env
# edit .env — fill in broker addresses and node keypairs
docker compose up --build
```

## Configuration

All configuration is via environment variables (`.env` file).

### TCP brokers

Plain TCP MQTT upstreams (MQTT v3.1.1). Add as many as needed; scanning stops at the first missing `ADDR`.

| Variable | Description |
|---|---|
| `MQTT_BROKER_N_ADDR` | `host:port` of the broker (use real IP, not DNS hostname) |
| `MQTT_BROKER_N_USER` | Username (optional) |
| `MQTT_BROKER_N_PASS` | Password (optional) |

### WS brokers

WebSocket MQTT upstreams (MQTT v5 over WSS). Each node gets its own connection with a fresh JWT. Add as many as needed; scanning stops at the first missing `URL`.

| Variable | Description |
|---|---|
| `WS_BROKER_N_URL` | Full WSS URL, e.g. `wss://mqtt-a.waev.app:443` |

### Node keypairs

MeshCore Ed25519 keypairs. Add one group per node; scanning stops at the first index where both `PUBLIC` and `PRIVATE` are unset. Each keypair is validated at startup (public key is derived from the private scalar and compared).

| Variable | Description |
|---|---|
| `MESHCORE_KEY_N_PUBLIC` | 32-byte Ed25519 public key, hex-encoded (64 chars) |
| `MESHCORE_KEY_N_PRIVATE` | 64-byte expanded private key, hex-encoded (128 chars). This is `SHA-512(seed)` with clamping applied — **not** the raw seed. |
| `MESHCORE_KEY_N_EMAIL` | Optional owner email embedded in the JWT for community node claiming |

### JWT settings

| Variable | Default | Description |
|---|---|---|
| `TOKEN_LIFETIME` | `3300` | Token lifetime in seconds. Waev.app rejects tokens with `exp − iat > 3600s`. |
| `TOKEN_CLIENT` | `mqtt-proxy/1.0` | Value of the `client` claim in the JWT |

### Other

| Variable | Default | Description |
|---|---|---|
| `LOCAL_LISTEN` | `:1883` | Local TCP listener address |
| `LOCAL_MQTT_USER` | _(unset)_ | Username required from connecting devices. If unset, any credentials are accepted. |
| `LOCAL_MQTT_PASS` | _(unset)_ | Password required from connecting devices. |
| `LOG_LEVEL` | `info` | Log verbosity: `debug`, `info`, `warn`, `error` |

## Key format and security

### Why keypairs are required

Waev.app (and other MeshCore community brokers) authenticate clients using Ed25519 JWT tokens. The token is signed with the node's private key and carries the public key as the identity claim. The broker verifies the signature and grants access only if the public key is already known to the network — effectively proving that whoever is connecting controls the private key associated with that node.

This means the proxy must hold the private key of each node it forwards on behalf of. It signs a fresh JWT on every WS connection using that key, impersonating the node toward the upstream broker.

### Security warning

> **If a node's private key is leaked, anyone who obtains it can impersonate that node on the MeshCore network** — connecting to community brokers, publishing telemetry under its identity, and potentially claiming ownership. Treat `MESHCORE_KEY_N_PRIVATE` values with the same care as passwords. Do not commit them to version control, do not share them, and restrict access to the machine running this proxy.

### iptables redirect

To transparently intercept device traffic destined for the real broker:

```bash
# Redirect packets from device to real broker → proxy
iptables -t nat -A PREROUTING \
  -s <device_ip> -d <real_broker_ip> -p tcp --dport 1883 \
  -j DNAT --to-destination <proxy_ip>:1883

# Enable forwarding
echo 1 > /proc/sys/net/ipv4/ip_forward
```

## AI usage
Built with help of AI tooling.

## Dependencies

| Package | Purpose |
|---|---|
| `github.com/mochi-mqtt/server/v2` | Embedded local MQTT broker with hook API |
| `github.com/eclipse/paho.mqtt.golang` | TCP upstream client (MQTT v3.1.1) |
| `github.com/eclipse/paho.golang/autopaho` | WS upstream client with auto-reconnect (MQTT v5) |
| `filippo.io/edwards25519` | Low-level Ed25519 scalar operations for MeshCore JWT signing |
