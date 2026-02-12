# Multiplayer Server Architecture

## Overview

A small relay server enables secure shared terminal sessions across the internet using WireGuard tunnels. The existing LAN mode (direct SSH) remains as the default. Internet sessions are opt-in via `--online`.

The server's role is limited to brokering WireGuard connections. It never sees terminal traffic — that's encrypted end-to-end inside the WireGuard tunnel, then again inside SSH.

## Repo Structure

**multiplayer-cli** (the current implementation, extended)
- `multiplayer start` — LAN session (unchanged, direct SSH)
- `multiplayer start --online` — Internet session via WireGuard and the server
- `multiplayer join mp://...` — Join LAN session (unchanged)
- `multiplayer join https://server/s/{session_id}/{token}` — Join internet session

**multiplayer-server** (new, also written in Rust)
- Web API for session lifecycle
- WireGuard hub in a star topology (all peers route through the server)
- Runs on a host with a public IP

## Network Topology

Star topology with the server as the WireGuard hub:

```
 [Host CLI] ---- WireGuard tunnel ----> [Server (hub)] <---- WireGuard tunnel ---- [Guest CLI]
 10.100.x.1                              10.100.x.254                               10.100.x.2
```

All traffic between host and guests flows through the server's WireGuard interface. For terminal sessions the bandwidth is trivial, so this adds negligible latency while being simpler and more reliable than peer-to-peer NAT traversal.

## WireGuard Details

Both Linux and macOS use the same `wg-quick` CLI and config format:
- Linux: kernel WireGuard module (built-in since 5.6) + `wireguard-tools`
- macOS: userspace `wireguard-go` + `wireguard-tools` (via Homebrew)

Requires `sudo` on both platforms. The CLI prints a clear message before invoking it:
```
Setting up secure tunnel (requires sudo)...
```

Each session gets its own WireGuard subnet (e.g. `10.100.x.0/24`). The server manages interface lifecycle — bringing up interfaces when sessions start and tearing them down on stop or timeout.

## API

### Authentication

Hosts authenticate with the server using a long-lived API token. Guests do not need to authenticate — the join link is their credential.

- `multiplayer register` — Creates an account, saves a bearer token to `~/.config/multiplayer/`
- `multiplayer login` — Authenticates and saves the token
- The token is sent as `Authorization: Bearer <token>` on authenticated endpoints

### Endpoints

**POST /api/register**

Create a new user account. Returns a bearer token.

Request:
```json
{
  "username": "alice"
}
```

Response:
```json
{
  "token": "<bearer_token>"
}
```

**POST /api/sessions** (authenticated)

Host creates a new internet session. Includes the SSH keypair so the server can hand the private key to guests in the join response.

Request:
```json
{
  "session_name": "hungry-otter",
  "host_wg_public_key": "<base64>",
  "ssh_user": "alice",
  "ssh_private_key_b64": "<base64url_encoded_ssh_private_key>"
}
```

Response:
```json
{
  "session_id": "abc123",
  "join_url": "https://server/s/{session_id}/{token}",
  "wg_config": {
    "host_address": "10.100.1.1/24",
    "server_public_key": "<base64>",
    "server_endpoint": "server-ip:51820",
    "allowed_ips": "10.100.1.0/24"
  }
}
```

**POST /api/sessions/:id/join**

Guest joins a session via the secret token.

Request:
```json
{
  "token": "k7Xp2mQ9vR4wL1nY8jF3hT6bA0cG5dE_zKoN-sWiUf",
  "guest_wg_public_key": "<base64>"
}
```

Response:
```json
{
  "wg_config": {
    "guest_address": "10.100.1.2/24",
    "server_public_key": "<base64>",
    "server_endpoint": "server-ip:51820",
    "allowed_ips": "10.100.1.0/24"
  },
  "ssh_token": "mp://user@10.100.1.1:22/hungry-otter#<base64_private_key>"
}
```

**POST /api/sessions/:id/heartbeat** (authenticated)

Host sends every 30 seconds to keep the session alive.

**DELETE /api/sessions/:id** (authenticated)

Host explicitly stops the session.

## Session Lifecycle

### Host starts an internet session

1. CLI generates a WireGuard keypair locally (private key never leaves the host)
2. CLI generates an SSH keypair locally
3. CLI calls `POST /api/sessions` with the host's WG public key, SSH user, and SSH private key (base64)
4. Server allocates a WireGuard subnet, assigns the host `10.100.x.1`, server gets `10.100.x.254`
5. Server configures its WG interface and adds the host as a peer
6. Server generates a cryptographically secure join token (32 bytes from CSPRNG, base64url-encoded) and stores a hash of it (never the raw token)
7. CLI receives WG config and join URL, brings up `sudo wg-quick up /tmp/multiplayer-{session}-wg.conf`
8. CLI installs the SSH authorized_key and creates the tmux session (same as LAN mode)
9. CLI prints the join URL and spawns a heartbeat daemon (sends heartbeats every 30 seconds)

### Guest joins

1. CLI extracts the token from the join URL
2. CLI generates a WireGuard keypair locally
3. CLI calls `POST /api/sessions/:id/join` with the token and guest's WG public key
4. Server verifies the token hash, adds the guest as a WG peer, assigns `10.100.x.N`
5. CLI receives WG config and SSH token, brings up its WG interface
6. CLI SSHs to the host through the WireGuard tunnel — from here it's identical to LAN mode

### Session teardown

Explicit stop:
1. Host runs `multiplayer stop`
2. CLI calls `DELETE /api/sessions/:id`
3. CLI runs `sudo wg-quick down`, cleans up tmux + SSH keys (same as LAN mode)
4. Server tears down WG interfaces and removes all peers

Timeout (crash recovery):
1. Server expects heartbeats every 30 seconds
2. After 2 missed heartbeats (60 seconds of silence), server tears down the session
3. Server removes WG interfaces and peer configs for the timed-out session

## Join Link Security

The join link is the sole credential for guests — treat it as a bearer token.

- Token is 32 bytes from a CSPRNG, base64url-encoded (256 bits of entropy)
- Server stores only a hash of the token, not the raw value
- Rate limiting on the join endpoint: 10 failed attempts per IP per minute (429 response)
- Links look like: `https://server/s/{session_id}/{token}`

## Security Summary

- WireGuard private keys are generated locally on each client and never sent to the server
- The server only sees WireGuard public keys and coordinates peer configs
- SSH private keys are uploaded to the server so it can hand them to guests. This is acceptable since the keys are temporary, scoped to one tmux session with ForceCommand, and the server already brokers the connection
- Terminal traffic is encrypted twice: once by WireGuard, once by SSH
- SSH keys are temporary (per-session) with ForceCommand restrictions (same as LAN mode)
- Join tokens have 256 bits of entropy, stored as hashes, protected by rate limiting
- Sessions auto-expire on missed heartbeats — no orphaned tunnels
