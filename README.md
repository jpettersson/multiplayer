# Multiplayer

Huddle together around Claude code or any other terminal program and build great things together!

Multiplayer enables instant shared terminal sessions on LAN — or over the internet using any SSH-accessible server as a relay. One command to share your tmux session, one command to join from another machine.

## Prerequisites

System dependencies (must be installed on both host and joiner machines):

- `tmux`
- `ssh` / `sshd` (sshd must be running on the host machine)
- `ssh-keygen`

On Arch Linux:

```bash
pacman -S tmux openssh
systemctl enable --now sshd
```

On Debian/Ubuntu:

```bash
apt install tmux openssh-server
```

On macOS:

```bash
brew install tmux
```

Then enable Remote Login (sshd) via System Settings > General > Sharing > Remote Login.

## Usage

### Start a session

```bash
multiplayer start
```

This generates a random session name (e.g. `hungry-otter`), creates a tmux session, prints a join token, then exits.

### Join a session

As the host (attach to your local session):

```bash
multiplayer join
```

As a remote user (copy the `mp://` token from the host):

```bash
multiplayer join mp://192.168.1.42:22/hungry-otter#AAAC3NzaC1lZDI1NTE5...
```

### Check session status

```bash
multiplayer status
```

Shows session name, host IP, and participant count.

### Stop a session

```bash
multiplayer stop
```

This cleans up everything: tmux session, temp SSH keys, and the authorized_keys entry.

## SSH Relay Mode

Share sessions over the internet by relaying traffic through any SSH-accessible server.

### Config setup

Create `~/.multiplayer/config.yml` with your relay host entries:

```yaml
hosts:
  default:
    host: relay.example.com
    user: relay_user
    key: relay_key
```

- **host** — hostname or IP of the relay server
- **user** — SSH user on the relay server
- **key** — path to the SSH private key for the relay server. Relative paths resolve to `~/.multiplayer/` (e.g. `relay_key` becomes `~/.multiplayer/relay_key`). Absolute paths are used as-is.

The key file must have `0600` permissions:

```bash
chmod 600 ~/.multiplayer/relay_key
```

You can define multiple entries (e.g. `default`, `work`, `eu-relay`) and select one at start time.

### Start a session over SSH relay

```bash
multiplayer start --ssh
```

This uses the `default` entry from your config. To use a different entry:

```bash
multiplayer start --ssh work
```

This establishes a reverse SSH tunnel from the relay server back to your machine, then prints a `mp-ssh://` join token.

### Join an SSH relay session

Copy the `mp-ssh://` token from the host and run:

```bash
multiplayer join "mp-ssh://user@relay.example.com:2291/eager-falcon?relay_user=relay_user#AAAC3Nza..."
```

The joiner's machine looks up the relay host in their own `~/.multiplayer/config.yml` to find the SSH key for the relay, then opens a local forward through the relay and connects to the host's tmux session.

### Stop an SSH relay session

```bash
multiplayer stop
```

Same command as LAN mode — cleans up the tmux session, SSH keys, authorized_keys entry, and the reverse tunnel.

## Local dev

### Build

```bash
cd projects/multiplayer
cargo build
```

For an optimized release build:

```bash
cargo build --release
```

The binary is at `target/debug/multiplayer` (or `target/release/multiplayer`).

### Testing on a single machine

You can test the full flow locally without a second machine.

**Terminal 1 — start a session:**

```bash
cargo run -- start
# Prints token and returns to shell

cargo run -- join
# Attaches to the tmux session (Ctrl+B, D to detach)
```

**Terminal 2 — join using the token:**

```bash
cargo run -- join "mp://127.0.0.1:22/brave-otter#<key-from-terminal-1>"
```

Copy the full `mp://...` token from terminal 1. You should land in the same tmux session.

**Terminal 3 — try the other commands:**

```bash
# Check status
cargo run -- status

# Stop the session
cargo run -- stop
```

## How it works

### LAN mode

1. `start` generates a temporary ed25519 SSH keypair
2. The public key is added to `~/.ssh/authorized_keys` with `ForceCommand="tmux attach -t <session>"` — this restricts the key to only attaching to the specific tmux session
3. A join token is printed containing the host IP, SSH port, session name, and base64-encoded private key
4. `join` decodes everything from the token, writes the key to a temp file, then SSHs in — the ForceCommand automatically attaches to the tmux session
5. `stop` cleans up everything: kills tmux, removes the authorized_keys entry, and deletes temp key files

### SSH relay mode

1. Steps 1–2 are the same (keypair + authorized_keys)
2. The host runs `ssh -R <port>:localhost:22` to establish a **reverse tunnel** from the relay server back to the host's SSH port, using the key from `~/.multiplayer/config.yml` (the relay port is randomly chosen from 2222–2322 so multiple sessions can share one server)
3. A `mp-ssh://` token is printed containing the relay host, relay port, session name, relay user, and the base64-encoded session private key
4. The joiner looks up the relay host in their own `~/.multiplayer/config.yml` to find the SSH key for the relay, then runs `ssh -L <local-port>:localhost:<port>` to establish a **local forward** through the same relay server
5. The joiner SSHs to `localhost:<local-port>`, which travels through the relay server's port and into the host's SSH server — the ForceCommand attaches to the tmux session
6. `stop` cleans up everything including killing the reverse tunnel process

## Temporary files

All session state lives in `/tmp`:

| File | Purpose |
|------|---------|
| `/tmp/multiplayer-<name>-key` | Temporary SSH private key |
| `/tmp/multiplayer-<name>-key.pub` | Temporary SSH public key |
| `/tmp/multiplayer-<name>-info` | Session metadata (name, host IP) |
| `/tmp/multiplayer-<name>-tunnel-pid` | Reverse tunnel process PID (relay mode only) |

All are cleaned up on `stop`.
