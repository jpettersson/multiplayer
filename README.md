# Multiplayer

Huddle togheter around Claude code or any other terminal program and build great things together!

Multiplayer enables instant shared terminal sessions on LAN. One command to share your tmux session, one command to join from another machine.

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

To choose a name:

```bash
multiplayer start --name my-feature
```

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

Shows session name, host IP, and participant count. Optionally pass a session name:

```bash
multiplayer status my-feature
```

### Stop a session

```bash
multiplayer stop
```

Optionally pass a session name:

```bash
multiplayer stop my-feature
```

This cleans up everything: tmux session, temp SSH keys, and the authorized_keys entry.

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
cargo run -- start --name test-session
# Prints token and returns to shell

cargo run -- join
# Attaches to the tmux session (Ctrl+B, D to detach)
```

**Terminal 2 — join using the token:**

```bash
cargo run -- join mp://127.0.0.1:22/test-session#<key-from-terminal-1>
```

Copy the full `mp://...` token from terminal 1. You should land in the same tmux session.

**Terminal 3 — try the other commands:**

```bash
# Check status
cargo run -- status

# Stop the session
cargo run -- stop test-session
```

## How it works

1. `start` generates a temporary ed25519 SSH keypair
2. The public key is added to `~/.ssh/authorized_keys` with `ForceCommand="tmux attach -t <session>"` — this restricts the key to only attaching to the specific tmux session
3. A join token is printed containing the host IP, SSH port, session name, and base64-encoded private key
4. `join` decodes everything from the token, writes the key to a temp file, then SSHs in — the ForceCommand automatically attaches to the tmux session
5. `stop` cleans up everything: kills tmux, removes the authorized_keys entry, and deletes temp key files

## Temporary files

All session state lives in `/tmp`:

| File | Purpose |
|------|---------|
| `/tmp/multiplayer-<name>-key` | Temporary SSH private key |
| `/tmp/multiplayer-<name>-key.pub` | Temporary SSH public key |
| `/tmp/multiplayer-<name>-info` | Session metadata (name, host IP) |

All are cleaned up on `stop`.
