# Multiplayer

Huddle together around Claude code or any other terminal program and build great things together!

Multiplayer enables instant shared terminal sessions on LAN — or over the internet using a GCP VM as a relay. One command to share your tmux session, one command to join from another machine.

## Prerequisites

System dependencies (must be installed on both host and joiner machines):

- `tmux`
- `ssh` / `sshd` (sshd must be running on the host machine)
- `ssh-keygen`
- `gcloud` CLI (only for GCP relay mode — [install guide](https://cloud.google.com/sdk/docs/install))

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

## GCP Relay Mode

Share sessions over the internet by relaying traffic through a GCP VM.

### GCP Prerequisites

- A GCP VM instance with [OS Login](https://cloud.google.com/compute/docs/instances/managing-instance-access) enabled
- `gcloud` CLI installed and authenticated on both host and participant machines
- Both users need SSH access to the relay VM (via `gcloud compute ssh`)

### Start a session over GCP

```bash
multiplayer start --gcp <vm-instance-name>
```

Optional flags:

- `--zone <zone>` — GCP zone (defaults to your `gcloud` config value)
- `--project <project>` — GCP project (defaults to your `gcloud` config value)
- `--name <session-name>` — custom session name

This establishes a reverse SSH tunnel from the GCP VM back to your machine, then prints a `mp-gcp://` join token.

### Join a GCP session

Copy the `mp-gcp://` token from the host and run:

```bash
multiplayer join "mp-gcp://user@relay-vm:2291/eager-falcon?zone=us-central1-a&project=my-project#AAAC3Nza..."
```

This opens a local forward through the same GCP VM and connects to the host's tmux session.

### Stop a GCP session

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

### LAN mode

1. `start` generates a temporary ed25519 SSH keypair
2. The public key is added to `~/.ssh/authorized_keys` with `ForceCommand="tmux attach -t <session>"` — this restricts the key to only attaching to the specific tmux session
3. A join token is printed containing the host IP, SSH port, session name, and base64-encoded private key
4. `join` decodes everything from the token, writes the key to a temp file, then SSHs in — the ForceCommand automatically attaches to the tmux session
5. `stop` cleans up everything: kills tmux, removes the authorized_keys entry, and deletes temp key files

### GCP relay mode

1. Steps 1–2 are the same (keypair + authorized_keys)
2. The host runs `gcloud compute ssh` to establish a **reverse tunnel** (`-R <port>:localhost:22`) from the GCP VM back to the host's SSH port (the relay port is randomly chosen from 2222–2322 so multiple sessions can share one VM)
3. A `mp-gcp://` token is printed containing the VM name, relay port, session name, zone/project, and the base64-encoded private key
4. The joiner runs `gcloud compute ssh` to establish a **local forward** (`-L <local-port>:localhost:<port>`) through the same GCP VM
5. The joiner SSHs to `localhost:<local-port>`, which travels through the GCP VM's relay port and into the host's SSH server — the ForceCommand attaches to the tmux session
6. `stop` cleans up everything including killing the reverse tunnel process

## Temporary files

All session state lives in `/tmp`:

| File | Purpose |
|------|---------|
| `/tmp/multiplayer-<name>-key` | Temporary SSH private key |
| `/tmp/multiplayer-<name>-key.pub` | Temporary SSH public key |
| `/tmp/multiplayer-<name>-info` | Session metadata (name, host IP) |
| `/tmp/multiplayer-<name>-tunnel-pid` | Reverse tunnel process PID (GCP mode only) |

All are cleaned up on `stop`.
