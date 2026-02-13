#!/usr/bin/env bash
set -euo pipefail

# ── Config ───────────────────────────────────────────────────────────────────
PROJECT=""
ZONE="us-central1-a"
MACHINE_TYPE="e2-small"
VM_NAME="multiplayer-server"
DISK_SIZE="20GB"
IMAGE_FAMILY="debian-12"
IMAGE_PROJECT="debian-cloud"
DOMAIN=""
REGISTER_SECRET=""
# ─────────────────────────────────────────────────────────────────────────────

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

usage() {
    echo "Usage: $0 {create|deploy|setup-tls <domain>}"
    exit 1
}

require_project() {
    if [[ -z "$PROJECT" ]]; then
        echo "Error: PROJECT is not set. Edit the config section at the top of this script."
        exit 1
    fi
}

get_external_ip() {
    gcloud compute instances describe "$VM_NAME" \
        --project="$PROJECT" \
        --zone="$ZONE" \
        --format='get(networkInterfaces[0].accessConfigs[0].natIP)'
}

cmd_create() {
    require_project

    echo "==> Creating VM '$VM_NAME' in project '$PROJECT'..."
    gcloud compute instances create "$VM_NAME" \
        --project="$PROJECT" \
        --zone="$ZONE" \
        --machine-type="$MACHINE_TYPE" \
        --image-family="$IMAGE_FAMILY" \
        --image-project="$IMAGE_PROJECT" \
        --boot-disk-size="$DISK_SIZE" \
        --tags=multiplayer-server \
        --metadata-from-file=user-data="$SCRIPT_DIR/cloud-init.yaml"

    echo "==> Creating firewall rules..."
    gcloud compute firewall-rules create multiplayer-allow-http-https \
        --project="$PROJECT" \
        --allow=tcp:80,tcp:443 \
        --target-tags=multiplayer-server \
        --description="Allow HTTP and HTTPS to multiplayer-server" \
        2>/dev/null || echo "    (firewall rule multiplayer-allow-http-https already exists)"

    gcloud compute firewall-rules create multiplayer-allow-wireguard \
        --project="$PROJECT" \
        --allow=udp:51820-51999 \
        --target-tags=multiplayer-server \
        --description="Allow WireGuard UDP to multiplayer-server" \
        2>/dev/null || echo "    (firewall rule multiplayer-allow-wireguard already exists)"

    EXTERNAL_IP=$(get_external_ip)
    echo ""
    echo "==> VM created. External IP: $EXTERNAL_IP"
    echo ""
    echo "Wait ~2 minutes for cloud-init to finish, then run:"
    echo "  bash deploy/deploy.sh deploy"
}

cmd_deploy() {
    require_project

    echo "==> Building multiplayer-server (static musl binary)..."
    cargo build --release --target=x86_64-unknown-linux-musl --package=multiplayer-server \
        --manifest-path="$REPO_DIR/Cargo.toml"

    BINARY="$REPO_DIR/target/x86_64-unknown-linux-musl/release/multiplayer-server"
    if [[ ! -f "$BINARY" ]]; then
        echo "Error: Binary not found at $BINARY"
        exit 1
    fi

    EXTERNAL_IP=$(get_external_ip)
    echo "==> VM external IP: $EXTERNAL_IP"

    echo "==> Uploading binary..."
    gcloud compute scp "$BINARY" "$VM_NAME:/tmp/multiplayer-server" \
        --project="$PROJECT" \
        --zone="$ZONE"

    echo "==> Installing binary and configuring service..."

    if [[ -n "$DOMAIN" ]]; then
        SERVER_URL="https://$DOMAIN"
    else
        SERVER_URL="http://$EXTERNAL_IP"
    fi

    ENV_CONTENTS="MULTIPLAYER_BIND=0.0.0.0:8080
MULTIPLAYER_SERVER_URL=$SERVER_URL
MULTIPLAYER_WG_ENDPOINT=$EXTERNAL_IP
MULTIPLAYER_WG_PORT_START=51820
MULTIPLAYER_DB_PATH=/var/lib/multiplayer/multiplayer.db"

    if [[ -n "$REGISTER_SECRET" ]]; then
        ENV_CONTENTS="$ENV_CONTENTS
MULTIPLAYER_REGISTER_SECRET=$REGISTER_SECRET"
    fi

    # Build remote commands
    REMOTE_CMDS="
sudo mv /tmp/multiplayer-server /usr/local/bin/multiplayer-server
sudo chmod +x /usr/local/bin/multiplayer-server
echo '$ENV_CONTENTS' | sudo tee /etc/multiplayer-server.env > /dev/null
sudo chmod 600 /etc/multiplayer-server.env
"

    if [[ -n "$DOMAIN" ]]; then
        REMOTE_CMDS="$REMOTE_CMDS
sudo sed -i 's/server_name _;/server_name $DOMAIN;/' /etc/nginx/sites-available/multiplayer
sudo systemctl reload nginx
"
    fi

    REMOTE_CMDS="$REMOTE_CMDS
sudo systemctl daemon-reload
sudo systemctl restart multiplayer-server
"

    gcloud compute ssh "$VM_NAME" \
        --project="$PROJECT" \
        --zone="$ZONE" \
        --command="$REMOTE_CMDS"

    echo ""
    echo "==> Deployed successfully!"
    echo "    Service URL: $SERVER_URL"
    echo "    Check status: gcloud compute ssh $VM_NAME --zone=$ZONE --project=$PROJECT --command='sudo systemctl status multiplayer-server'"
}

cmd_setup_tls() {
    local domain="$1"
    require_project

    echo "==> Setting up TLS for $domain..."
    gcloud compute ssh "$VM_NAME" \
        --project="$PROJECT" \
        --zone="$ZONE" \
        --command="sudo certbot --nginx -d $domain --non-interactive --agree-tos --register-unsafely-without-email --redirect"

    echo ""
    echo "==> TLS configured for $domain"
    echo "    Verify: curl https://$domain/api/sessions"
}

# ── Main ─────────────────────────────────────────────────────────────────────

if [[ $# -lt 1 ]]; then
    usage
fi

case "$1" in
    create)
        cmd_create
        ;;
    deploy)
        cmd_deploy
        ;;
    setup-tls)
        if [[ $# -lt 2 ]]; then
            echo "Error: setup-tls requires a domain argument"
            echo "Usage: $0 setup-tls <domain>"
            exit 1
        fi
        cmd_setup_tls "$2"
        ;;
    *)
        usage
        ;;
esac
