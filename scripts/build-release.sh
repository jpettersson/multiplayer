#!/usr/bin/env bash
set -euo pipefail

LINUX_TARGETS=(
  "x86_64-unknown-linux-gnu:multiplayer-linux-amd64"
  "aarch64-unknown-linux-gnu:multiplayer-linux-arm64"
)

MACOS_TARGETS=(
  "x86_64-apple-darwin:multiplayer-macos-amd64"
  "aarch64-apple-darwin:multiplayer-macos-arm64"
)

usage() {
  echo "Usage: $0 <linux|macos>"
  exit 1
}

[[ $# -eq 1 ]] || usage

case "$1" in
  linux) TARGETS=("${LINUX_TARGETS[@]}") ;;
  macos) TARGETS=("${MACOS_TARGETS[@]}") ;;
  *) usage ;;
esac

DIST_DIR="dist"

mkdir -p "$DIST_DIR"

for entry in "${TARGETS[@]}"; do
  target="${entry%%:*}"
  archive_name="${entry##*:}"

  echo "==> Building for $target"
  cargo build --release --target "$target"

  staging=$(mktemp -d)
  cp "target/$target/release/multiplayer" "$staging/multiplayer"

  tar -czf "$DIST_DIR/$archive_name.tar.gz" -C "$staging" multiplayer
  rm -rf "$staging"

  echo "    Created $DIST_DIR/$archive_name.tar.gz"
done

echo "==> Done. Archives in $DIST_DIR/:"
ls -lh "$DIST_DIR"
