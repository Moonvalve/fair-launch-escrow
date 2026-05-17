#!/usr/bin/env bash
set -euo pipefail

cluster="${1:-}"

case "$cluster" in
  devnet|mainnet)
    ;;
  *)
    echo "Usage: $0 devnet|mainnet" >&2
    exit 2
    ;;
esac

cargo build-sbf --features "$cluster"

src="target/deploy/fair_launch_escrow.so"
dst="target/deploy/fair_launch_escrow_${cluster}.so"

cp "$src" "$dst"

echo "Built: $dst"
wc -c "$dst"
