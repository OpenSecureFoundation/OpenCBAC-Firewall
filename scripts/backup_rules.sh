#!/usr/bin/env bash
set -euo pipefail

CONFIG_DIR="${CBAC_CONFIG_DIR:-/etc/cbac-shield}"
mkdir -p "$CONFIG_DIR/backups"
cp "$CONFIG_DIR/rules.json" "$CONFIG_DIR/backups/rules-$(date +%F-%H-%M-%S).json"
