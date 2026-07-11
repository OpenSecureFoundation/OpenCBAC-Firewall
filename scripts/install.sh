#!/usr/bin/env bash
set -euo pipefail

APP_DIR="/opt/cbac-shield"
CONFIG_DIR="/etc/cbac-shield"
LOG_DIR="/var/log/cbac-shield"

sudo mkdir -p "$APP_DIR" "$CONFIG_DIR/backups" "$LOG_DIR"
sudo cp -r app requirements.txt "$APP_DIR/"
sudo cp -n config/*.json "$CONFIG_DIR/"
sudo cp config/cbac.conf "$CONFIG_DIR/cbac.conf"
sudo python3 -m venv "$APP_DIR/.venv"
sudo "$APP_DIR/.venv/bin/python" -m pip install -r "$APP_DIR/requirements.txt"
sudo cp scripts/cbacctl /usr/local/bin/cbacctl
sudo chmod +x /usr/local/bin/cbacctl
sudo cp systemd/cbac-shield.service /etc/systemd/system/cbac-shield.service
sudo systemctl daemon-reload

echo "Installation terminee. Demarrage: sudo systemctl enable --now cbac-shield"
