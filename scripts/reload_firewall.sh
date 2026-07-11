#!/usr/bin/env bash
set -euo pipefail

cd /opt/cbac-shield
sudo CBAC_CONFIG_DIR=/etc/cbac-shield CBAC_LOG_DIR=/var/log/cbac-shield .venv/bin/python - <<'PY'
from app.firewall_engine import FirewallEngine
FirewallEngine().apply_all()
print("Regles CBAC rechargees.")
PY
