#!/usr/bin/env bash
# Vendor malwares/ics-tools ship with the public IXF repository (v1.0.45+).
# This script re-syncs from company-backup when working from Projetos-SafeLabs monorepo.
set -euo pipefail

FORGE="$(cd "$(dirname "$0")/.." && pwd)"
VENDOR="$FORGE/industrialxpl/resources/vendor"
SUPER="$(cd "$FORGE/../../.." && pwd)"
BACKUP="$SUPER/company-backup/incorporated-vendor"

if [ -d "$VENDOR/submodules__malwares__mirai-iot-botnet" ]; then
  echo "Vendor corpus already present in $VENDOR (git clone is authoritative)."
  exit 0
fi

if [ -x "$SUPER/company-backup/restore-ixf-vendor.sh" ]; then
  echo "Restoring from company-backup (monorepo layout)..."
  exec "$SUPER/company-backup/restore-ixf-vendor.sh"
fi

echo "Clone https://github.com/mrhenrike/IndustrialXPL-Forge for the full public corpus."
exit 1
