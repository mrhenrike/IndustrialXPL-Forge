#!/usr/bin/env bash
# Restaura vendor malwares/ics-tools a partir do company-backup do superprojeto (repo privado).
set -euo pipefail

FORGE="$(cd "$(dirname "$0")/.." && pwd)"
SUPER="$(cd "$FORGE/../../.." && pwd)"
SCRIPT="$SUPER/company-backup/restore-ixf-vendor.sh"

if [ ! -x "$SCRIPT" ]; then
  echo "Execute a partir do clone de Projetos-SafeLabs (privado)."
  echo "Esperado: $SCRIPT"
  exit 1
fi
exec "$SCRIPT"
