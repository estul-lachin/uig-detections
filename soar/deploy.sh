#!/usr/bin/env bash
# Deploy soar/main.bicep: show what-if first, then deploy. Idempotent.
#   soar/deploy.sh [--yes]      --yes skips the confirmation (still prints what-if)
set -euo pipefail
cd "$(dirname "$0")"

RG=${SOAR_RG:-rg-uig-sentinel}
NAME=uig-soar
# High incidents are assigned to whoever deploys; the ID stays out of the repo.
OWNER=$(az ad signed-in-user show --query id -o tsv)

az deployment group what-if -g "$RG" -n "$NAME" -f main.bicep -p ownerObjectId="$OWNER" --no-pretty-print \
  --query 'changes[].{change:changeType, resource:resourceId}' -o table
if [ "${1:-}" != "--yes" ]; then
  read -r -p "Deploy to $RG? [y/N] " ok
  [ "$ok" = y ] || { echo "aborted"; exit 1; }
fi
az deployment group create -g "$RG" -n "$NAME" -f main.bicep -p ownerObjectId="$OWNER" \
  --query 'properties.outputs.{vault:vaultName.value, playbooks:playbooks.value[].name}' -o json
