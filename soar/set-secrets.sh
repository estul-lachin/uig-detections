#!/usr/bin/env bash
# Store the playbooks' secrets in the SOAR Key Vault. Values are typed (hidden) or piped on stdin,
# never passed as arguments, so they stay out of shell history and the process list.
#
#   soar/set-secrets.sh                         asks for all three
#   soar/set-secrets.sh abuseipdb-key < file    sets one from stdin
set -euo pipefail

RG=${SOAR_RG:-rg-uig-sentinel}
VAULT=$(az deployment group show -g "$RG" -n uig-soar --query properties.outputs.vaultName.value -o tsv)
NAMES=(abuseipdb-key telegram-bot-token telegram-chat-id)

put() { # name value
  local f rc=0
  f=$(umask 077; mktemp)
  printf '%s' "$2" > "$f"
  az keyvault secret set --vault-name "$VAULT" -n "$1" --file "$f" --encoding utf-8 -o none || rc=$?
  rm -f "$f"
  [ "$rc" -eq 0 ] && echo "set $1"
  return "$rc"
}

if [ $# -eq 1 ]; then
  IFS= read -r value || [ -n "$value" ]
  put "$1" "$value"
  exit
fi
for n in "${NAMES[@]}"; do
  IFS= read -r -s -p "$n (empty to skip): " value
  echo
  [ -n "$value" ] && put "$n" "$value"
done
