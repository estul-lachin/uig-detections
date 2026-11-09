#!/usr/bin/env bash
# Role assignments for the SOAR deployment. Run after soar/deploy.sh, as a user who can assign roles
# (Owner or User Access Administrator). Safe to run again: existing assignments are kept.
#
#   each playbook's managed identity:
#     Microsoft Sentinel Responder   on the workspace  read incidents, add comments and tags, change status
#     Log Analytics Reader           on the workspace  query Cowrie_CL for the IP's activity
#     Key Vault Secrets User         on the vault      read the API keys
#   Azure Security Insights (Sentinel's own app):
#     Microsoft Sentinel Automation Contributor on the resource group, so automation rules can run playbooks
#   you (the signed-in user):
#     Key Vault Secrets Officer      on the vault      set the secrets with soar/set-secrets.sh
set -euo pipefail

RG=${SOAR_RG:-rg-uig-sentinel}
NAME=uig-soar
SENTINEL_APP=98785600-1bb7-4fb9-b9fa-19afe2c8a360 # Azure Security Insights, same ID in every tenant

out() { az deployment group show -g "$RG" -n "$NAME" --query "properties.outputs.$1.value" -o tsv; }
grant() { # principal-id principal-type role scope
  if [ -n "$(az role assignment list --assignee "$1" --role "$3" --scope "$4" --query '[0].id' -o tsv)" ]; then
    echo "  have  $3"
  else
    az role assignment create --assignee-object-id "$1" --assignee-principal-type "$2" \
      --role "$3" --scope "$4" -o none
    echo "  added $3"
  fi
}

WS=$(out workspaceId)
VAULT=$(out vaultId)
RG_ID=$(az group show -n "$RG" --query id -o tsv)

az deployment group show -g "$RG" -n "$NAME" \
  --query 'properties.outputs.playbooks.value[].[name, principalId]' -o tsv |
while read -r name pid; do
  echo "$name"
  grant "$pid" ServicePrincipal "Microsoft Sentinel Responder" "$WS"
  grant "$pid" ServicePrincipal "Log Analytics Reader" "$WS"
  grant "$pid" ServicePrincipal "Key Vault Secrets User" "$VAULT"
done

echo "Azure Security Insights"
grant "$(az ad sp show --id "$SENTINEL_APP" --query id -o tsv)" ServicePrincipal \
  "Microsoft Sentinel Automation Contributor" "$RG_ID"

echo "you"
grant "$(az ad signed-in-user show --query id -o tsv)" User "Key Vault Secrets Officer" "$VAULT"

echo "Done. New assignments can take a few minutes to apply."
