#!/usr/bin/env bash
# Let this repo's CI read the Sentinel workspace for the site's SOAR numbers (tools/soar_stats.py).
# Creates an app registration with a GitHub OIDC federated credential (no secret anywhere) for runs on
# main, gives it one role, Log Analytics Reader on the workspace, and stores its IDs as repo variables.
# Run once, as a user who can create app registrations and assign roles. Safe to run again.
set -euo pipefail

RG=${SOAR_RG:-rg-uig-sentinel}
WS=${SOAR_WORKSPACE:-law-uig-honeypot}
REPO=${SOAR_REPO:-estul-lachin/uig-detections}
APP=uig-detections-ci

app_id=$(az ad app list --display-name "$APP" --query '[0].appId' -o tsv)
if [ -z "$app_id" ]; then
  app_id=$(az ad app create --display-name "$APP" --query appId -o tsv)
  echo "created app $APP"
fi
sp_id=$(az ad sp show --id "$app_id" --query id -o tsv 2>/dev/null || true)
if [ -z "$sp_id" ]; then
  sp_id=$(az ad sp create --id "$app_id" --query id -o tsv)
  echo "created its service principal"
fi

# GitHub's subject claim is either repo:owner/name:... or, with immutable IDs,
# repo:owner@<owner id>/name@<repo id>:... (this repo sends the second). Trust both, for main only.
ids_subject=$(gh api "repos/$REPO" --jq '"repo:\(.owner.login)@\(.owner.id)/\(.name)@\(.id):ref:refs/heads/main"')
add_subject() { # name subject
  if [ -z "$(az ad app federated-credential list --id "$app_id" --query "[?subject=='$2'].name" -o tsv)" ]; then
    az ad app federated-credential create --id "$app_id" -o none --parameters "{
      \"name\": \"$1\",
      \"issuer\": \"https://token.actions.githubusercontent.com\",
      \"subject\": \"$2\",
      \"audiences\": [\"api://AzureADTokenExchange\"]
    }"
    echo "added federated credential for $2"
  fi
}
add_subject github-main "repo:$REPO:ref:refs/heads/main"
add_subject github-main-ids "$ids_subject"

scope=$(az monitor log-analytics workspace show -g "$RG" -n "$WS" --query id -o tsv)
if [ -z "$(az role assignment list --assignee "$sp_id" --role "Log Analytics Reader" --scope "$scope" --query '[0].id' -o tsv)" ]; then
  az role assignment create --assignee-object-id "$sp_id" --assignee-principal-type ServicePrincipal \
    --role "Log Analytics Reader" --scope "$scope" -o none
  echo "granted Log Analytics Reader on $WS"
fi

gh variable set AZURE_CLIENT_ID -R "$REPO" -b "$app_id"
gh variable set AZURE_TENANT_ID -R "$REPO" -b "$(az account show --query tenantId -o tsv)"
gh variable set AZURE_SUBSCRIPTION_ID -R "$REPO" -b "$(az account show --query id -o tsv)"
echo "Done. The next CI run on main publishes soar.json."
