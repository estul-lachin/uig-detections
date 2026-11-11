// SOAR for the honeypot's Sentinel workspace: a Key Vault for the playbooks' API keys, a Microsoft
// Sentinel API connection that signs in with each playbook's managed identity, and the playbooks.
// Role assignments are not made here; soar/grant.sh makes them (see soar/README.md).
//
//   soar/deploy.sh            what-if, then deploy
targetScope = 'resourceGroup'

@description('Region; defaults to the resource group\'s (the workspace is in Canada Central).')
param location string = resourceGroup().location

@description('The existing Log Analytics workspace that has Microsoft Sentinel on it.')
param workspaceName string = 'law-uig-honeypot'

@description('Key Vault names are global; this suffix is stable per resource group.')
param vaultSuffix string = substring(uniqueString(resourceGroup().id), 0, 6)

@description('Entra object ID of the analyst who gets High incidents (deploy.sh passes the signed-in user).')
param ownerObjectId string

resource workspace 'Microsoft.OperationalInsights/workspaces@2023-09-01' existing = {
  name: workspaceName
}

// Secrets: abuseipdb-key, telegram-bot-token, telegram-chat-id (set with soar/set-secrets.sh).
// RBAC only, no access policies. Purge protection stays off so the vault can be removed for good.
resource vault 'Microsoft.KeyVault/vaults@2023-07-01' = {
  name: 'kv-uig-soar-${vaultSuffix}'
  location: location
  properties: {
    tenantId: subscription().tenantId
    sku: {
      family: 'A'
      name: 'standard'
    }
    enableRbacAuthorization: true
    enableSoftDelete: true
    softDeleteRetentionInDays: 7
    publicNetworkAccess: 'Enabled' // Consumption Logic Apps reach the vault over the internet
  }
}

// Only the trigger uses this connection; actions call the REST APIs with the HTTP action and the
// managed identity, which bills as a built-in action instead of a standard connector call.
resource sentinelConnection 'Microsoft.Web/connections@2016-06-01' = {
  name: 'azuresentinel-uig-soar'
  location: location
  // kind and parameterValueType (managed identity sign-in) are missing from Bicep's type definitions
  #disable-next-line BCP187
  kind: 'V1'
  properties: {
    displayName: 'uig-soar (managed identity)'
    #disable-next-line BCP037
    parameterValueType: 'Alternative'
    api: {
      id: subscriptionResourceId('Microsoft.Web/locations/managedApis', location, 'azuresentinel')
    }
  }
}

var connections = {
  azuresentinel: {
    connectionId: sentinelConnection.id
    connectionName: sentinelConnection.name
    id: sentinelConnection.properties.api.id
    connectionProperties: {
      authentication: {
        type: 'ManagedServiceIdentity'
      }
    }
  }
}

resource enrich 'Microsoft.Logic/workflows@2019-05-01' = {
  name: 'pb-uig-enrich'
  location: location
  identity: {
    type: 'SystemAssigned'
  }
  properties: {
    state: 'Enabled'
    // A Workflow action needs the called playbook's ID as a literal, so it is filled in here
    definition: json(replace(loadTextContent('playbooks/enrich.json'), '__NOTIFY_WORKFLOW_ID__', notify.id))
    parameters: {
      '$connections': {
        value: connections
      }
      workspaceId: {
        value: workspace.id
      }
      // Built from names, not runtime properties, so what-if can show "no change" on a redeploy
      vaultUri: {
        value: 'https://${vault.name}${environment().suffixes.keyvaultDns}/'
      }
    }
  }
}

resource notify 'Microsoft.Logic/workflows@2019-05-01' = {
  name: 'pb-uig-notify'
  location: location
  identity: {
    type: 'SystemAssigned'
  }
  properties: {
    state: 'Enabled'
    definition: loadJsonContent('playbooks/notify.json')
    parameters: {
      vaultUri: {
        value: 'https://${vault.name}${environment().suffixes.keyvaultDns}/'
      }
    }
  }
}

// Automation rules are free; they decide which playbook runs when. Lower order runs first.
// Triage that depends on the enrichment (auto-close, Telegram) lives in pb-uig-enrich itself: changes made
// by a playbook that an automation rule started do not fire "incident updated" rules (seen 2026-11-09:
// enriched High incidents #61 and #62 never reached an update-triggered notify rule).
resource enrichOnCreate 'Microsoft.SecurityInsights/automationRules@2024-03-01' = {
  scope: workspace
  name: guid(workspace.id, 'uig-soar', 'enrich-on-create')
  properties: {
    displayName: 'SOAR: enrich every new incident'
    order: 10
    triggeringLogic: {
      isEnabled: true
      triggersOn: 'Incidents'
      triggersWhen: 'Created'
    }
    actions: [
      {
        order: 1
        actionType: 'RunPlaybook'
        actionConfiguration: {
          logicAppResourceId: enrich.id
          tenantId: subscription().tenantId
        }
      }
    ]
  }
}

// Triage. High incidents go straight to the analyst.
resource escalateHigh 'Microsoft.SecurityInsights/automationRules@2024-03-01' = {
  scope: workspace
  name: guid(workspace.id, 'uig-soar', 'escalate-high')
  properties: {
    displayName: 'SOAR: assign High incidents and set them Active'
    order: 20
    triggeringLogic: {
      isEnabled: true
      triggersOn: 'Incidents'
      triggersWhen: 'Created'
      conditions: [
        {
          conditionType: 'Property'
          conditionProperties: {
            propertyName: 'IncidentSeverity'
            operator: 'Equals'
            propertyValues: [
              'High'
            ]
          }
        }
      ]
    }
    actions: [
      {
        order: 1
        actionType: 'ModifyProperties'
        actionConfiguration: {
          status: 'Active'
          owner: {
            objectId: ownerObjectId
            ownerType: 'User'
          }
        }
      }
    ]
  }
}



// End-to-end test (tools/soar_e2e.py): turns a marked synthetic event in Cowrie_Test_CL into a real Low
// incident, so the whole chain runs as it would for an attack. tools/sentinel_check.py also writes to that
// table, but never with this sensor prefix. Empty runs cost nothing.
resource e2eRule 'Microsoft.SecurityInsights/alertRules@2024-03-01' = {
  scope: workspace
  name: guid(workspace.id, 'uig-soar', 'e2e-test-rule')
  kind: 'Scheduled'
  properties: {
    displayName: 'SOAR end-to-end test'
    description: 'Fires only on synthetic events written by tools/soar_e2e.py (sensor soar-e2e:<run>).'
    severity: 'Low'
    enabled: true
    query: 'Cowrie_Test_CL\n| where ingestion_time() > ago(5m) and ingestion_time() <= now() and sensor startswith "soar-e2e:"\n| summarize Matches = count(), FirstSeen = min(TimeGenerated), LastSeen = max(TimeGenerated) by src_ip'
    queryFrequency: 'PT5M'
    queryPeriod: 'PT1H'
    triggerOperator: 'GreaterThan'
    triggerThreshold: 0
    suppressionDuration: 'PT5M'
    suppressionEnabled: false
    tactics: []
    techniques: []
    entityMappings: [
      {
        entityType: 'IP'
        fieldMappings: [
          {
            identifier: 'Address'
            columnName: 'src_ip'
          }
        ]
      }
    ]
    alertDetailsOverride: {
      alertDisplayNameFormat: 'SOAR end-to-end test from {{src_ip}}'
    }
    eventGroupingSettings: {
      aggregationKind: 'AlertPerResult'
    }
    incidentConfiguration: {
      createIncident: true
      groupingConfiguration: {
        enabled: true
        reopenClosedIncident: false
        lookbackDuration: 'P1D'
        matchingMethod: 'AllEntities'
        groupByEntities: []
        groupByAlertDetails: []
        groupByCustomDetails: []
      }
    }
  }
}

output vaultName string = vault.name
output vaultId string = vault.id
output workspaceId string = workspace.id
output playbooks array = [
  {
    name: enrich.name
    id: enrich.id
    principalId: enrich.identity.principalId
  }
  {
    name: notify.name
    id: notify.id
    principalId: notify.identity.principalId
  }
]
