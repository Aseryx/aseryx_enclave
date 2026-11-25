#!/usr/bin/env bash
# 0.7 step 2: the cgroup probe at 2, 4 and 16 GB. Run from the repository root:
#   spike/0.7/step2.sh <probe policy, base64 on one line: out/policy.deploy.b64 of the probe-policy artifact>
# Stops at the first failure and leaves what it created for inspection (it prints the container's events first); a size
# that succeeds is deleted before the next. Every resource is tagged aseryx-run=0.7 and aseryx-step=mem-<N>gb.
set -euo pipefail

RG=aseryx-enclave-run07
POLICY_FILE=${1:?usage: step2.sh <probe policy base64 file>}
TEMPLATE=spike/0.7/probe-template.json
[[ -s "$POLICY_FILE" && "$(wc -l < "$POLICY_FILE")" -le 1 ]] || { echo "the policy file must be one line of base64" >&2; exit 2; }
mkdir -p run07
stamp() { date -u +%Y-%m-%dT%H:%M:%SZ; }

if [[ "$(az group exists -n "$RG")" != "true" ]]; then
  az group create -n "$RG" -l eastus --tags aseryx-run=0.7 aseryx-step=group --output none
  echo "$(stamp) created group $RG"
fi

for n in 2 4 16; do
  name="probe-${n}gb"
  file="run07/probe-${n}.json"
  jq --argjson n "$n" --arg pol "$(cat "$POLICY_FILE")" '
      .resources[0].properties.containers[0].properties.resources.requests.memoryInGB = $n
      | .resources[0].tags = {"aseryx-run":"0.7","aseryx-step":("mem-"+($n|tostring)+"gb")}
      | .resources[0].properties.confidentialComputeProperties.ccePolicy = $pol' "$TEMPLATE" > "$file"
  echo "$(stamp) deploying $name (${n} GB)"
  if ! az deployment group create -g "$RG" -f "$file" -p containerGroupName="$name" --output none; then
    echo "deployment of $name failed; the container's events:" >&2
    az container show -g "$RG" -n "$name" --query "containers[].{name:name,state:instanceView.currentState,events:instanceView.events}" -o json >&2 || true
    exit 1
  fi
  logs=""
  for _ in $(seq 1 12); do
    logs=$(az container logs -g "$RG" -n "$name" --container-name cgroup-probe 2>&1 || true)
    grep -q MemTotal <<<"$logs" && break
    sleep 5
  done
  echo "--- $name output ($(stamp)) ---"
  echo "$logs"
  echo "--- end ---"
  grep -q MemTotal <<<"$logs" || { echo "the probe printed no memory line; leaving $name for inspection" >&2; exit 1; }
  az container delete -g "$RG" -n "$name" --yes --output none
  echo "$(stamp) deleted $name"
done
echo "step 2 done; $RG holds: $(az resource list -g "$RG" --query 'length(@)' -o tsv) resources"
