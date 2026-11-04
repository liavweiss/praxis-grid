#!/usr/bin/env bash
# Exercise the installed GridNetwork CRD through Kubernetes admission.
set -euo pipefail

if [ "$#" -ne 1 ]; then
  echo "usage: bash scripts/test-gridnetwork-sovereignty.sh <kube-context>" >&2
  exit 2
fi

context=$1
created=()
message='sovereignty is applied only by siteRouter gridSiteRoute'

cleanup() {
  local result=$? name
  trap - EXIT
  for name in "${created[@]}"; do
    if ! kubectl --context "$context" delete gridnetwork "$name" --ignore-not-found --wait=false >/dev/null; then
      echo "failed to remove test resource $name" >&2
      result=1
    fi
  done
  exit "$result"
}
trap cleanup EXIT

kubectl --context "$context" wait --for=condition=Established \
  crd/gridnetworks.grid.praxis.fast --timeout=60s >/dev/null

# Build raw resources so legacy names and explicit nulls reach the API server.
resource() {
  local gateways=$1 config=$2 router=$3 sovereignty=$4 generate=${5:-false}
  jq -n --arg gateways "$gateways" --arg config "$config" --arg router "$router" --arg sovereignty "$sovereignty" --argjson generate "$generate" '
    ({} + (if $router == "omitted" then {} else {siteRouter: $router} end)
        + (if $sovereignty == "omitted" then {}
           elif $sovereignty == "null" then {sovereignty: null}
           else {sovereignty: {header: "X-Sovereignty-Zone", mode: $sovereignty}} end)
        + {generate: $generate}) as $settings |
    {apiVersion: "grid.praxis.fast/v1alpha1", kind: "GridNetwork",
     metadata: {generateName: "sovereignty-admission-"},
     spec: {($gateways): [{name: "gateway", namespace: "default", ($config): $settings}]}}'
}

expect_accept() {
  local gateways=$1 config=$2 router=$3 sovereignty=$4 output
  if ! output=$(resource "$gateways" "$config" "$router" "$sovereignty" |
    kubectl --context "$context" create --dry-run=server -f - -o json); then
    echo "rejected valid $gateways/$config router=$router sovereignty=$sovereignty" >&2
    return 1
  fi
  if ! jq -e --arg gateways "$gateways" --arg config "$config" \
    '.spec[$gateways][0][$config] | type == "object"' <<<"$output" >/dev/null; then
    echo "API server pruned $gateways/$config" >&2
    return 1
  fi
  if [ "$sovereignty" != omitted ] && [ "$sovereignty" != null ]; then
    if ! jq -e --arg gateways "$gateways" --arg config "$config" --arg mode "$sovereignty" \
      '.spec[$gateways][0][$config].sovereignty.mode == $mode' <<<"$output" >/dev/null; then
      echo "API server pruned sovereignty at $gateways/$config" >&2
      return 1
    fi
  fi
}

expect_reject() {
  local input=$1 operation=$2 label=$3 output
  if output=$(kubectl --context "$context" "$operation" --dry-run=server -f - -o json <<<"$input" 2>&1); then
    echo "accepted invalid $label" >&2
    return 1
  fi
  if [[ $output != *"$message"* ]]; then
    echo "invalid $label failed for an unexpected reason: $output" >&2
    return 1
  fi
}

for gateways in consumerGateways gatewayRefs; do
  for config in praxisConfig consumerConfig; do
    for router in omitted intelligentRoute gridSiteRoute; do
      expect_accept "$gateways" "$config" "$router" omitted
      expect_accept "$gateways" "$config" "$router" null
    done
    for mode in enforce audit; do
      expect_accept "$gateways" "$config" gridSiteRoute "$mode"
      for router in omitted intelligentRoute; do
        input=$(resource "$gateways" "$config" "$router" "$mode")
        expect_reject "$input" create "$gateways/$config router=$router mode=$mode"
      done
    done
    input=$(resource "$gateways" "$config" intelligentRoute enforce true)
    expect_reject "$input" create "$gateways/$config with generation enabled"

    input=$(resource "$gateways" "$config" gridSiteRoute enforce)
    stored=$(kubectl --context "$context" create -f - -o json <<<"$input")
    name=$(jq -er '.metadata.name' <<<"$stored")
    created+=("$name")
    invalid=$(jq --arg gateways "$gateways" --arg config "$config" \
      '.spec[$gateways][0][$config].siteRouter = "intelligentRoute" | del(.metadata.managedFields, .status)' <<<"$stored")
    expect_reject "$invalid" replace "$gateways/$config update"
    echo "PASS: $gateways/$config admission and update"
  done
done
