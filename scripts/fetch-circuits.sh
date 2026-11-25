#!/bin/sh
# Downloads the circuit artifacts named in harness/circuit-pins.json from the public artifact bucket into
# $ENCLAVE_CIRCUITS (default .cache/circuits) and refuses any file whose SHA-256 differs from its pin.
set -eu
root=$(cd "$(dirname "$0")/.." && pwd)
dest=${ENCLAVE_CIRCUITS:-$root/.cache/circuits}
base=${ZK_ARTIFACTS_URL:-https://xjzgzsdinbjtszmwookf.supabase.co/storage/v1/object/public/zk-artifacts}
pins=$root/harness/circuit-pins.json
for name in $(jq -r 'keys[]' "$pins"); do
  case $name in threshold_*) folder=threshold ;; *) folder=appraisal ;; esac
  mkdir -p "$dest/$name"
  for pair in circuit.wasm:wasm proving_key.zkey:zkey verification_key.json:verificationKey; do
    file=${pair%%:*}
    field=${pair##*:}
    want=$(jq -r --arg n "$name" --arg f "$field" '.[$n][$f]' "$pins")
    path=$dest/$name/$file
    if [ -f "$path" ] && [ "$(shasum -a 256 "$path" | cut -d' ' -f1)" = "$want" ]; then continue; fi
    curl -fsS --max-time 120 -o "$path" "$base/$folder/$name/$file"
    got=$(shasum -a 256 "$path" | cut -d' ' -f1)
    if [ "$got" != "$want" ]; then
      rm -f "$path"
      echo "$name/$file does not match its pin" >&2
      exit 1
    fi
  done
done
echo "circuits ready in $dest"
