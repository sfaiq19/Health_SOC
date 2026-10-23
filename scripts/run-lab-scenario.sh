#!/usr/bin/env bash
# Run after initial setup with Codex closed. Owns only processes it starts.
set -euo pipefail
[[ $# -eq 3 ]] || { echo 'Usage: run-lab-scenario.sh s1|s2|s3 VERIFIED_INTERFACE NEW_RUN_DIRECTORY' >&2; exit 2; }
scenario=$1; iface=$2; run_dir=$3
[[ "$scenario" =~ ^s[123]$ ]] || { echo 'Invalid scenario' >&2; exit 2; }
[[ -f config/client.local.json ]] || { echo 'Prepare the private client config first' >&2; exit 2; }
[[ ! -e "$run_dir" ]] || { echo 'Use a new evidence directory' >&2; exit 2; }
mkdir -p -- "$run_dir"
python=.venv/bin/python
[[ -x "$python" ]] || { echo 'Run setup-linux.sh first' >&2; exit 2; }
ip -json addr show dev "$iface" > "$run_dir/interface-before.json"
dumpcap -D > "$run_dir/capture-interfaces.txt"
pids=()
capture_pid=''
cleanup() {
  if [[ -n "$capture_pid" ]]; then kill -INT "$capture_pid" 2>/dev/null || true; wait "$capture_pid" 2>/dev/null || true; fi
  for pid in "${pids[@]}"; do kill -TERM "$pid" 2>/dev/null || true; wait "$pid" 2>/dev/null || true; done
}
trap cleanup EXIT
for port in 9080 9081; do
  "$python" -m hospital_soc --config config/client.local.json receiver --port "$port" > "$run_dir/receiver-$port-console.txt" 2>&1 &
  pids+=("$!")
done
sleep 2
for pid in "${pids[@]}"; do kill -0 "$pid" || { echo 'A receiver failed to start; inspect logs' >&2; exit 2; }; done
dumpcap -i "$iface" -f 'host 10.77.0.1 and (tcp port 8080 or tcp port 9080 or tcp port 9081)' \
  -w "$run_dir/traffic.pcapng" 2> "$run_dir/capture-stats.txt" &
capture_pid=$!
sleep 2
kill -0 "$capture_pid" || { echo 'Capture failed to start' >&2; exit 2; }
# Manifest lives in a child because the capture has already created evidence files.
"$python" -m hospital_soc --config config/client.local.json scenario "$scenario" --output "$run_dir/generated"
sleep 30
kill -INT "$capture_pid"
wait "$capture_pid"
capture_pid=''
cp -- "$run_dir/generated/manifest.json" "$run_dir/manifest.json"
for name in file-hashes-before.json file-hashes-after.json; do
  if [[ -f "$run_dir/generated/$name" ]]; then cp -- "$run_dir/generated/$name" "$run_dir/$name"; fi
done
bash scripts/export-packets.sh "$run_dir"
echo 'Generation/capture finished. Collection is NOT complete: collect app/archive/alert/receiver evidence, clock/visibility observations and native rule proof before evaluation.'
