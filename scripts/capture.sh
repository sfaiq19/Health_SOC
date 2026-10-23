#!/usr/bin/env bash
set -euo pipefail
if [[ $# -ne 2 ]]; then
  echo 'Usage: capture.sh VERIFIED_INTERFACE NEW_RUN_DIRECTORY' >&2; exit 2
fi
iface=$1
run_dir=$2
command -v dumpcap >/dev/null || { echo 'Install Wireshark/dumpcap first' >&2; exit 2; }
[[ -d "$run_dir" ]] || mkdir -p -- "$run_dir"
[[ ! -e "$run_dir/traffic.pcapng" ]] || { echo 'Refusing to overwrite existing capture' >&2; exit 2; }
dumpcap -D > "$run_dir/capture-interfaces.txt"
ip -json addr show dev "$iface" > "$run_dir/capture-interface.json"
date --utc --iso-8601=ns > "$run_dir/capture-start.txt"
echo 'Stop capture with Ctrl+C after traffic and a 30-second collection drain.' >&2
dumpcap -i "$iface" -f 'host 10.77.0.1 and (tcp port 8080 or tcp port 9080 or tcp port 9081)' \
  -w "$run_dir/traffic.pcapng" 2> >(tee "$run_dir/capture-stats.txt" >&2)
