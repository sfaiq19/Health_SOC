#!/usr/bin/env bash
set -euo pipefail
[[ $# -eq 1 ]] || { echo 'Usage: export-packets.sh RUN_DIRECTORY' >&2; exit 2; }
run_dir=$1
[[ -f "$run_dir/traffic.pcapng" ]] || { echo 'Missing capture' >&2; exit 2; }
[[ ! -e "$run_dir/frames.csv" ]] || { echo 'Refusing to replace a packet export' >&2; exit 2; }
tshark -r "$run_dir/traffic.pcapng" \
  -d tcp.port==8080,http -d tcp.port==9080,http -d tcp.port==9081,http \
  -T fields -E header=y -E separator=, -E quote=d \
  -e frame.number -e frame.time_epoch -e ip.src -e ip.dst -e tcp.srcport -e tcp.dstport \
  -e http.request.method -e http.request.uri -e http.response.code -e http.content_length -e http.request.line \
  > "$run_dir/frames.csv.part"
mv -- "$run_dir/frames.csv.part" "$run_dir/frames.csv"
capinfos -M "$run_dir/traffic.pcapng" > "$run_dir/capinfos.txt"
