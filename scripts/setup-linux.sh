#!/usr/bin/env bash
set -euo pipefail
[[ -f /etc/os-release ]] || { echo 'Ubuntu is required' >&2; exit 2; }
. /etc/os-release
[[ "$ID" == 'ubuntu' && "$VERSION_ID" == '24.04' ]] || { echo 'Expected Ubuntu 24.04' >&2; exit 2; }
echo 'Installing Python and packet tools; this does not install or certify Wazuh.'
sudo apt-get update
sudo apt-get install -y python3-venv python3-pip tshark openssh-server
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements-lock.txt
.venv/bin/python -m pip install --no-deps -e .
echo 'Configure dumpcap group permissions separately and verify with dumpcap -D.'
echo 'Install matching Wazuh central packages using official instructions; record exact versions.'
