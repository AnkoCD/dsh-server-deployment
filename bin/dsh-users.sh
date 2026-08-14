#!/usr/bin/env bash
set -euo pipefail
if [ "$(id -u)" -ne 0 ]; then exec sudo "$0" "$@"; fi
exec /opt/deepseek-harness/runtime/bin/node /opt/deepseek-harness/gateway/userctl.js "$@"
