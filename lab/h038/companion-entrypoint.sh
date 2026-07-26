#!/usr/bin/env bash
set -euo pipefail

if [[ "$(id -u)" == "0" && "${H038_IDENTITY_MAPPED:-0}" != "1" ]]; then
  groupmod --non-unique --gid "${H034_HOST_GID}" companion
  usermod --non-unique --uid "${H034_HOST_UID}" --gid "${H034_HOST_GID}" companion
  device_group="$(getent group "${H038_DEVICE_GID}" | cut -d: -f1 || true)"
  if [[ -z "${device_group}" ]]; then
    device_group="h038-device"
    groupadd --gid "${H038_DEVICE_GID}" "${device_group}"
  fi
  usermod --append --groups "${device_group}" companion
  chown -R companion:companion /companion /evidence
  export H038_IDENTITY_MAPPED=1
  exec runuser --user companion --preserve-environment -- /bin/bash "$0" "$@"
fi

{
  printf 'node='
  /app/node-runtimes/main/bin/node --version
  printf 'module_sha256='
  cut -d' ' -f1 /opt/h034/module.sha256
  printf 'identity='
  id
  . /etc/os-release
  printf 'os=%s\nversion=%s\n' "$ID" "$VERSION_ID"
} > /evidence/companion-runtime.txt

exec /app/node-runtimes/main/bin/node /app/main.js \
  --admin-address :: \
  --admin-port "${COMPANION_ADMIN_PORT}" \
  --config-dir "${COMPANION_CONFIG_BASEDIR}" \
  --extra-module-path /app/module-local-dev
