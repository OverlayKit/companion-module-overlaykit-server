#!/usr/bin/env bash
set -euo pipefail

fail() {
  printf 'H-041 entrypoint: %s\n' "$1" >&2
  exit 1
}

require_decimal() {
  local name="$1"
  local value="${!name:-}"
  [[ "${value}" =~ ^[1-9][0-9]*$ ]] || fail "${name} must be a positive decimal integer"
  printf '%s' "${value}"
}

[[ "${EUID}" -eq 0 ]] || fail 'must start as root'

uid="$(require_decimal H041_UID)"
gid="$(require_decimal H041_GID)"
device_gid="$(require_decimal H041_DEVICE_GID)"
dynamic_path="${H041_DYNAMIC_PATH:-}"
compat_path="${H041_COMPAT_PATH:-}"

[[ "${uid}" == '1000' ]] || fail 'H041_UID must be 1000'
[[ "${gid}" == '1000' ]] || fail 'H041_GID must be 1000'
[[ "${device_gid}" == '1002' ]] || fail 'H041_DEVICE_GID must be 1002'
[[ "${dynamic_path}" =~ ^/host-dev/(hidraw[0-9]+)$ ]] ||
  fail 'H041_DYNAMIC_PATH must match /host-dev/hidrawN'
dynamic_name="${BASH_REMATCH[1]}"
[[ "${compat_path}" =~ ^/dev/(hidraw[0-9]+)$ ]] ||
  fail 'H041_COMPAT_PATH must match /dev/hidrawN'
compat_name="${BASH_REMATCH[1]}"
[[ "${dynamic_name}" == "${compat_name}" ]] ||
  fail 'H041_DYNAMIC_PATH and H041_COMPAT_PATH must name the same hidraw index'
[[ ! -e "${compat_path}" && ! -L "${compat_path}" ]] ||
  fail 'H041_COMPAT_PATH already exists'
[[ -x /docker-entrypoint.sh ]] || fail '/docker-entrypoint.sh is not executable'
command -v setpriv >/dev/null 2>&1 || fail 'setpriv is unavailable'

ln --symbolic -- "${dynamic_path}" "${compat_path}"
[[ -L "${compat_path}" ]] || fail 'compatibility symlink was not created'
[[ "$(readlink -- "${compat_path}")" == "${dynamic_path}" ]] ||
  fail 'compatibility symlink target is not exact'

exec setpriv \
  --reuid "${uid}" \
  --regid "${gid}" \
  --groups "${gid},${device_gid}" \
  --no-new-privs \
  /docker-entrypoint.sh "$@"
