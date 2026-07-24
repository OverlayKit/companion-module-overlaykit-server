#!/usr/bin/env bash
set -euo pipefail

archive="${1:?module archive is required}"
module_root="${2:?module root is required}"
package_root="${module_root}/pkg"

mkdir -p "${package_root}"
touch "${module_root}/DEBUG-PACKAGED"
tar -xzf "${archive}" --strip-components=1 -C "${package_root}"

test -f "${package_root}/companion/manifest.json"
test -f "${package_root}/main.js"
