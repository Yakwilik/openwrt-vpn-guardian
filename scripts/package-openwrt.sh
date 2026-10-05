#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -ne 3 ]; then
  echo "Usage: $0 SDK_DIRECTORY OUTPUT_DIRECTORY PACKAGE_ARCH" >&2
  exit 2
fi

source_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
sdk_dir="$(cd -- "$1" && pwd)"
output_dir="$2"
expected_arch="$3"
if [[ "$output_dir" != /* ]]; then
  output_dir="$PWD/$output_dir"
fi
case "$expected_arch" in
  aarch64_cortex-a53) expected_goarch=arm64; asset_arch=arm64 ;;
  arm_cortex-a7_neon-vfpv4) expected_goarch=arm; asset_arch=armv7 ;;
  x86_64) expected_goarch=amd64; asset_arch=x64 ;;
  *) echo "Unsupported package architecture: $expected_arch" >&2; exit 2 ;;
esac

if [ -n "$(git -C "$source_dir" status --porcelain --untracked-files=normal)" ]; then
  echo 'Package builds require a clean source checkout.' >&2
  exit 1
fi
source_commit="$(git -C "$source_dir" rev-parse HEAD)"
source_epoch="$(git -C "$source_dir" show -s --format=%ct HEAD)"
package_version="0.1.0~git${source_epoch}.${source_commit:0:12}"
if [[ "${GITHUB_REF:-}" == refs/tags/v* ]]; then
  package_version="${GITHUB_REF#refs/tags/v}"
  if [[ ! "$package_version" =~ ^[0-9][0-9A-Za-z.+~-]*$ ]]; then
    echo 'Release tags must contain a valid package version after v.' >&2
    exit 1
  fi
fi

source_mirror="$(mktemp -d)"
check_dir="$(mktemp -d)"
trap 'rm -rf -- "$source_mirror" "$check_dir"' EXIT
git clone --bare --quiet "$source_dir" "$source_mirror/repo.git"
mkdir "$source_mirror/package-source"
git --git-dir="$source_mirror/repo.git" archive "$source_commit" package/openwrt package/v2raya \
  | tar -xf - -C "$source_mirror/package-source"

cd "$sdk_dir"
if [ ! -s feeds.conf ] || grep '^src-git' feeds.conf | grep -Evq '\^[0-9a-f]{40}$'; then
  echo 'SDK feeds.conf must pin every Git feed to a full commit hash.' >&2
  exit 1
fi
./scripts/feeds update -a
./scripts/feeds install -a
# The pinned OpenWrt feed contains the incompatible BoltDB-based v2rayA 2.2.x.
rm -f package/feeds/packages/v2raya
rm -rf package/vpn-guardian package/v2raya
cp -a "$source_mirror/package-source/package/openwrt" package/vpn-guardian
cp -a "$source_mirror/package-source/package/v2raya" package/v2raya
sed -i \
  -e "s|^PKG_VERSION:=.*|PKG_VERSION:=$package_version|" \
  -e "s|^PKG_SOURCE_URL:=.*|PKG_SOURCE_URL:=file://$source_mirror/repo.git|" \
  -e "s|^PKG_SOURCE_VERSION:=.*|PKG_SOURCE_VERSION:=$source_commit|" \
  package/vpn-guardian/Makefile

export SOURCE_DATE_EPOCH="$source_epoch"
# Preserve the SDK target while removing its default selection of every package.
python3 - <<'PY'
from pathlib import Path
import re
config = Path('.config')
lines = config.read_text().splitlines() if config.exists() else []
lines = [line for line in lines if not re.match(r'^(# )?CONFIG_(PACKAGE_\S+|ALL(?:_KMODS|_NONSHARED)?)(?:[ =])', line)]
lines.extend(['CONFIG_ALL=n', 'CONFIG_ALL_KMODS=n', 'CONFIG_ALL_NONSHARED=n',
              'CONFIG_PACKAGE_v2raya=m', 'CONFIG_PACKAGE_vpn-guardian=m'])
config.write_text('\n'.join(lines) + '\n')
PY
make defconfig
mkdir -p "$sdk_dir/bin"
find "$sdk_dir/bin" -type f \( -name 'vpn-guardian_*.ipk' -o -name 'v2raya_*.ipk' \) -delete
make package/v2raya/compile V=s
make package/vpn-guardian/compile V=s

go_tool="$(find -L "$sdk_dir/staging_dir/hostpkg" -type f -path '*/bin/go' -print -quit)"
test -n "$go_tool"
verify_binary() {
  local binary="$1" buildinfo="$2"
  test -x "$binary"
  file "$binary"
  file "$binary" | grep -q 'statically linked'
  if readelf -l "$binary" | grep -q INTERP || readelf -d "$binary" | grep -q NEEDED; then
    echo "$binary unexpectedly requires a dynamic loader or shared library." >&2
    exit 1
  fi
  "$go_tool" version -m "$binary" > "$buildinfo"
  grep -F 'CGO_ENABLED=0' "$buildinfo"
  grep -F 'GOOS=linux' "$buildinfo"
  grep -F "GOARCH=$expected_goarch" "$buildinfo"
  if [ "$expected_goarch" = arm ]; then
    grep -Eq 'GOARM=7(,hardfloat)?$' "$buildinfo"
  fi
}

mkdir -p "$output_dir"
for package in v2raya vpn-guardian; do
  mapfile -t packages < <(find "$sdk_dir/bin" -type f -name "${package}_*.ipk")
  if [ "${#packages[@]}" -ne 1 ]; then
    echo "Expected exactly one $package IPK, found ${#packages[@]}." >&2
    exit 1
  fi
  package_file="${packages[0]}"
  unpack_dir="$check_dir/$package"
  mkdir -p "$unpack_dir/control" "$unpack_dir/data"
  # OpenWrt ipkg-build produces a gzip-compressed tar container, not a Debian ar.
  tar -xf "$package_file" -C "$unpack_dir"
  test "$(cat "$unpack_dir/debian-binary")" = 2.0
  tar -xf "$unpack_dir/control.tar.gz" -C "$unpack_dir/control"
  tar -xf "$unpack_dir/data.tar.gz" -C "$unpack_dir/data"
  grep -Fx "Architecture: $expected_arch" "$unpack_dir/control/control"
  grep -Fx "Package: $package" "$unpack_dir/control/control"
  verify_binary "$unpack_dir/data/usr/bin/$package" "$unpack_dir/go-buildinfo"
  while IFS= read -r -d '' script; do
    sh -n "$script"
  done < <(find "$unpack_dir/data/etc/init.d" "$unpack_dir/control" -type f \
    \( -path '*/init.d/*' -o -name 'postinst*' -o -name 'prerm*' -o -name 'postrm*' \) -print0)
  cp "$package_file" "$output_dir/"
  package_name="$(basename "$package_file")"
  if [ "$package" = v2raya ]; then
    backend_package_name="$package_name"
  fi
  (
    cd "$output_dir"
    sha256sum "$package_name" > "$package_name.sha256"
  )
  {
    printf 'source_commit=%s\nsource_date_epoch=%s\n' "$source_commit" "$source_epoch"
    printf 'openwrt_version=%s\nsdk_target=%s\nsdk_sha256=%s\n' \
      "${OPENWRT_VERSION:-unspecified}" "${SDK_TARGET:-unspecified}" "${SDK_SHA256:-unspecified}"
    cat "$unpack_dir/control/control"
    cat "$unpack_dir/go-buildinfo"
    cat "$sdk_dir/feeds.conf"
  } > "$output_dir/$package_name.buildinfo.txt"
done

guardian_dir="$check_dir/vpn-guardian"
grep -F 'v2raya (>=2.5.8)' "$guardian_dir/control/control"
grep -Fx '/etc/vpn-guardian/' "$guardian_dir/data/lib/upgrade/keep.d/vpn-guardian"
# No configured manifests exist in the build host: neither service may start.
for script in "$guardian_dir/data/etc/init.d"/*; do
  sh -c 'procd_open_instance() { echo "unexpected service start" >&2; exit 1; }; . "$1"; start_service' sh "$script"
done

# Installation and upgrades must not invoke generated front/routing cleanup.
sh "$guardian_dir/control/postinst-pkg"
PKG_UPGRADE=1 sh "$guardian_dir/control/prerm-pkg"
PKG_UPGRADE=1 sh "$guardian_dir/control/postrm"

backend_dir="$check_dir/v2raya"
verify_binary "$backend_dir/data/usr/bin/v2raya_core" "$backend_dir/core-buildinfo"
backend_recipe="$source_mirror/package-source/package/v2raya/Makefile"
for entry in "v2raya:V2RAYA_HASH" "v2raya_core:V2RAYA_CORE_HASH"; do
  binary_name="${entry%%:*}"
  hash_key="${entry#*:}_$asset_arch"
  expected_hash="$(awk -F ':=' -v key="$hash_key" '$1 == key {print $2}' "$backend_recipe")"
  [[ "$expected_hash" =~ ^[0-9a-f]{64}$ ]]
  echo "$expected_hash  $backend_dir/data/usr/bin/$binary_name" | sha256sum --check --strict
done
for buildinfo in "$backend_dir/go-buildinfo" "$backend_dir/core-buildinfo"; do
  grep -F 'vcs.revision=f86763d00b14c565671fcad75f990fdf40facbf4' "$buildinfo"
done
for asset in geoip geosite; do
  test "$(readlink "$backend_dir/data/usr/share/v2raya/$asset.dat")" = "../v2ray/$asset.dat"
  grep -F "v2ray-$asset" "$backend_dir/control/control"
done
grep -Eq "^[[:space:]]*option enabled '0'$" "$backend_dir/data/etc/config/v2raya"
grep -F "option v2ray_bin '/usr/bin/v2raya_core'" "$backend_dir/data/etc/config/v2raya"
disabled_status=0
sh -c 'config_load() { :; }; config_get_bool() { enabled=0; }; procd_open_instance() { exit 99; }; . "$1"; start_service' \
  sh "$backend_dir/data/etc/init.d/v2raya" || disabled_status=$?
test "$disabled_status" -eq 1
test -s "$backend_dir/data/usr/share/v2raya/web/index.html"
for license in LICENSE CORE-LICENSE SOURCE.txt; do
  test -s "$backend_dir/data/usr/share/licenses/v2raya/$license"
done
cat "$backend_dir/core-buildinfo" >> "$output_dir/$backend_package_name.buildinfo.txt"

# Ship the corresponding upstream source and licenses with each architecture bundle.
backend_source='v2rayA-2.5.8.tar.gz'
cp "$sdk_dir/dl/$backend_source" "$output_dir/"
cp "$backend_dir/data/usr/share/licenses/v2raya/SOURCE.txt" "$output_dir/v2raya-2.5.8.SOURCE.txt"
(
  cd "$output_dir"
  sha256sum "$backend_source" > "$backend_source.sha256"
)
printf 'Verified both packages for %s at source %s\n' "$expected_arch" "$source_commit"
