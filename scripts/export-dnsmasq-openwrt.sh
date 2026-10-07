#!/usr/bin/env bash
# Export and verify one pinned native dnsmasq-full variant from the SDK.
set -euo pipefail
if [[ $# != 5 ]]; then
  echo "Usage: $0 SDK OUTPUT_DIR PACKAGE_ARCH (openwrt|glinet) SOURCE_COMMIT" >&2
  exit 2
fi
sdk=$(cd -- "$1" && pwd)
output_dir=$2
arch=$3
flavor=$4
source_commit=$5
case "$flavor" in openwrt|glinet) ;; *) echo "Unknown dnsmasq variant $flavor" >&2; exit 2;; esac
[[ "$arch" == aarch64_cortex-a53 || "$arch" == arm_cortex-a7_neon-vfpv4 || "$arch" == x86_64 ]]
[[ "$source_commit" =~ ^[0-9a-f]{40}$ ]]
mapfile -t artifacts < <(find "$sdk/bin" -type f -name "dnsmasq-full_*.ipk")
if [[ "${#artifacts[@]}" != 1 ]]; then
  echo "Expected one dnsmasq-full IPK, found ${#artifacts[@]}" >&2
  exit 1
fi
original="${artifacts[0]}"
filename=$(basename "$original")
version=$(awk -F_ '{print $2}' <<<"$filename")
[[ "$version" == "2.90-r5.1" ]] || { echo "Unexpected dnsmasq-full version: $version" >&2; exit 1; }
case "$filename" in *"_${arch}.ipk") ;; *) echo "Unexpected dnsmasq-full architecture: $filename" >&2; exit 1;; esac
export_name="${filename%.ipk}.${flavor}.ipk"
mkdir -p "$output_dir"
output_dir=$(cd -- "$output_dir" && pwd)
test ! -e "$output_dir/$export_name"
work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT
mkdir -p "$work/control" "$work/data"
tar -xf "$original" -C "$work"
test "$(cat "$work/debian-binary")" = 2.0
tar -xf "$work/control.tar.gz" -C "$work/control"
tar -xf "$work/data.tar.gz" -C "$work/data"
control="$work/control/control"
binary="$work/data/usr/sbin/dnsmasq"
test -x "$binary"
grep -Fx 'Package: dnsmasq-full' "$control"
grep -Fx 'Version: 2.90-r5.1' "$control"
grep -Fx "Architecture: $arch" "$control"
grep -q 'libubus' "$control"
test -s "$work/data/etc/config/dhcp"
sh -n "$work/data/etc/init.d/dnsmasq"
file "$binary"
readelf -h "$binary" > "$work/elf-header"
case "$arch" in
  aarch64_cortex-a53) grep -q 'Machine:.*AArch64' "$work/elf-header" ;;
  arm_cortex-a7_neon-vfpv4) grep -q 'Machine:.*ARM' "$work/elf-header" ;;
  x86_64) grep -q 'Machine:.*X86-64' "$work/elf-header" ;;
esac
# Feature markers are compiled into the actual target daemon, not just in a
# source-only patch or a helper binary.
strings "$binary" | grep -F 'regex-server' > "$work/regex-markers"
grep -F 'regex-server-ack' "$work/regex-markers"
if [[ "$flavor" == glinet ]]; then
  # getopt assembles "--mark=" at runtime, so it is not a literal ELF
  # string. Probe the vendor-specific option description and error path.
  strings "$binary" | grep -F 'Specify the outgoing packet mark.' > "$work/mark-marker"
  strings "$binary" | grep -F 'bad outgoing packet mark' >> "$work/mark-marker"
  grep -F 'procd_add_jail_mount /tmp/resolv.conf.vpn' "$work/data/etc/init.d/dnsmasq"
else
  if grep -Fq 'procd_add_jail_mount /tmp/resolv.conf.vpn' "$work/data/etc/init.d/dnsmasq"; then
    echo 'GL.iNet init script leaked into upstream OpenWrt variant' >&2
    exit 1
  fi
fi
cp "$original" "$output_dir/$export_name"
(
  cd "$output_dir"
  sha256sum "$export_name" > "$export_name.sha256"
)
{
  printf 'source_commit=%s\n' "$source_commit"
  printf 'openwrt_version=%s\nsdk_target=%s\nsdk_sha256=%s\n' \
    "${OPENWRT_VERSION:-unspecified}" "${SDK_TARGET:-unspecified}" "${SDK_SHA256:-unspecified}"
  printf 'dnsmasq_variant=%s\n' "$flavor"
  printf 'dnsmasq_source=2.90, OpenWrt 24.10.4 revision 5 + security patches\n'
  cat "$control"
  cat "$work/elf-header"
  cat "$sdk/feeds.conf"
} > "$output_dir/$export_name.buildinfo.txt"
# Both builds use the same verified upstream source; copy it only once.
source_archive=dnsmasq-2.90.tar.xz
if [[ ! -e "$output_dir/$source_archive" ]]; then
  test -s "$sdk/dl/$source_archive"
  echo "8e50309bd837bfec9649a812e066c09b6988b73d749b7d293c06c57d46a109e4  $sdk/dl/$source_archive" | sha256sum --check --strict
  cp "$sdk/dl/$source_archive" "$output_dir/$source_archive"
  ( cd "$output_dir" && sha256sum "$source_archive" > "$source_archive.sha256" )
fi
printf 'Verified dnsmasq-full %s for %s: %s\n' "$flavor" "$arch" "$export_name"
