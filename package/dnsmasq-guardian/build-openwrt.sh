#!/bin/sh
# Stage the complete native OpenWrt dnsmasq recipe, then compile its full variant.
set -eu
if [ "$#" -lt 1 ] || [ "$#" -gt 3 ]; then
  echo "Usage: $0 OPENWRT_SDK [--prepare-only] [--glinet]" >&2
  exit 2
fi
sdk_arg=$1
shift
mode=build
glinet=0
for option in "$@"; do
  case "$option" in
    --prepare-only) mode=--prepare-only ;;
    --glinet) glinet=1 ;;
    *) echo "Unknown build option: $option" >&2; exit 2 ;;
  esac
done
package_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
sdk=$(CDPATH= cd -- "$sdk_arg" && pwd)
if [ ! -f "$sdk/include/package.mk" ] || [ ! -f "$sdk/rules.mk" ]; then
  echo 'The supplied directory is not an OpenWrt SDK/buildroot' >&2
  exit 1
fi
(
  cd "$package_dir/upstream"
  sha256sum -c ../upstream.sha256 > /dev/null
)
# SDK feeds install an active package symlink at package/feeds/base/dnsmasq.
# Overriding package/network/services/dnsmasq would silently leave that feed
# symlink pointing at the *unpatched* r4 recipe. Replace the resolved active
# package source, and keep the original in a directory outside the package
# scanner to prevent duplicates.
active="$sdk/package/feeds/base/dnsmasq"
if [ -L "$active" ]; then
  destination=$(readlink -f "$active")
  case "$destination" in
    "$sdk/"*) ;;
    *) echo "Refusing to override dnsmasq outside this SDK: $destination" >&2; exit 1 ;;
  esac
elif [ -d "$active" ]; then
  destination="$active"
else
  destination="$sdk/package/network/services/dnsmasq"
fi
backup="$sdk/guardian-original-dnsmasq-recipe"
stage="$sdk/.guardian-dnsmasq-stage"
if [ -e "$stage" ]; then
  echo "Staging directory already exists: $stage" >&2
  exit 1
fi
mkdir -p "$(dirname -- "$destination")"
cp -R "$package_dir/upstream" "$stage"
cp "$package_dir/patches/990-guardian-regex-servers.patch" "$stage/patches/"
cp "$package_dir/patches/991-guardian-reload-ack.patch" "$stage/patches/"
if [ "$glinet" = 1 ]; then
  cp "$package_dir/compat/glinet/992-glinet-outgoing-mark.patch" "$stage/patches/"
  patch -d "$stage" -p1 < "$package_dir/compat/glinet/init.patch"
fi
sed 's/^PKG_RELEASE:=5$/PKG_RELEASE:=5.1/' "$stage/Makefile" > "$stage/Makefile.new"
mv "$stage/Makefile.new" "$stage/Makefile"
printf 'dnsmasq 2.90-r5 plus native regex selectors and reload ack, revision 5.1; glinet=%s\n' "$glinet" > "$stage/guardian-regex-recipe"
if [ -d "$destination" ]; then
  if [ -f "$destination/guardian-regex-recipe" ]; then
    rm -rf "$destination"
  elif [ ! -e "$backup" ]; then
    mv "$destination" "$backup"
  else
    echo "A previous recipe backup already exists: $backup" >&2
    rm -rf "$stage"
    exit 1
  fi
fi
mv "$stage" "$destination"
printf 'Prepared dnsmasq-full 2.90-5.1 recipe: %s\n' "$destination"
if [ "$mode" = --prepare-only ]; then
  exit 0
fi
if [ ! -f "$sdk/.config" ] || ! awk '/^CONFIG_PACKAGE_dnsmasq-full=[my]$/ { found=1 } END { exit !found }' "$sdk/.config"; then
  echo 'Select CONFIG_PACKAGE_dnsmasq-full=m in the SDK and run make defconfig first.' >&2
  echo 'Preserve the deployed feature flags, including DHCP, DHCPv6, DNSSEC, auth, conntrack, ipset, nftset and TFTP.' >&2
  exit 1
fi
make -C "$sdk" -j"${JOBS:-2}" package/dnsmasq/compile V=s
