#!/bin/sh
# Execute the real UBus acknowledgement callback with isolated state hooks.
set -eu
if [ "$#" -ne 2 ]; then
  echo "Usage: $0 DNSMASQ_SOURCE_DIR SDK_TARGET_INCLUDE_DIR" >&2
  exit 2
fi
suite_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
include_dir=$(CDPATH= cd -- "$2" && pwd)
if [ ! -f "$include_dir/libubus.h" ] || [ ! -f "$include_dir/libubox/blob.h" ]; then
  echo 'Provide the SDK target usr/include directory containing libubus/libubox headers.' >&2
  exit 1
fi
work=$(mktemp -d "${TMPDIR:-/tmp}/dnsmasq-guardian-ack-test.XXXXXX")
trap 'rm -rf "$work"' EXIT HUP INT TERM
cp -R "$1" "$work/source"
source_dir="$work/source"
if ! rg -q 'serverarray_native' "$source_dir/src/dnsmasq.h"; then
  patch -d "$source_dir" -p1 < "$suite_dir/../patches/990-guardian-regex-servers.patch"
fi
if ! rg -q 'UBUS_METHOD_NOARG\("reload_servers"' "$source_dir/src/ubus.c"; then
  patch -d "$source_dir" -p1 < "$suite_dir/../patches/991-guardian-reload-ack.patch"
fi
compiler=${CC:-cc}
"$compiler" -O1 -g -Wall -W -DHAVE_UBUS -DNO_ID \
  -ffunction-sections -fdata-sections -I "$source_dir/src" -idirafter "$include_dir" \
  -c "$source_dir/src/ubus.c" -o "$work/ubus.o"
objcopy --globalize-symbol ubus_handle_reload_servers "$work/ubus.o" "$work/callable.o"
# Discard other UBus methods, so this test needs headers but no host libubus.
"$compiler" -O1 -g -Wall -W -DHAVE_UBUS -DNO_ID \
  -ffunction-sections -fdata-sections -I "$source_dir/src" -idirafter "$include_dir" \
  "$suite_dir/test-reload-ack.c" "$work/callable.o" -Wl,--gc-sections -o "$work/test-reload-ack"
"$work/test-reload-ack"
