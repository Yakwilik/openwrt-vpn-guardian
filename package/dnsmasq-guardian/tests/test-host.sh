#!/bin/sh
set -eu
export ASAN_OPTIONS="${ASAN_OPTIONS:-detect_leaks=0}"
if [ "$#" -lt 1 ] || [ "$#" -gt 2 ]; then
  echo "Usage: $0 PATH_TO_DNSMASQ_2.90_SOURCE [--glinet]" >&2
  exit 2
fi
glinet=0
case "${2:-}" in
  '') ;;
  --glinet) glinet=1 ;;
  *) echo 'Unknown test mode' >&2; exit 2 ;;
esac
suite_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
work=$(mktemp -d "${TMPDIR:-/tmp}/dnsmasq-guardian-test.XXXXXX")
trap 'rm -rf "$work"' EXIT HUP INT TERM
cp -R "$1" "$work/source"
source_dir="$work/source"
if ! rg -q 'dumpfile regex-server' "$source_dir/src/config.h"; then
  patch -d "$source_dir" -p1 < "$suite_dir/../patches/990-guardian-regex-servers.patch"
fi
if ! rg -q 'regex-server-ack' "$source_dir/src/config.h"; then
  patch -d "$source_dir" -p1 < "$suite_dir/../patches/991-guardian-reload-ack.patch"
fi
if [ "$glinet" = 1 ] && ! rg -q 'explicit outgoing DNS socket mark' "$source_dir/src/dnsmasq.h"; then
  patch -d "$source_dir" -p1 < "$suite_dir/../compat/glinet/992-glinet-outgoing-mark.patch"
fi
make -C "$source_dir" clean > "$work/build.log" 2>&1
flags='-O1 -g -Wall -W'
ldflags=''
if [ -n "${SANITIZE:-}" ]; then
  flags="$flags -fsanitize=$SANITIZE -fno-omit-frame-pointer"
  ldflags="-fsanitize=$SANITIZE"
fi
if ! make -C "$source_dir" -j2 COPTS=-DNO_ID CFLAGS="$flags" LDFLAGS="$ldflags" >> "$work/build.log" 2>&1; then
  cat "$work/build.log" >&2
  exit 1
fi
objcopy --redefine-sym main=dnsmasq_main "$source_dir/src/dnsmasq.o" "$work/main.o"
objcopy --redefine-sym check_servers=dnsmasq_check_servers "$source_dir/src/network.o" "$work/network.o"
if [ "$glinet" = 1 ]; then
  objcopy --redefine-sym setsockopt=guardian_test_setsockopt "$work/network.o"
  flags="$flags -DGUARDIAN_TEST_GLINET"
fi
objcopy --redefine-sym regcomp=guardian_test_regcomp --redefine-sym regfree=guardian_test_regfree \
  --redefine-sym regexec=guardian_test_regexec \
  "$source_dir/src/domain-match.o" "$work/domain-match.o"
objcopy --redefine-sym whine_malloc=guardian_test_option_malloc "$source_dir/src/option.o" "$work/option.o"
set --
for object in "$source_dir"/src/*.o; do
  case "$object" in
    */dnsmasq.o|*/network.o|*/domain-match.o|*/option.o) continue ;;
  esac
  set -- "$@" "$object"
done
# Word splitting of compiler flag lists is intentional.
# shellcheck disable=SC2086
cc $flags -DNO_ID -I "$source_dir/src" "$suite_dir/test-domain-match.c" \
  "$work/main.o" "$work/network.o" "$work/domain-match.o" "$work/option.o" "$@" $ldflags -o "$work/test-domain-match"
mkdir "$work/state"
ASAN_OPTIONS=detect_leaks=0 "$work/test-domain-match" "$work/state"
"$source_dir/src/dnsmasq" --test --conf-file="$work/state/main.conf"
printf '%s\n' 'server=/regex:[unterminated/127.0.0.1#2053' > "$work/invalid.conf"
if "$source_dir/src/dnsmasq" --test --conf-file="$work/invalid.conf" > "$work/invalid.log" 2>&1; then
  echo 'Malformed regex was accepted' >&2
  exit 1
fi
"$source_dir/src/dnsmasq" --version | rg 'regex-server'
if [ "$glinet" = 1 ]; then
  "$source_dir/src/dnsmasq" --help | rg -- '--mark=<hex>.*Specify the outgoing packet mark'
  for mark in 0 0x1000 FFFFFFFF; do
    "$source_dir/src/dnsmasq" --test --conf-file=/dev/null --mark="$mark"
  done
  for mark in '' 0x100000000 -1 +1 0xxyz '0x1000 trailing'; do
    if "$source_dir/src/dnsmasq" --test --conf-file=/dev/null --mark="$mark" > "$work/mark.log" 2>&1; then
      echo "Malformed mark was accepted: $mark" >&2
      exit 1
    fi
  done
fi
echo 'PASS: native syntax and capability checks'
