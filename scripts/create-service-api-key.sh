#!/bin/sh
set -eu

usage() {
  echo "Usage: $0 <router-ssh-target> [local-key-path]" >&2
  echo "Example: $0 root@192.168.1.90 ~/.config/vpn-guardian/assistant-api-key" >&2
  exit 2
}

[ "$#" -ge 1 ] && [ "$#" -le 2 ] || usage

router="$1"
output="${2:-$HOME/.config/vpn-guardian/assistant-api-key}"
remote_tmp="/tmp/vpn-guardian-service-api-key.$$"
output_dir=$(dirname "$output")
local_tmp="$output.tmp.$$"

cleanup() {
  rm -f "$local_tmp"
  ssh -o BatchMode=yes "$router" "rm -f '$remote_tmp'" >/dev/null 2>&1 || true
}
trap cleanup EXIT HUP INT TERM

if [ -e "$output" ]; then
  echo "Refusing to overwrite existing key: $output" >&2
  echo "Revoke/rotate it explicitly first if replacement is intended." >&2
  exit 1
fi

mkdir -p "$output_dir"
chmod 700 "$output_dir"

echo "Creating service API key on router..."
ssh -o BatchMode=yes "$router"   "set -e; umask 077; rm -f '$remote_tmp'; vpn-guardian api-key create --output '$remote_tmp'"

echo "Copying key to local protected file..."
umask 077
scp -O -q "$router:$remote_tmp" "$local_tmp"
chmod 600 "$local_tmp"

if ! grep -Eq '^[0-9a-f]{64}$' "$local_tmp"; then
  echo "Generated key has unexpected format." >&2
  exit 1
fi

mv "$local_tmp" "$output"
chmod 600 "$output"

echo "Verifying router key status..."
status=$(ssh -o BatchMode=yes "$router" "vpn-guardian api-key status")
[ "$status" = "configured" ] || {
  echo "Router reports unexpected API key status: $status" >&2
  exit 1
}

ssh -o BatchMode=yes "$router" "rm -f '$remote_tmp'"
trap - EXIT HUP INT TERM

echo "Service API key configured."
echo "Local key file: $output"
echo "The key value was not printed."
