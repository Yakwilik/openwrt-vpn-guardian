#!/bin/sh
# Run explicitly on a test router, from an independent management connection.
# Requires ip-full, veth/netns, curl, jsonfilter and the corectl test helper.
# Stops the VPN core and front briefly; never enables fail-open.
set -eu
: "${TEST_ADDRESS:?Set an unused LAN address with prefix, e.g. 192.168.8.250/24}"
CORECTL=${CORECTL:-/tmp/vg-corectl}
config=/etc/vpn-guardian/stack.json
lan=$(jsonfilter -i "$config" -e '@.lanInterface')
front_port=$(jsonfilter -i "$config" -e '@.front.tproxyPort')
backend_port=$(jsonfilter -i "$config" -e '@.backend.socksPort')
gateway=$(ip -4 -o addr show dev "$lan" | awk '{split($4,a,"/"); print a[1]; exit}')
address=${TEST_ADDRESS%/*}
ns=vg-acceptance
host=vg-test-host
peer=vg-test-peer
work=$(mktemp -d /tmp/vg-acceptance.XXXXXX)
chmod 700 "$work"
core_off=0
front_off=0
namespace_created=0

cleanup() {
  if [ "$core_off" = 1 ]; then "$CORECTL" start >/dev/null 2>&1 || :; fi
  if [ "$front_off" = 1 ]; then /etc/init.d/vpn-front start >/dev/null 2>&1 || :; fi
  if [ "$core_off" = 1 ] || [ "$front_off" = 1 ]; then /etc/init.d/vpn-backend-watchdog start >/dev/null 2>&1 || :; fi
  if [ "$namespace_created" = 1 ]; then
    ip link del "$host" 2>/dev/null || :
    ip netns del "$ns" 2>/dev/null || :
    rm -f /etc/netns/vg-acceptance/resolv.conf
    rmdir /etc/netns/vg-acceptance 2>/dev/null || :
  fi
  rm -rf "$work"
}
trap cleanup EXIT
trap 'exit 130' INT TERM
fail() { echo "FAIL: $*" >&2; exit 1; }
listening() {
  port=$(printf '%04X' "$1")
  grep -qi ":$port .* 0A " /proc/net/tcp /proc/net/tcp6
}
lan_curl() { ip netns exec "$ns" curl -4 --noproxy '*' --connect-timeout 3 --max-time 8 "$@"; }
trace_ip() { sed -n 's/^ip=//p' "$1" | tr -d '\r'; }
guard() { nft list table inet vpn_front >/dev/null 2>&1 && ip rule show | grep -q '^5:.*lookup '; }

[ -x "$CORECTL" ] || fail 'corectl helper missing'
[ "$(cat /etc/vpn-guardian/policy-mode)" = killswitch ] || fail 'requires VPN-only mode'
[ ! -e /var/run/netns/"$ns" ] || fail 'test namespace already exists'
[ ! -e /etc/netns/vg-acceptance ] || fail 'test resolver directory already exists'
if grep -q " $address " /tmp/dhcp.leases || ping -c 1 -W 1 "$address" >/dev/null 2>&1; then fail 'test address is in use'; fi
ip netns add "$ns"
namespace_created=1
ip link add "$host" type veth peer name "$peer"
ip link set "$peer" netns "$ns"
ip link set "$host" master "$lan"
ip link set "$host" up
ip -n "$ns" link set lo up
ip -n "$ns" link set "$peer" up
ip -n "$ns" addr add "$TEST_ADDRESS" dev "$peer"
ip -n "$ns" route add default via "$gateway"
mkdir -p /etc/netns/vg-acceptance
printf 'nameserver %s\n' "$gateway" > /etc/netns/vg-acceptance/resolv.conf
sleep 1

echo '=== Baseline from the virtual LAN client ==='
lan_curl -fsS http://vpn.home.arpa/healthz > "$work/health"
[ "$(jsonfilter -i "$work/health" -e '@.ok')" = true ] || fail 'dashboard health'
lan_curl -fsS "http://$gateway/" -o "$work/admin"
home=$(lan_curl -fsS --retry 1 https://icanhazip.com | tr -d '\r\n')
lan_curl -fsS https://chatgpt.com/cdn-cgi/trace > "$work/trace"
vpn=$(trace_ip "$work/trace")
[ -n "$home" ] && [ -n "$vpn" ] && [ "$home" != "$vpn" ] || fail 'direct/VPN paths not separated'
echo "PASS LAN dashboard/admin; direct=$home; VPN=$vpn"

echo '=== Dashboard write while watchdog is running ==='
lan_curl -fsS http://vpn.home.arpa/api/control > "$work/control"
if [ "$(jsonfilter -i "$work/control" -e '@.authConfigured')" = false ]; then
  lan_curl -fsS -c "$work/cookie" -H 'Content-Type: application/json' -H 'X-VPN-Unlock: 1' --data '{"action":"login"}' http://vpn.home.arpa/api/control > "$work/login"
  csrf=$(jsonfilter -i "$work/login" -e '@.csrf')
  [ -n "$csrf" ] || fail 'login did not return CSRF token'
  lan_curl -fsS --max-time 15 -b "$work/cookie" -H 'Content-Type: application/json' -H "X-VPN-CSRF: $csrf" --data '{"action":"killswitch","enabled":true}' http://vpn.home.arpa/api/control > "$work/write"
  [ "$(jsonfilter -i "$work/write" -e '@.ok')" = true ] || fail 'dashboard write'
  lan_curl -fsS -b "$work/cookie" -H 'Content-Type: application/json' -H "X-VPN-CSRF: $csrf" --data '{"action":"logout"}' http://vpn.home.arpa/api/control >/dev/null
  echo 'PASS management write completed with watchdog running'
else
  echo 'SKIP management write: PIN already configured; test does not bypass authentication'
fi

echo '=== Core stop: same API operation as the v2rayA Stop button ==='
/etc/init.d/vpn-backend-watchdog stop
core_off=1
"$CORECTL" stop
if listening "$backend_port"; then fail 'core listener remained after stop'; fi
[ "$(lan_curl -fsS https://icanhazip.com | tr -d '\r\n')" = "$home" ] || fail 'direct traffic broke while core stopped'
if lan_curl --max-time 3 -fsS https://chatgpt.com/cdn-cgi/trace > "$work/closed" 2>"$work/error"; then fail 'proxy request succeeded with core stopped'; fi
guard || fail 'VPN-only guard disappeared'
lan_curl -fsS http://vpn.home.arpa/healthz >/dev/null
echo 'PASS core stopped: direct works, proxy fails closed, dashboard accessible'
started=$(date +%s)
/etc/init.d/vpn-backend-watchdog start
until listening "$backend_port"; do
  [ $(($(date +%s)-started)) -le 50 ] || fail 'core recovery timeout'
  sleep 1
done
core_off=0
echo "PASS core recovered in $(($(date +%s)-started)) seconds"
lan_curl -fsS --retry 1 https://chatgpt.com/cdn-cgi/trace > "$work/restored"
[ "$(trace_ip "$work/restored")" != "$home" ] || fail 'VPN recovered as direct'

echo '=== Front stop: retain interception and let watchdog restart it ==='
front_off=1
/etc/init.d/vpn-front stop
started=$(date +%s)
guard || fail 'guard missing immediately after front stop'
lan_curl -fsS http://vpn.home.arpa/healthz >/dev/null
if lan_curl --max-time 1 -fsS https://chatgpt.com/cdn-cgi/trace > "$work/front-closed" 2>"$work/error"; then
  [ "$(trace_ip "$work/front-closed")" != "$home" ] || fail 'front failure leaked directly'
fi
until listening "$front_port"; do
  guard || fail 'guard lost during front recovery'
  [ $(($(date +%s)-started)) -le 35 ] || fail 'front recovery timeout'
  sleep 1
done
front_off=0
guard || fail 'guard missing after recovery'
echo "PASS front recovered in $(($(date +%s)-started)) seconds with interception retained"
lan_curl -fsS --retry 1 https://chatgpt.com/cdn-cgi/trace > "$work/front-restored"
[ "$(trace_ip "$work/front-restored")" != "$home" ] || fail 'wrong egress after front recovery'
[ "$(lan_curl -fsS https://icanhazip.com | tr -d '\r\n')" = "$home" ] || fail 'direct did not recover'
echo 'PASS final direct/VPN split'
echo 'ACCEPTANCE PASS'
