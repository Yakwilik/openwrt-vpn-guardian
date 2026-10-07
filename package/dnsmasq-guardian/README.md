# Native dnsmasq selectors for VPN Guardian

This package extends the native OpenWrt dnsmasq process. Ordinary DNS queries,
local records, DHCP and upstream selection stay inside dnsmasq. Only names
selected by the proxy policy are forwarded to Guardian's loopback DNS port.

## Source and packaging

The vendored recipe is OpenWrt v24.10.4
<https://github.com/openwrt/openwrt/tree/v24.10.4/package/network/services/dnsmasq>,
with the complete upstream security update
<https://github.com/openwrt/openwrt/commit/15250e11aa4e77e47cee3afca0625fca02c97917>
which raises dnsmasq 2.90 from release 4 to release 5 and adds six CVE fixes.
The complete upstream files, init script, configuration files and native patch
set are preserved as the baseline. Their checksums are recorded in
"upstream.sha256". GL.iNet also used the revision "2.90-r5" in older firmware;
that vendor revision does not identify the later OpenWrt security commit.

The dnsmasq 2.90 source archive SHA-256 is
"8e50309bd837bfec9649a812e066c09b6988b73d749b7d293c06c57d46a109e4".
The OpenWrt security-update commit patch SHA-256 is
"a4530cca3f6b757c56eb30143799ce05576b96cd0c5079251c08c33e0216ef0a".

The generated package retains the native name "dnsmasq-full" and uses revision
"2.90-5.1". It adds no shared-library dependency: POSIX regular expressions and
locale support come from libc. The 24.10.4 SDK uses libubox ABI 20240329,
libubus ABI 20250102, libnettle ABI 8 and libnetfilter-conntrack ABI 3.

### GL.iNet compatibility

The optional "--glinet" build mode applies two small compatibility changes.
The init patch retains the observed UCI user/group overrides and jail mounts
for the four VPN resolver files. Applying it to the pinned upstream init
script reproduces the inspected device's init script byte for byte.

The C patch provides "--mark=<hex>" and the equivalent "mark=0x1000" config
entry. This is an independent implementation of the interface observed on
the device, not a retrieved GL.iNet source patch. A nonzero mark is set on
every outgoing DNS UDP and TCP socket, for IPv4 and IPv6. It takes precedence
over per-client conntrack marks; an absent or zero mark retains the upstream
conntrack behavior. A failed SO_MARK call prevents an unmarked DNS send.
NET_ADMIN is retained when a nonzero mark is configured, including after the
normal privilege drop. Listening sockets, replies and DHCP are unaffected.

The compatibility patch adds no fixed router mark, resolver or network
configuration. The existing instance configuration supplies the value.

## Release artifacts

The release pipeline cross-compiles two independent package variants for each
OpenWrt 24.10.4 SDK target: `dnsmasq-full_2.90-r5.1_<arch>.openwrt.ipk`
and `dnsmasq-full_2.90-r5.1_<arch>.glinet.ipk`. **Install only one**,
according to the firmware's dnsmasq init/marking contract. Both archives
declare the same opkg package name `dnsmasq-full` internally; the filename
suffix is for human selection, not an additional package name.

Releases also include `dnsmasq-2.90.tar.xz` and its checksum, the exact
pinned recipe and security/feature patches in the tagged repository, and a
per-variant IPK checksum and build-provenance report. Installing either variant
requires matching target architecture, package libraries and OpenWrt 24.10.4
firmware feeds; neither variant is a universal binary for all OpenWrt devices.

## Selector contract

A regex upstream selector is written in the ordinary servers file:

~~~text
server=/regex:^github-production-release-asset-[0-9a-zA-Z]{6}\.s3\.amazonaws\.com$/127.0.0.1#2053
server=/regex:^chatgpt-async-webps-prod-[^ ]+-[0-9]+\.webpubsub\.azure\.com$/127.0.0.1#2053
~~~

The pattern is a POSIX extended regular expression. It is compiled once per
configuration read with REG_EXTENDED and REG_NOSUB, in the C locale. There is
no implicit REG_ICASE or REG_NEWLINE. Invalid patterns fail validation.
The prefix "regex:" is reserved for this extension. It accepts an upstream
address; it cannot be used for a local answer, an address override or a
standard-upstream "#" exception.

The pattern is tested against the lowercase escaped presentation of the DNS
question name, without its trailing root dot. This matches the previous
miekg/dns name representation used by Guardian. Non-printable and non-ASCII
bytes become decimal escapes; embedded label dots and other DNS presentation
special characters retain their escapes. An escaped space contains a literal
space, so on this representation the exact translation of RE2 "\S" is
"[^ ]". There is no implicit conversion of arbitrary RE2 expressions in C;
Guardian's compiler must reject unsupported expressions.

The config delimiters "/" and "#", double quotes, control bytes and bytes
outside printable ASCII are not supported inside a pattern. Interior ASCII
spaces are preserved. Guardian also limits the generated expression size to
fit a native configuration line. Matching never alters the original DNS
question or answer.

Domain selectors use actual DNS label boundaries. An embedded label dot,
represented as "\." in escaped presentation, is not a boundary for a Domain
rule. Regex selectors retain their escaped-presentation semantics, so an
expression explicitly matching a dot can also match that presentation dot.
The compiler must preserve this distinction when deciding whether a regex
can be represented by a native suffix rule.

The native suffix search and local overrides run first. Explicit local,
private/split-horizon upstreams, standard-upstream guards and address rules
retain precedence. Regex rules only replace the ordinary default upstream.
Matching regex groups use their declaration order; multiple upstreams for
one identical expression preserve the existing dnsmasq server-group behavior.

In extended mode, exact-only proxy names must be emitted as anchored regexes.
Do not combine synthetic subdomain "#" exclusions with regex rules: such a
native exclusion would have intentional precedence over a matching regex.

The capability marker "regex-server" is present in the compile-time options
from "dnsmasq --version". Check this marker before applying a file containing
regex selectors. An unpatched dnsmasq can accept "regex:" as a literal domain;
a successful syntax check alone does not prove support.

## Reload and ownership

The extension uses the native "servers-file" reader. Every accepted
regex is compiled during the file read. A replacement frees its old compiled
expression, and server deletion frees both the expression and its allocation.
The regex groups occupy a separate tail of the native server array and never
participate in the suffix binary search.

Syntax validation must precede atomic publication and reload. Use
"dnsmasq --test --conf-file=STAGED_FILE" with a restricted generated grammar;
"--test --servers-file=STAGED_FILE" does not read the server file in dnsmasq
2.90 and therefore does not validate it. The native
servers-file reader stages a complete candidate without mutating active
records. Server-array growth is reserved before commit. A parse, read, allocation
or compilation failure discards the candidate and
retains the previous active policy. This also covers daemon-side allocation
failure after successful validation in a separate process. A regex execution
error refuses the DNS query instead of treating the error as a non-match and
using a direct upstream. Guardian must keep the last valid file when its own
compilation or validation fails.

Patch 991 adds a synchronous UBus "reload_servers" method and the additional
compile-time marker "regex-server-ack" when UBus is enabled. A successful
response means the daemon committed the complete candidate, retired previous
TCP workers and outstanding UDP consumers, and invalidated its cache. A
read/parse/compile/allocation rejection returns an error and retains the
active policy. Guardian uses this acknowledgement before removing transitional
matching rules. SIGHUP remains available for ordinary native reloads; sending
a signal alone is not an acknowledgement that the new policy is active.

## Build

The SDK and its package dependencies must be prepared first. To install just
the pinned recipe and patch into an existing SDK:

~~~sh
./build-openwrt.sh /path/to/openwrt-sdk --prepare-only
./build-openwrt.sh /path/to/openwrt-sdk --prepare-only --glinet
~~~

Select the native "dnsmasq-full" variant in the SDK, retaining the features
installed on the destination device, then build:

~~~sh
JOBS=2 ./build-openwrt.sh /path/to/openwrt-sdk
JOBS=2 ./build-openwrt.sh /path/to/openwrt-sdk --glinet
~~~

The build helper keeps a copy of the SDK's original dnsmasq recipe outside the
package search tree. It does not install anything on a router or rewrite the
router configuration. The resulting package must be inspected for target
architecture, dependencies and compile-time features before deployment.

## Verification

The host suite uses the real dnsmasq config parser, server groups, name
matching and reload cleanup. Network discovery is replaced only inside the
test harness, so it can run in an environment where listening sockets are
unavailable. It checks direct/proxy/private/local selection, exact boundaries,
the two production regexes, name escaping, declaration order, multiple
upstreams, removal/replacement, an empty native array and 100 reload cycles.
Fault injection covers libc compilation/execution failures and server-array growth; independent libc
handle accounting checks that every successfully compiled regex is freed.

~~~sh
./tests/test-host.sh /path/to/dnsmasq-2.90
SANITIZE=address,undefined ./tests/test-host.sh /path/to/dnsmasq-2.90
./tests/test-host.sh /path/to/dnsmasq-2.90 --glinet
./tests/test-reload-ack.sh /path/to/dnsmasq-2.90 /path/to/sdk/staging_dir/target-architecture/usr/include
~~~

The separate acknowledgement suite builds the actual UBus callback with the
SDK headers and the host C compiler. No host libubus library is required. It
checks that a rejected candidate leaves existing consumers intact, while an
accepted candidate waits for a child to exit, closes its cache pipe, cancels
outstanding UDP consumers and flushes the cache.

The daemon transport suite uses loopback-only listeners and records which of
three independent upstreams received each DNS query. It must be run in an
environment that permits native listening sockets. It starts no DHCP range
and cleans up its child processes and temporary files on exit.

~~~sh
go run ./tests/transport/main.go /path/to/native/dnsmasq
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -o transport-arm64 ./tests/transport/main.go
~~~

The transport runner takes the dnsmasq binary path as its only argument. It
checks UDP and TCP requests, A/AAAA/TXT routing, local records, proxy boundary
negatives, eight SIGHUP cycles, a rejected malformed reload and continued direct DNS when the protected
upstream becomes unavailable. Packet counters must show zero queries at the
wrong upstream. On a restricted host dnsmasq may be unable to open its native
netlink socket; that is an environment limitation, not a transport-test pass.

Setting the optional environment variable "DNSMASQ_TEST_MARK=0x1000" makes
the transport runner pass that mark to its isolated native instance. This
allows external packet-mark counters to verify both UDP and TCP without
starting or changing a real VPN instance. The host GL.iNet test variant also
checks hexadecimal parsing, IPv4/IPv6 UDP/TCP socket marking, zero-mark
behavior and refusal after a socket-mark failure. Its socket-option syscall
is mocked; native packet counters provide the separate transport evidence.

Set "DNSMASQ_TEST_UBUS=dnsmasq.guardian-canary" to exercise the actual UBus
reload method instead of SIGHUP. The runner requires the acknowledgement
capability, refuses an existing object and restricts its object name to the
"dnsmasq.guardian-canary" namespace. It enables UBus only on its own temporary
instance. Every accepted reload must expose the new policy immediately after
the method returns; a malformed file must produce a UBus error and retain the
previous policy. This mode can be combined with "DNSMASQ_TEST_MARK".
