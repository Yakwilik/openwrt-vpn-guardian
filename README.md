# OpenWrt VPN Guardian

Selective IPv4 VPN routing for OpenWrt. Send chosen domains and IP ranges through v2rayA, automatically switch unhealthy VPN nodes, and manage connections from a local dashboard. Ordinary traffic stays direct when the VPN backend fails.

**Development status:** install from source. The OpenWrt IPK workflow is disabled until release.

## Install on GL-MT6000

Tested with OpenWrt 24.10.4 and v2rayA 2.5.8. Guardian requires the SQLite-based v2rayA database format.

You need Go 1.23+, Git and Make on your computer, plus root SSH access to the router. Run the commands below in the same terminal on your computer. Change the router address if needed.

### 1. Build

~~~sh
git clone https://github.com/Yakwilik/openwrt-vpn-guardian.git
cd openwrt-vpn-guardian
make linux-arm64
~~~

This produces a static Linux/ARM64 binary with *CGO_ENABLED=0*.

### 2. Install router dependencies

Use package feeds matching your router firmware.

~~~sh
ROUTER=root@192.168.8.1
ssh "$ROUTER" '
  opkg update &&
  opkg install v2raya xray-core v2ray-geosite ca-bundle \
    ip-full nftables-json kmod-nft-tproxy
'
~~~

### 3. Copy the binary and service files

~~~sh
scp -O dist/vpn-guardian-linux-arm64 "$ROUTER:/usr/bin/vpn-guardian.new"
COPYFILE_DISABLE=1 tar -C package/openwrt/files -cf - etc |
  ssh "$ROUTER" 'tar -C / -xf -'
ssh "$ROUTER" '
  set -e
  chmod 755 /usr/bin/vpn-guardian.new \
    /etc/init.d/vpn-guardian-api \
    /etc/init.d/vpn-guardian-bootstrap \
    /etc/hotplug.d/iface/99-vpn-front-routing
  mv -f /usr/bin/vpn-guardian.new /usr/bin/vpn-guardian
  /etc/init.d/vpn-guardian-bootstrap enable
  /etc/init.d/vpn-guardian-bootstrap start
'
~~~

Bootstrap detects the network, creates configuration, prepares v2rayA and starts the dashboard. Once a VPN node works, it activates routing, runs the self-test and enables services at boot.

### 4. Connect a VPN node and check the result

Open [v2rayA](http://192.168.8.1:2017/). On first use, create an account, import a subscription, select a node and click **Start**. Guardian configures v2rayA for backend-only operation; leave its transparent proxy disabled.

Until the VPN backend is usable, bootstrap keeps ordinary routing active and retries every 15 seconds.

~~~sh
ssh "$ROUTER" 'tail -n 30 /tmp/vpn-guardian-bootstrap.log'
~~~

Wait for *bootstrap OK*, then verify:

~~~sh
ssh "$ROUTER" 'vpn-guardian status && vpn-guardian selftest'
~~~

## Dashboard

Open [http://192.168.8.1:20175/](http://192.168.8.1:20175/) from the router's LAN. Use **Режим управления** to manage nodes and subscriptions and set a management PIN.

With nginx already installed, the supplied virtual host also serves [http://vpn.home.arpa/](http://vpn.home.arpa/). nginx is optional. Use HTTP: HTTPS may open the stock GL.iNet admin page.

VPN-only is the default: backend failure blocks only VPN traffic. If the shared front itself fails, interception stays enabled until automatic recovery. See the [architecture](docs/architecture.md) for details.

## Routing configuration

Bootstrap creates these files on the router:

| File | Purpose |
|---|---|
| */etc/vpn-guardian/routing.json* | Domains and IP ranges to route through VPN |
| */etc/vpn-guardian/stack.json* | Interfaces, ports and routing settings |

Edit the manifests, then validate and apply:

~~~sh
ssh "$ROUTER" 'vpn-guardian validate && vpn-guardian apply'
~~~

Apply creates a backup and rolls back on failure. [Configuration examples](configs/) · [Router validation](docs/validation/) · [Release checklist](docs/release-checklist.md)
