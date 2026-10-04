include $(TOPDIR)/rules.mk

PKG_NAME:=vpn-guardian
PKG_VERSION:=0.1.0
PKG_RELEASE:=1

PKG_SOURCE_PROTO:=git
PKG_SOURCE_URL:=https://github.com/Yakwilik/openwrt-vpn-guardian.git
PKG_SOURCE_VERSION:=main
PKG_MIRROR_HASH:=skip

PKG_MAINTAINER:=Yakwilik
PKG_LICENSE:=MIT
PKG_LICENSE_FILES:=LICENSE

PKG_BUILD_DEPENDS:=golang/host
PKG_BUILD_PARALLEL:=1
PKG_BUILD_FLAGS:=no-mips16

GO_PKG:=github.com/Yakwilik/openwrt-vpn-guardian
GO_PKG_BUILD_PKG:=$(GO_PKG)/cmd/vpn-guardian

include $(INCLUDE_DIR)/package.mk
include $(TOPDIR)/feeds/packages/lang/golang/golang-package.mk

# vpn-guardian is pure Go. Force an internal-link, CGO-free target build so
# the package does not depend on the SDK libc ABI or a target C toolchain.
# GOOS/GOARCH/GOARM/GOMIPS continue to come from OpenWrt's Go helper.
GO_PKG_TARGET_VARS:=$(filter-out CGO_ENABLED=%,$(GO_PKG_TARGET_VARS)) CGO_ENABLED=0
GO_PKG_DEFAULT_LDFLAGS:=$(filter-out -linkmode external,$(GO_PKG_DEFAULT_LDFLAGS))

EMPTY:=
SPACE:=$(EMPTY) $(EMPTY)
ARCH_DEPENDS:=@($(subst $(SPACE),||,$(strip $(filter-out mips mips64 mipsel mips64el,$(subst ||,$(SPACE),$(patsubst @(%),%,$(GO_ARCH_DEPENDS)))))))

define Package/vpn-guardian
  SECTION:=net
  CATEGORY:=Network
  SUBMENU:=VPN
  TITLE:=Selective VPN control plane for v2rayA
  DEPENDS:=$(ARCH_DEPENDS) +v2raya +xray-core +v2ray-geosite +v2ray-geoip +ca-bundle +ip-full +kmod-nft-core +kmod-nft-socket +kmod-nft-tproxy +nftables-json +nginx-ssl
endef
define Package/vpn-guardian/description
 Selective VPN routing, health monitoring and automatic v2rayA failover.
 Direct traffic remains independent from VPN backend health.
endef

define Package/vpn-guardian/install
	$(call GoPackage/Package/Install/Bin,$(1))

	$(INSTALL_DIR) $(1)/usr/bin
	$(LN) vpn-guardian $(1)/usr/bin/vpn-stack
	$(LN) vpn-guardian $(1)/usr/bin/vpn-selftest
	$(LN) vpn-guardian $(1)/usr/bin/vpn-backend-watchdog
	$(LN) vpn-guardian $(1)/usr/bin/vpn-status-collector
	$(LN) vpn-guardian $(1)/usr/bin/v2raya-failover
	$(INSTALL_BIN) ./files/usr/bin/vpn-policy-mode $(1)/usr/bin/vpn-policy-mode

	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/etc/init.d/vpn-front $(1)/etc/init.d/vpn-front
	$(INSTALL_BIN) ./files/etc/init.d/vpn-policy $(1)/etc/init.d/vpn-policy
	$(INSTALL_BIN) ./files/etc/init.d/vpn-guardian-api $(1)/etc/init.d/vpn-guardian-api
	$(INSTALL_BIN) ./files/etc/init.d/vpn-guardian-bootstrap $(1)/etc/init.d/vpn-guardian-bootstrap

	$(INSTALL_DIR) $(1)/etc/hotplug.d/iface
	$(INSTALL_BIN) ./files/etc/hotplug.d/iface/99-vpn-front-routing $(1)/etc/hotplug.d/iface/99-vpn-front-routing

	$(INSTALL_DIR) $(1)/etc/nginx/conf.d
	$(INSTALL_CONF) ./files/etc/nginx/conf.d/vpn-guardian.conf $(1)/etc/nginx/conf.d/vpn-guardian.conf

	$(INSTALL_DIR) $(1)/etc/vpn-stack
	$(INSTALL_DIR) $(1)/usr/share/vpn-guardian/examples
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/configs/stack.example.json $(1)/usr/share/vpn-guardian/examples/stack.json
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/configs/routing.example.json $(1)/usr/share/vpn-guardian/examples/routing.json

	$(INSTALL_DIR) $(1)/www/vpn-dashboard
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/dashboard/index.html $(1)/www/vpn-dashboard/index.html

	$(INSTALL_DIR) $(1)/www/cgi-bin
	$(LN) ../../usr/bin/vpn-guardian $(1)/www/cgi-bin/vpn-status
	$(LN) ../../usr/bin/vpn-guardian $(1)/www/cgi-bin/vpn-history
	$(LN) ../../usr/bin/vpn-guardian $(1)/www/cgi-bin/vpn-control
endef

define Package/vpn-guardian/preinst
#!/bin/sh
[ -n "$$IPKG_INSTROOT" ] && exit 0

if [ -e /www/cgi-bin/vpn-control ] && [ ! -L /www/cgi-bin/vpn-control ] && [ ! -e /www/cgi-bin/vpn-control.legacy ]; then
	cp -p /www/cgi-bin/vpn-control /www/cgi-bin/vpn-control.legacy
fi

if [ -f /etc/nginx/conf.d/vpn-dashboard.conf ] && grep -q 'server_name vpn.home.arpa' /etc/nginx/conf.d/vpn-dashboard.conf; then
	mkdir -p /etc/vpn-stack/legacy
	cp -p /etc/nginx/conf.d/vpn-dashboard.conf /etc/vpn-stack/legacy/vpn-dashboard.conf
fi

exit 0
endef

define Package/vpn-guardian/postinst
#!/bin/sh
[ -n "$$IPKG_INSTROOT" ] && exit 0

if [ -f /etc/nginx/conf.d/vpn-dashboard.conf ] && grep -q 'server_name vpn.home.arpa' /etc/nginx/conf.d/vpn-dashboard.conf; then
	rm -f /etc/nginx/conf.d/vpn-dashboard.conf
fi

rm -f /etc/vpn-stack/bootstrap-complete
/etc/init.d/vpn-guardian-bootstrap enable >/dev/null 2>&1 || true
/etc/init.d/vpn-guardian-bootstrap restart >/dev/null 2>&1 || true

exit 0
endef

define Package/vpn-guardian/prerm
#!/bin/sh
[ -n "$$IPKG_INSTROOT" ] && exit 0

for svc in vpn-guardian-bootstrap vpn-guardian-api vpn-dashboard-collector vpn-backend-watchdog vpn-front-routing vpn-front vpn-policy; do
	[ -x "/etc/init.d/$$svc" ] || continue
	"/etc/init.d/$$svc" disable >/dev/null 2>&1 || true
	"/etc/init.d/$$svc" stop >/dev/null 2>&1 || true
done

rm -f /etc/vpn-front-enabled
exit 0
endef

define Package/vpn-guardian/postrm
#!/bin/sh
[ -n "$$IPKG_INSTROOT" ] && exit 0

uci -q delete dhcp.vpn_guardian
uci -q commit dhcp
/etc/init.d/dnsmasq reload >/dev/null 2>&1 || true
/etc/init.d/nginx reload >/dev/null 2>&1 || true

exit 0
endef

$(eval $(call BuildPackage,vpn-guardian))
