include $(TOPDIR)/rules.mk

PKG_NAME:=vpn-guardian
PKG_VERSION:=0.1.0
PKG_RELEASE:=1

PKG_SOURCE_PROTO:=git
PKG_SOURCE_URL:=https://github.com/Yakwilik/openwrt-vpn-guardian.git
# CI and SDK builds must supply the immutable commit being packaged.
PKG_SOURCE_VERSION:=
PKG_MIRROR_HASH:=skip

PKG_MAINTAINER:=Yakwilik
PKG_LICENSE:=MIT
PKG_LICENSE_FILES:=LICENSE

PKG_BUILD_DEPENDS:=golang/host
PKG_BUILD_PARALLEL:=1
PKG_BUILD_FLAGS:=no-mips16

GO_PKG:=github.com/Yakwilik/openwrt-vpn-guardian
GO_PKG_BUILD_PKG:=$(GO_PKG)/cmd/vpn-guardian
GO_PKG_INSTALL_EXTRA:=internal/api/web/.*
PKG_ASLR_PIE:=0

include $(INCLUDE_DIR)/package.mk
include $(TOPDIR)/feeds/packages/lang/golang/golang-package.mk

# vpn-guardian is pure Go. OpenWrt still supplies the target GOOS/GOARCH
# values, but CGO and the external C linker are deliberately disabled.
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
  DEPENDS:=$(ARCH_DEPENDS) +xray-core +v2ray-geosite +ca-bundle +ip-full +kmod-nft-tproxy +nftables-json
  EXTRA_DEPENDS:=v2raya (>=2.5.8)
endef

define Package/vpn-guardian/description
 Selective VPN routing, health monitoring and automatic v2rayA failover.
 Direct traffic remains independent from VPN backend health.
endef

define Package/vpn-guardian/conffiles
/etc/vpn-guardian/
endef

define Build/Prepare
	@printf '%s\n' "$(PKG_SOURCE_VERSION)" | grep -Exq '[0-9a-f]{40}' || { echo 'PKG_SOURCE_VERSION must be a full commit hash' >&2; exit 1; }
	$(call Build/Prepare/Default)
endef

define Package/vpn-guardian/install
	$(call GoPackage/Package/Install/Bin,$(1))

	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/etc/init.d/vpn-guardian-api $(1)/etc/init.d/vpn-guardian-api
	$(INSTALL_BIN) ./files/etc/init.d/vpn-guardian-bootstrap $(1)/etc/init.d/vpn-guardian-bootstrap

	$(INSTALL_DIR) $(1)/etc/hotplug.d/iface
	$(INSTALL_BIN) ./files/etc/hotplug.d/iface/99-vpn-front-routing $(1)/etc/hotplug.d/iface/99-vpn-front-routing

	# Optional GL.iNet/OpenWrt nginx integration. nginx is not a dependency;
	# vpn-guardian serves the same UI directly on LAN port 20175.
	$(INSTALL_DIR) $(1)/etc/nginx/conf.d
	$(INSTALL_CONF) ./files/etc/nginx/conf.d/vpn-guardian.conf $(1)/etc/nginx/conf.d/vpn-guardian.conf

	$(INSTALL_DIR) $(1)/usr/share/vpn-guardian/examples
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/configs/stack.example.json $(1)/usr/share/vpn-guardian/examples/stack.json
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/configs/routing.example.json $(1)/usr/share/vpn-guardian/examples/routing.json
endef

define Package/vpn-guardian/postinst
#!/bin/sh
[ -n "$$IPKG_INSTROOT" ] && exit 0

echo 'VPN Guardian installed. Run: vpn-guardian init'
echo 'Setup verifies dependencies and configuration before enabling routing.'

exit 0
endef

define Package/vpn-guardian/prerm
#!/bin/sh
[ -n "$$IPKG_INSTROOT" ] && exit 0
[ "$$PKG_UPGRADE" = "1" ] && exit 0

/usr/bin/vpn-guardian cleanup >/dev/null 2>&1 || true

for svc in vpn-guardian-bootstrap vpn-guardian-api vpn-dashboard-collector vpn-backend-watchdog vpn-front-routing vpn-front vpn-policy; do
	[ -x "/etc/init.d/$$svc" ] || continue
	"/etc/init.d/$$svc" disable >/dev/null 2>&1 || true
	"/etc/init.d/$$svc" stop >/dev/null 2>&1 || true
done

exit 0
endef

define Package/vpn-guardian/postrm
#!/bin/sh
[ -n "$$IPKG_INSTROOT" ] && exit 0
[ "$$PKG_UPGRADE" = "1" ] && exit 0

for svc in vpn-front-routing vpn-backend-watchdog vpn-dashboard-collector vpn-front vpn-policy; do
	rm -f "/etc/init.d/$$svc"
done

if [ -x /etc/init.d/dnsmasq ]; then
	uci -q delete dhcp.vpn_guardian
	uci -q commit dhcp
	/etc/init.d/dnsmasq reload >/dev/null 2>&1 || true
fi

[ -x /etc/init.d/nginx ] && /etc/init.d/nginx reload >/dev/null 2>&1 || true

exit 0
endef

$(eval $(call BuildPackage,vpn-guardian))
