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

GO_PKG:=github.com/Yakwilik/openwrt-vpn-guardian
GO_PKG_BUILD_PKG:=$(GO_PKG)/cmd/vpn-guardian

include $(INCLUDE_DIR)/package.mk
include $(TOPDIR)/feeds/packages/lang/golang/golang-package.mk

define Package/vpn-guardian
  SECTION:=net
  CATEGORY:=Network
  SUBMENU:=VPN
  TITLE:=Selective VPN control plane for v2rayA
  DEPENDS:=$(GO_ARCH_DEPENDS) +v2raya +xray-core +ca-bundle +ip-full +nftables +nginx-ssl +fcgi
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

exit 0
endef

define Package/vpn-guardian/postinst
#!/bin/sh
[ -n "$$IPKG_INSTROOT" ] && exit 0

rm -f /etc/vpn-stack/bootstrap-complete
/etc/init.d/vpn-guardian-bootstrap enable >/dev/null 2>&1 || true
/etc/init.d/vpn-guardian-bootstrap restart >/dev/null 2>&1 || true

exit 0
endef

$(eval $(call BuildPackage,vpn-guardian))
