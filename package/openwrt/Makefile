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
  DEPENDS:=$(GO_ARCH_DEPENDS) +v2raya +xray-core +ca-bundle +ip-full +nftables
endef
define Package/vpn-guardian/description
 Selective VPN routing, health monitoring and automatic v2rayA failover.
 Direct traffic remains independent from VPN backend health.
endef

define Package/vpn-guardian/conffiles
/etc/vpn-stack/stack.json
/etc/vpn-stack/routing.json
endef

define Package/vpn-guardian/install
	$(call GoPackage/Package/Install/Bin,$(1))
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(GO_PKG_BUILD_BIN_DIR)/vpn-guardian $(1)/usr/bin/vpn-guardian
	$(LN) vpn-guardian $(1)/usr/bin/vpn-stack
	$(LN) vpn-guardian $(1)/usr/bin/vpn-selftest
	$(LN) vpn-guardian $(1)/usr/bin/vpn-backend-watchdog
	$(LN) vpn-guardian $(1)/usr/bin/v2raya-failover

	$(INSTALL_DIR) $(1)/etc/vpn-stack
	$(INSTALL_CONF) ./files/etc/vpn-stack/stack.json $(1)/etc/vpn-stack/stack.json
	$(INSTALL_CONF) ./files/etc/vpn-stack/routing.json $(1)/etc/vpn-stack/routing.json
endef

$(eval $(call BuildPackage,vpn-guardian))
