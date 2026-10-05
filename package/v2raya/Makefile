# SPDX-License-Identifier: GPL-3.0-only
# Packages the unmodified upstream release for the SQLite-based control API.
include $(TOPDIR)/rules.mk

PKG_NAME:=v2rayA
PKG_VERSION:=2.5.8
PKG_RELEASE:=1
PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz
PKG_SOURCE_URL:=https://codeload.github.com/v2rayA/v2rayA/tar.gz/refs/tags/v$(PKG_VERSION)?
PKG_HASH:=dfc0c113134728ef8c73ff8a7fea398103af1b9e38749437fed668d72985e601
PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)
PKG_LICENSE:=AGPL-3.0-only MPL-2.0
PKG_LICENSE_FILES:=LICENSE core/LICENSE
PKG_MAINTAINER:=Yakwilik

include $(INCLUDE_DIR)/package.mk

# Preserve upstream binaries byte for byte, including their Go build metadata.
RSTRIP:=:

V2RAYA_ARCH_aarch64_cortex-a53:=arm64
V2RAYA_ARCH_arm_cortex-a7_neon-vfpv4:=armv7
V2RAYA_ARCH_x86_64:=x64
V2RAYA_ARCH:=$(V2RAYA_ARCH_$(ARCH_PACKAGES))

V2RAYA_HASH_arm64:=0e537ce421042c636c3424f037e0880aa8e8a1569599a1852d391a1d85fd4213
V2RAYA_HASH_armv7:=8553a6d8046dae975fc12e73fc63e40c42ec70ed1a14e017ab7315a4186a267b
V2RAYA_HASH_x64:=e6b2441037c81162c2ab2e627a24b807e464bf937cc58b7a10b87e064b859af5
V2RAYA_CORE_HASH_arm64:=9dd97ff6ec2feec8a3089a2f86c1042b8bfb519f6aa22b5836b428b582421c8e
V2RAYA_CORE_HASH_armv7:=e763e8f61b0b61735112e4c0254632ac8551e6d4da440997c55679d9e19307f4
V2RAYA_CORE_HASH_x64:=f93638ae8310505215bcdb95be51e8c1af96e45e8b6ac214a83e9fcb7e052c99

V2RAYA_FILE:=v2raya_linux_$(V2RAYA_ARCH)_$(PKG_VERSION)
V2RAYA_CORE_FILE:=v2raya_core_linux_$(V2RAYA_ARCH)_$(PKG_VERSION)
V2RAYA_WEB_FILE:=v2raya-web-$(PKG_VERSION).tar.gz

define Download/v2raya-manager
  URL:=https://github.com/v2rayA/v2rayA/releases/download/v$(PKG_VERSION)
  URL_FILE:=$(V2RAYA_FILE)
  FILE:=$(V2RAYA_FILE)
  HASH:=$(V2RAYA_HASH_$(V2RAYA_ARCH))
endef

define Download/v2raya-core
  URL:=https://github.com/v2rayA/v2rayA/releases/download/v$(PKG_VERSION)
  URL_FILE:=$(V2RAYA_CORE_FILE)
  FILE:=$(V2RAYA_CORE_FILE)
  HASH:=$(V2RAYA_CORE_HASH_$(V2RAYA_ARCH))
endef

define Download/v2raya-web
  URL:=https://github.com/v2rayA/v2rayA/releases/download/v$(PKG_VERSION)
  URL_FILE:=web.tar.gz
  FILE:=$(V2RAYA_WEB_FILE)
  HASH:=bac5158511e3f3a2ece8ad93cb816331436de9b75fe8b4629a248b810e43554b
endef

define Package/v2raya
  TITLE:=v2rayA with matching v2raya_core
  SECTION:=net
  CATEGORY:=Network
  SUBMENU:=Web Servers/Proxies
  DEPENDS:=@(aarch64||arm||x86_64) +ca-bundle +kmod-nft-tproxy +v2ray-geosite +v2ray-geoip
  URL:=https://github.com/v2rayA/v2rayA/releases/tag/v$(PKG_VERSION)
endef

define Package/v2raya/description
 Unmodified v2rayA $(PKG_VERSION) manager, matching core and web interface.
 The upstream binaries and corresponding source are verified by SHA-256.
 The service stays disabled until explicitly configured.
endef

define Package/v2raya/conffiles
/etc/v2raya/
/etc/config/v2raya
endef

define Build/Prepare
	@test -n "$(V2RAYA_ARCH)" || { echo 'Unsupported v2rayA package architecture: $(ARCH_PACKAGES)' >&2; exit 1; }
	$(call Build/Prepare/Default)
	$(INSTALL_DIR) $(PKG_BUILD_DIR)/packaged-web
	$(HOST_TAR) -xzf $(DL_DIR)/$(V2RAYA_WEB_FILE) -C $(PKG_BUILD_DIR)/packaged-web --strip-components=1
endef

define Build/Configure
endef

define Build/Compile
endef

define Package/v2raya/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(DL_DIR)/$(V2RAYA_FILE) $(1)/usr/bin/v2raya
	$(INSTALL_BIN) $(DL_DIR)/$(V2RAYA_CORE_FILE) $(1)/usr/bin/v2raya_core

	$(INSTALL_DIR) $(1)/etc/config $(1)/etc/init.d
	$(INSTALL_CONF) ./files/v2raya.config $(1)/etc/config/v2raya
	$(INSTALL_BIN) ./files/v2raya.init $(1)/etc/init.d/v2raya

	$(INSTALL_DIR) $(1)/usr/share/v2raya/web
	$(CP) $(PKG_BUILD_DIR)/packaged-web/. $(1)/usr/share/v2raya/web/
	$(LN) ../v2ray/geosite.dat $(1)/usr/share/v2raya/geosite.dat
	$(LN) ../v2ray/geoip.dat $(1)/usr/share/v2raya/geoip.dat

	$(INSTALL_DIR) $(1)/usr/share/licenses/v2raya
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/LICENSE $(1)/usr/share/licenses/v2raya/LICENSE
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/core/LICENSE $(1)/usr/share/licenses/v2raya/CORE-LICENSE
	$(INSTALL_DATA) ./files/SOURCE.txt $(1)/usr/share/licenses/v2raya/SOURCE.txt
endef

$(eval $(call Download,v2raya-manager))
$(eval $(call Download,v2raya-core))
$(eval $(call Download,v2raya-web))
$(eval $(call BuildPackage,v2raya))
