#
# Copyright 2008 Steven Barth <steven@midlink.org>
# Copyright 2008 Jo-Philipp Wich <jow@openwrt.org>
# Copyright 2019 Hostle <hostle19@gmail.com>
#
# This is free software, licensed under the Apache License, Version 2.0
# Multi-user application for luci
# Added new functions for compatibility for openwrt-19.07 tree 
# Hostle 2/7/2019 <hostle19@gmail.com>

include $(TOPDIR)/rules.mk

# PKG_NAME:=luci-app-multi-user

PKG_VERSION:=3.0.0
PKG_DEPENDS:= libuci libuci-lua
PKG_RELEASE:=6

PKG_LICENSE:=Apache-2.0
PKG_MAINTAINER:=Hostle <hostle19@gmail.com>

# LuCI specific settings
LUCI_TITLE:=LuCI Multi User Support
LUCI_DEPENDS:=+luci-mod-admin-full
# LUCI_PKGARCH:=all

define Package/$(PKG_NAME)/config
# shown in make menuconfig <Help>
help
	$(LUCI_TITLE)
	Version: $(PKG_VERSION)-$(PKG_RELEASE)
endef

include ../../luci.mk

# call BuildPackage - OpenWrt buildroot signature
