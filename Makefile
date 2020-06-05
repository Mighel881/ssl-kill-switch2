include $(THEOS)/makefiles/common.mk

TWEAK_NAME = SSLKillSwitch2

$(TWEAK_NAME)_FILES = /mnt/d/codes/ssl-kill-switch2/SSLKillSwitch2.xm
$(TWEAK_NAME)_FRAMEWORKS = Security CydiaSubstrate

$(TWEAK_NAME)_CFLAGS = -fobjc-arc
$(TWEAK_NAME)_LDFLAGS = -Wl,-segalign,4000

export ARCHS = armv6 armv7 armv7s arm64 arm64e
$(TWEAK_NAME)_ARCHS = armv6 armv7 armv7s arm64 arm64e


include $(THEOS_MAKE_PATH)/tweak.mk
