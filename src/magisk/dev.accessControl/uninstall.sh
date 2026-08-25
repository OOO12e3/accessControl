#!/system/bin/sh

# Runtime policy changes disappear on reboot. Persistent configuration is
# module-owned and is removed when the user uninstalls the module.
CONFIG_DIR=/data/adb/dev.accessControl

if [ -d "$CONFIG_DIR" ]; then
    rm -rf "$CONFIG_DIR"
fi
