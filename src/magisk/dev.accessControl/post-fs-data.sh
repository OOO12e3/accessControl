#!/system/bin/sh

MODDIR=${0%/*}

# This runs before Zygote and before Magisk mounts module files. The core first
# loads the generated domain policy, then prepares the seapp_contexts overlay.
"$MODDIR/bin/service" prepare
