#!/system/bin/sh

MODDIR=${0%/*}

echo "Reloading access-control rules..."
"$MODDIR/bin/service" reload
result=$?
case "$result" in
    0) echo "Reload completed." ;;
    2) echo "Reload skipped." ;;
    *) echo "Reload failed; inspect /data/adb/dev.accessControl/access-control.log" ;;
esac
echo
"$MODDIR/bin/service" status
