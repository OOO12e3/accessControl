#!/system/bin/sh

CONFIG_DIR=${AC_CONFIG_DIR:-/data/adb/dev.accessControl}
RUNTIME_DIR=${AC_RUNTIME_DIR:-$CONFIG_DIR/run}
CONFIG_FILE=$CONFIG_DIR/default.conf
TARGET_FILE=$CONFIG_DIR/target.csv
LOG_FILE=$CONFIG_DIR/access-control.log
LOCK_DIR=$RUNTIME_DIR/apply.lock
APPLIED_HASH_FILE=$RUNTIME_DIR/applied.hash
ACTIVE_COUNT_FILE=$RUNTIME_DIR/active.count
PENDING_COUNT_FILE=$RUNTIME_DIR/pending.count
REBOOT_REQUIRED_FILE=$RUNTIME_DIR/reboot-required

MAGISKPOLICY=${AC_MAGISKPOLICY:-magiskpolicy}
SEAPP_SOURCE=${AC_SEAPP_SOURCE:-/system/etc/selinux/plat_seapp_contexts}
SEAPP_OVERLAY=${AC_SEAPP_OVERLAY:-$MODULE_DIR/system/etc/selinux/plat_seapp_contexts}

GENERATED_POLICY=$RUNTIME_DIR/generated.policy
GENERATED_SEAPP=$RUNTIME_DIR/generated.seapp_contexts
NORMALIZED_RULES=$RUNTIME_DIR/normalized.tsv
MAPPING_RULES=$RUNTIME_DIR/mappings.tsv
POLICY_DUMP=$RUNTIME_DIR/live-policy.rules
BASE_CLONE_POLICY=$RUNTIME_DIR/base-clone.policy
SEAPP_BASELINE=$RUNTIME_DIR/base-seapp_contexts

ac_timestamp() {
    date '+%Y-%m-%d %H:%M:%S' 2>/dev/null || date
}

rotate_log_if_needed() {
    [ -f "$LOG_FILE" ] || return 0
    max_bytes=$((${MAX_LOG_SIZE_KB:-256} * 1024))
    current_bytes=$(wc -c <"$LOG_FILE" 2>/dev/null)
    case "$current_bytes" in
        '' | *[!0-9]*) return 0 ;;
    esac
    if [ "$current_bytes" -gt "$max_bytes" ]; then
        mv -f "$LOG_FILE" "$LOG_FILE.1" 2>/dev/null || true
    fi
}

ac_log() {
    level=$1
    shift
    mkdir -p "$CONFIG_DIR" 2>/dev/null || true
    rotate_log_if_needed
    printf '%s [%s] %s\n' "$(ac_timestamp)" "$level" "$*" >>"$LOG_FILE" 2>/dev/null || true
}

trim_value() {
    printf '%s' "$1" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//'
}

configuration_hash() {
    {
        [ -f "$CONFIG_FILE" ] && cksum "$CONFIG_FILE"
        [ -f "$TARGET_FILE" ] && cksum "$TARGET_FILE"
    } 2>/dev/null | cksum | awk '{print $1 ":" $2}'
}

acquire_apply_lock() {
    mkdir -p "$RUNTIME_DIR" || return 1
    if mkdir "$LOCK_DIR" 2>/dev/null; then
        printf '%s\n' "$$" >"$LOCK_DIR/pid"
        return 0
    fi

    lock_pid=
    [ -f "$LOCK_DIR/pid" ] && lock_pid=$(sed -n '1p' "$LOCK_DIR/pid")
    if [ -n "$lock_pid" ] && kill -0 "$lock_pid" 2>/dev/null; then
        return 1
    fi

    rm -f "$LOCK_DIR/pid" 2>/dev/null || true
    rmdir "$LOCK_DIR" 2>/dev/null || return 1
    mkdir "$LOCK_DIR" 2>/dev/null || return 1
    printf '%s\n' "$$" >"$LOCK_DIR/pid"
}

release_apply_lock() {
    rm -f "$LOCK_DIR/pid" 2>/dev/null || true
    rmdir "$LOCK_DIR" 2>/dev/null || true
}
