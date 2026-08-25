#!/system/bin/sh

load_config() {
    DYNAMIC_LOAD=1
    MAX_LOG_SIZE_KB=256
    BASE_DOMAIN=untrusted_app
    config_errors=0

    if [ ! -f "$CONFIG_FILE" ]; then
        ac_log error "missing configuration: $CONFIG_FILE"
        return 1
    fi

    while IFS='=' read -r raw_key raw_value extra; do
        key=$(trim_value "$raw_key")
        value=$(trim_value "$raw_value")

        case "$key" in
            '' | \#*) continue ;;
            DYNAMIC_LOAD)
                case "$value" in
                    0 | false | FALSE | no | NO) DYNAMIC_LOAD=0 ;;
                    1 | true | TRUE | yes | YES) DYNAMIC_LOAD=1 ;;
                    *) ac_log error "DYNAMIC_LOAD must be 0 or 1"; config_errors=$((config_errors + 1)) ;;
                esac
                ;;
            MAX_LOG_SIZE_KB)
                case "$value" in
                    '' | *[!0-9]*) ac_log error "MAX_LOG_SIZE_KB must be an integer"; config_errors=$((config_errors + 1)) ;;
                    *)
                        if [ "$value" -lt 32 ] || [ "$value" -gt 8192 ]; then
                            ac_log error "MAX_LOG_SIZE_KB must be between 32 and 8192"
                            config_errors=$((config_errors + 1))
                        else
                            MAX_LOG_SIZE_KB=$value
                        fi
                        ;;
                esac
                ;;
            BASE_DOMAIN)
                if printf '%s\n' "$value" | grep -Eq '^[A-Za-z][A-Za-z0-9_]{0,62}$'; then
                    BASE_DOMAIN=$value
                else
                    ac_log error "BASE_DOMAIN must be a valid SELinux type name"
                    config_errors=$((config_errors + 1))
                fi
                ;;
            *)
                ac_log error "unknown setting: $key"
                config_errors=$((config_errors + 1))
                ;;
        esac

        if [ -n "$extra" ]; then
            ac_log error "invalid setting syntax for $key"
            config_errors=$((config_errors + 1))
        fi
    done <"$CONFIG_FILE"

    [ "$config_errors" -eq 0 ]
}
