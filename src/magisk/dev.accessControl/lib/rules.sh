#!/system/bin/sh

valid_package() {
    printf '%s\n' "$1" | grep -Eq '^[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z][A-Za-z0-9_]*)+$'
}

valid_domain() {
    printf '%s\n' "$1" | grep -Eq '^ac_[a-z][a-z0-9_]{0,58}$'
}

normalize_permissions() {
    raw=$(printf '%s' "$1" | tr '[:upper:]+' '[:lower:]|')
    raw=$(printf '%s' "$raw" | tr -d '[:space:]')
    [ -n "$raw" ] || return 1

    result=
    old_ifs=$IFS
    IFS='|'
    for permission in $raw; do
        case "$permission" in
            read | write | execute | delete | metadata) ;;
            all)
                result=all
                break
                ;;
            *)
                IFS=$old_ifs
                return 1
                ;;
        esac
        case "|$result|" in
            *"|$permission|"*) ;;
            *)
                if [ -n "$result" ]; then
                    result="$result|$permission"
                else
                    result=$permission
                fi
                ;;
        esac
    done
    IFS=$old_ifs
    printf '%s\n' "$result"
}

context_for_path() {
    target_path=$1

    if [ -n "${AC_CONTEXT_MAP:-}" ] && [ -f "$AC_CONTEXT_MAP" ]; then
        awk -F '\t' -v wanted="$target_path" '$1 == wanted { print $2; exit }' "$AC_CONTEXT_MAP"
        return
    fi

    context=$(/system/bin/ls -Zd "$target_path" 2>/dev/null | awk '{
        for (i = 1; i <= NF; i++) {
            if ($i ~ /^u:object_r:[A-Za-z0-9_]+:/) { print $i; exit }
        }
    }')
    if [ -z "$context" ]; then
        context=$(ls -Zd "$target_path" 2>/dev/null | awk '{
            for (i = 1; i <= NF; i++) {
                if ($i ~ /^u:object_r:[A-Za-z0-9_]+:/) { print $i; exit }
            }
        }')
    fi
    printf '%s\n' "$context"
}

type_from_context() {
    printf '%s\n' "$1" | awk -F: 'NF >= 4 && $1 == "u" && $2 == "object_r" { print $3 }'
}

target_kind() {
    if [ -L "$1" ]; then
        printf '%s\n' lnk_file
    elif [ -d "$1" ]; then
        printf '%s\n' dir
    else
        printf '%s\n' file
    fi
}

validate_domain_mappings() {
    awk -F '\t' '
        {
            package = $1
            domain = $2
            if ((package in package_domain) && package_domain[package] != domain) {
                printf "package %s maps to both %s and %s\n", package, package_domain[package], domain
                bad = 1
            }
            if ((domain in domain_package) && domain_package[domain] != package) {
                printf "domain %s maps to both %s and %s\n", domain, domain_package[domain], package
                bad = 1
            }
            package_domain[package] = domain
            domain_package[domain] = package
        }
        END { exit bad }
    ' "$MAPPING_RULES" >"$RUNTIME_DIR/mapping-errors" 2>&1
}

emit_domain_policy() {
    awk -F '\t' '!seen[$2]++ { print $2 }' "$MAPPING_RULES" | while IFS= read -r domain; do
        [ -n "$domain" ] || continue
        printf 'type %s domain\n' "$domain"
        printf 'typeattribute %s appdomain\n' "$domain"
        printf 'typeattribute %s untrusted_app_all\n' "$domain"
        printf 'typeattribute %s netdomain\n' "$domain"
        printf 'typeattribute %s bluetoothdomain\n' "$domain"
    done
}

prepare_base_clone_policy() {
    : >"$BASE_CLONE_POLICY"
    [ "$DOMAIN_MAPPINGS" -gt 0 ] || return 0

    if [ -n "${AC_POLICY_DUMP:-}" ] && [ -f "$AC_POLICY_DUMP" ]; then
        policy_source=$AC_POLICY_DUMP
    else
        if ! command -v "$MAGISKPOLICY" >/dev/null 2>&1; then
            ac_log error "magiskpolicy executable not found: $MAGISKPOLICY"
            return 1
        fi
        if ! "$MAGISKPOLICY" --print-rules >"$POLICY_DUMP" 2>>"$LOG_FILE"; then
            ac_log error "cannot inspect the live SELinux policy"
            return 1
        fi
        policy_source=$POLICY_DUMP
    fi

    while IFS="$(printf '\t')" read -r package domain; do
        [ -n "$domain" ] || continue
        awk -v base="$BASE_DOMAIN" -v custom="$domain" '
            $1 == "allow" || $1 == "allowxperm" ||
            $1 == "type_transition" || $1 == "type_change" || $1 == "type_member" {
                # Magisk 30.7 can print named anon_inode transitions such as
                # "... anon_inode ... [userfaultfd]", but feeding that line
                # back through --apply crashes magiskpolicy. It is not needed
                # for the configured file-access deny, so do not clone it.
                if ($1 == "type_transition" && $4 == "anon_inode" && NF >= 6) next
                matched = 0
                if ($2 == base) { $2 = custom; matched = 1 }
                if ($3 == base) { $3 = custom; matched = 1 }
                if (($1 == "type_transition" || $1 == "type_change" || $1 == "type_member") && $5 == base) {
                    $5 = custom
                    matched = 1
                }
                if (matched) print
            }
        ' "$policy_source"
    done <"$MAPPING_RULES" | awk '!seen[$0]++' >"$BASE_CLONE_POLICY"

    BASE_CLONE_COUNT=$(wc -l <"$BASE_CLONE_POLICY" | tr -d '[:space:]')
    case "$BASE_CLONE_COUNT" in
        '' | 0 | *[!0-9]*)
            ac_log error "BASE_DOMAIN has no clonable policy rules: $BASE_DOMAIN"
            return 1
            ;;
    esac
}

emit_deny() {
    domain=$1
    target_type=$2
    object_class=$3
    permission=$4

    case "$permission:$object_class" in
        all:*) perms='*' ;;
        read:dir) perms='{ open read search getattr }' ;;
        read:file) perms='{ open read getattr map }' ;;
        read:lnk_file) perms='{ read getattr }' ;;
        write:dir) perms='{ open write add_name remove_name setattr }' ;;
        write:file) perms='{ open write append setattr create unlink link rename }' ;;
        write:lnk_file) perms='{ create setattr unlink link rename }' ;;
        execute:dir) perms='{ search }' ;;
        execute:file) perms='{ open read getattr map execute execute_no_trans }' ;;
        execute:lnk_file) perms='{ read }' ;;
        delete:dir) perms='{ remove_name rmdir rename reparent }' ;;
        delete:file | delete:lnk_file) perms='{ unlink rename }' ;;
        metadata:*) perms='{ getattr setattr relabelfrom relabelto }' ;;
        *) return 1 ;;
    esac
    printf 'deny %s %s %s %s\n' "$domain" "$target_type" "$object_class" "$perms"
}

emit_rule_policy() {
    while IFS="$(printf '\t')" read -r package domain path permissions target_type kind; do
        old_ifs=$IFS
        IFS='|'
        for permission in $permissions; do
            if [ "$kind" = dir ]; then
                emit_deny "$domain" "$target_type" dir "$permission"
                emit_deny "$domain" "$target_type" file "$permission"
                emit_deny "$domain" "$target_type" lnk_file "$permission"
            else
                emit_deny "$domain" "$target_type" "$kind" "$permission"
            fi
        done
        IFS=$old_ifs
    done <"$NORMALIZED_RULES"
}

build_policy_file() {
    {
        printf '# Generated by dev.accessControl; do not edit.\n'
        emit_domain_policy
        cat "$BASE_CLONE_POLICY"
        emit_rule_policy
    } | awk '!seen[$0]++' >"$GENERATED_POLICY"
}

build_seapp_file() {
    if [ ! -f "$SEAPP_SOURCE" ]; then
        ac_log error "seapp_contexts source not found: $SEAPP_SOURCE"
        return 1
    fi

    if [ "${APPLY_PHASE:-check}" = boot ] || [ ! -f "$SEAPP_BASELINE" ]; then
        awk '/^# dev\.accessControl generated mappings$/ { exit } { print }' \
            "$SEAPP_SOURCE" >"$SEAPP_BASELINE" || return 1
    fi

    cp -p "$SEAPP_BASELINE" "$GENERATED_SEAPP" || return 1
    {
        printf '\n# dev.accessControl generated mappings\n'
        awk -F '\t' '!seen[$1 FS $2]++ {
            printf "user=_app name=%s domain=%s levelFrom=all\n", $1, $2
        }' "$MAPPING_RULES"
    } >>"$GENERATED_SEAPP"
}

generate_rules() {
    ACTIVE_RULES=0
    PENDING_RULES=0
    DOMAIN_MAPPINGS=0
    errors=0
    line_number=0
    : >"$NORMALIZED_RULES"
    : >"$MAPPING_RULES"

    if [ ! -f "$TARGET_FILE" ]; then
        ac_log error "missing rules file: $TARGET_FILE"
        return 1
    fi

    while IFS=, read -r raw_package raw_domain raw_target raw_permissions extra; do
        line_number=$((line_number + 1))
        package=$(trim_value "$raw_package")
        domain=$(trim_value "$raw_domain")
        target=$(trim_value "$raw_target")
        permissions=$(trim_value "$raw_permissions")
        permissions=${permissions%"$(printf '\r')"}

        case "$package" in
            '' | \#*) continue ;;
            package)
                [ "$line_number" -eq 1 ] && continue
                ;;
        esac

        if [ -n "$extra" ]; then
            ac_log error "target.csv:$line_number: expected exactly four comma-separated fields"
            errors=$((errors + 1))
            continue
        fi
        if ! valid_package "$package"; then
            ac_log error "target.csv:$line_number: invalid Android package name: $package"
            errors=$((errors + 1))
            continue
        fi
        if ! valid_domain "$domain"; then
            ac_log error "target.csv:$line_number: domain must match ac_[a-z][a-z0-9_]* and be at most 62 characters"
            errors=$((errors + 1))
            continue
        fi
        case "$target" in
            /*) ;;
            *)
                ac_log error "target.csv:$line_number: target must be an absolute path"
                errors=$((errors + 1))
                continue
                ;;
        esac
        normalized_permissions=$(normalize_permissions "$permissions") || {
            ac_log error "target.csv:$line_number: permissions must use read, write, execute, delete, metadata, or all"
            errors=$((errors + 1))
            continue
        }

        printf '%s\t%s\n' "$package" "$domain" >>"$MAPPING_RULES"

        if [ ! -e "$target" ] && [ ! -L "$target" ]; then
            ac_log warn "target.csv:$line_number: target does not exist yet: $target"
            PENDING_RULES=$((PENDING_RULES + 1))
            continue
        fi

        context=$(context_for_path "$target")
        target_type=$(type_from_context "$context")
        if [ -z "$target_type" ]; then
            ac_log error "target.csv:$line_number: cannot read SELinux context for $target"
            errors=$((errors + 1))
            continue
        fi

        kind=$(target_kind "$target")
        printf '%s\t%s\t%s\t%s\t%s\t%s\n' \
            "$package" "$domain" "$target" "$normalized_permissions" "$target_type" "$kind" \
            >>"$NORMALIZED_RULES"
        ACTIVE_RULES=$((ACTIVE_RULES + 1))
    done <"$TARGET_FILE"

    if [ "$errors" -gt 0 ]; then
        ac_log error "$errors invalid rule(s) found"
        return 1
    fi

    if ! validate_domain_mappings; then
        while IFS= read -r mapping_error; do
            ac_log error "$mapping_error"
        done <"$RUNTIME_DIR/mapping-errors"
        return 1
    fi

    DOMAIN_MAPPINGS=$(awk -F '\t' '!seen[$1 FS $2]++ { count++ } END { print count + 0 }' "$MAPPING_RULES")
    prepare_base_clone_policy || return 1
    build_policy_file || return 1
    build_seapp_file || return 1
}
