#!/bin/sh

set -eu

ROOT=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
MODULE=$ROOT/src/magisk/dev.accessControl
OUTPUT_DIR=$ROOT/build
OUTPUT=$OUTPUT_DIR/dev.accessControl.zip

mkdir -p "$OUTPUT_DIR"
rm -f "$OUTPUT"
(
    cd "$MODULE"
    zip -qr "$OUTPUT" . -x '*.DS_Store' 'README.md' 'system/etc/selinux/.keep'
)
printf '%s\n' "$OUTPUT"
