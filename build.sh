#!/bin/sh

set -e

CC="${CC:-cc}"

set -x
$CC $CFLAGS fy4dec.c -o fy4dec -lcrypto
{ set +x; } 2>/dev/null

echo "Build successful."