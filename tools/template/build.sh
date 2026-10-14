#!/usr/bin/env bash
# Generic build script for the ML-KEM server/client template.
# Override CC, INCLUDES, LIBS to target a different library.
set -e

CC=${CC:-clang}
WOLFSSL=${WOLFSSL:-/home/isaac/wolfssl}
INCLUDES=${INCLUDES:--I"$WOLFSSL"}
LIBS=${LIBS:--L"$WOLFSSL/src/.libs" -lwolfssl -Wl,-rpath,"$WOLFSSL/src/.libs"}
SANITIZE="-fsanitize=address,undefined"

$CC $SANITIZE -g -o poc_server server.c $INCLUDES $LIBS
$CC $SANITIZE -g -o poc_client client.c $INCLUDES $LIBS

echo "Built: poc_server  poc_client"
