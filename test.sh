#!/bin/sh
REPO=$(dirname "$0")
cov=Off
if [ "$1" = "cov" ]; then cov=On; fi
rm -rf "$REPO"/build
mkdir -p "$REPO"/build && cd "$REPO"/build || exit
cmake -DBUILD_SHARED_LIBS=Off -DUSE_SHARED_MBEDTLS_LIBRARY=Off -DL8W8JWT_ENABLE_TESTS=On -DENABLE_COVERAGE="${cov}" ..
make
./run_tests
cd "$REPO" || exit