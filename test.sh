#!/bin/sh
REPO=$(dirname "$0")
rm -rf $REPO/build/
mkdir build && cd build
cmake -DBUILD_SHARED_LIBS=Off -DL8W8JWT_ENABLE_TESTS=On -DENABLE_COVERAGE=On .. && make
./run_tests
cd $REPO
