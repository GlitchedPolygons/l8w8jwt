#!/bin/sh
REPO=$(dirname "$0")
rm -rf $REPO/tests/build/
cd $REPO/tests/ && mkdir build && cd build
cmake .. && make
./run_tests
