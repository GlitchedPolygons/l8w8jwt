#!/bin/bash

#  Copyright 2020 Raphael Beck
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

PROJECT_NAME="L8W8JWT"

if [ "$(whoami)" = "root" ]; then
  echo "  Please don't run as root/using sudo..."
  exit
fi

PREVCC="$CC"
PREVCXX="$CXX"

if command -v clang &> /dev/null
then
    echo "-- Clang found on system, great! Long live LLVM! :D"
    export CC=clang
    export CXX=clang++
fi

REPO=$(dirname "$0")
rm -rf "$REPO"/out
rm -rf "$REPO"/build
mkdir -p "$REPO"/build/include && cd "$REPO"/build || exit

cmake -DBUILD_SHARED_LIBS=On -DUSE_SHARED_MBEDTLS_LIBRARY=Off "-D${PROJECT_NAME}_BUILD_DLL=On" "-D${PROJECT_NAME}_PACKAGE=On" -DCMAKE_BUILD_TYPE=Release ..

cmake --build . --config Release

export CC="$PREVCC"
export CXX="$PREVCXX"

cp -r ../include .
cd "$REPO" || exit

echo "  Done. Exported build into $REPO/build"
