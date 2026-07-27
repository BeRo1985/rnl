#!/bin/sh
#
# Builds the RNL test runner with FreePascal.
#
# Usage:
#   ./build.sh [additional fpc options]     native build      -> ./RNLTests
#   ./build.sh --win64 [fpc options]        cross build       -> ./RNLTests.exe
#
# The win64 cross build is worth running even on a non Windows machine, because the
# Windows specific socket wait implementation, which emulates poll on top of
# WSAEventSelect and WSAWaitForMultipleEvents, is a completely separate code path from
# the poll and select ones used everywhere else. Under wine it can be executed:
#
#   ./build.sh --win64 && wine ./RNLTests.exe
#
set -e

cd "$(dirname "$0")"

TARGET=""
OUTPUT="RNLTests"
UNITS="units"

if [ "$1" = "--win64" ]; then
    shift
    TARGET="-Twin64"
    OUTPUT="RNLTests.exe"
    UNITS="units-win64"
fi

mkdir -p "$UNITS"

fpc $TARGET \
    -Mdelphi \
    -Sc \
    -O1 \
    -g \
    -gl \
    -Ci \
    -Co \
    -CR \
    -Sa \
    -vewn \
    -Fu.. \
    -Fu. \
    -FU"$UNITS" \
    -o"$OUTPUT" \
    "$@" \
    RNLTests.dpr
