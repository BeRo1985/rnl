#!/bin/sh
#
# Builds the RNL test runner with FreePascal.
#
# Usage: ./build.sh [additional fpc options]
#
set -e

cd "$(dirname "$0")"

mkdir -p units

fpc -Mdelphi \
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
    -FUunits \
    -oRNLTests \
    "$@" \
    RNLTests.dpr
