#!/bin/sh -e

BINARY=$1
shift

# When pushing a bin, the full target dir is appended (including the target
# triple). There's no need for this, so strip it away. This simplifies the
# `TEST_HELPER` definition across multiple architectures.
REMOTE_BINARY="/data/local/$(basename $BINARY)"

# Make sure to run the following to copy the test helper binary over.
# cargo run --target ANDROID-TARGET --bin test
adb push $BINARY $REMOTE_BINARY
adb shell "chmod 777 $REMOTE_BINARY && env TEST_HELPER=/data/local/test $REMOTE_BINARY" "$@"
