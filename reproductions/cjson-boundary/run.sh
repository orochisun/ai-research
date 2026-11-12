#!/bin/sh
set -eu
cd "$(dirname "$0")/../.."
mkdir -p data/cjson-boundary
clang -fsanitize=address,undefined -g -O1 -fno-omit-frame-pointer \
  -I research-targets/cJSON reproductions/cjson-boundary/harness.c \
  research-targets/cJSON/cJSON.c -o data/cjson-boundary/harness
ASAN_OPTIONS=halt_on_error=1 UBSAN_OPTIONS=halt_on_error=1 data/cjson-boundary/harness
