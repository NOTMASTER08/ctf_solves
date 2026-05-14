#!/bin/sh
set -euxo pipefail
musl-gcc -Os -static exploit.c -o exploit
