#!/bin/sh
set -euxo pipefail
musl-gcc -static -Os -o pwn pwn.c
sudo cp pwn ./rootfs/home/ctf/
./compress.sh
