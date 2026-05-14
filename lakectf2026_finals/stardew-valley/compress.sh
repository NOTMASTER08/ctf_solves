#!/bin/sh
set -exo pipefail

[ ! -d rootfs ] && echo "No rootfs" && exit -1
cd rootfs
sudo find . -print0 | sudo cpio -ov0 -H newc > ../rootfs.cpio
cd ..
