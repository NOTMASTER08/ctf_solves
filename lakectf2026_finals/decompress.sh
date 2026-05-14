#!/bin/sh
set -exo pipefail

[ ! -d rootfs ] && mkdir rootfs
cd rootfs
sudo rm -rf *
cat ../rootfs.cpio | sudo cpio -idmv
cd ..
