#!/bin/bash

rm -rf release

echo "copy modules..."
mkdir -p release/lib/modules/
cp -rf /lib/modules/2.6.31.5-broncho/ release/lib/modules/

echo "copy boot..."
mkdir -p release/boot
cp -rf /boot/*broncho* release/boot
rm -f release/boot/initramfs-2.6.31.5-broncho.img

echo "make a tar..."
cd release
tar czf kernel.tar.gz boot lib

