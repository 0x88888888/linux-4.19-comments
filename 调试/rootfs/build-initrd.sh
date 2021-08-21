#! /bin/sh
cd ~/software/kernel_debug/BUSYBOX/_install
rm rootfs.img rootfs.img.gz

find . | cpio -o --format=newc > ~/software/kernel_debug/rootfs.img

cd ~/software/kernel_debug
gzip -c rootfs.img > rootfs.img.gz

