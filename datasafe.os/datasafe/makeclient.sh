#!/bin/bash

DIST_DIR=cpkg
rm -rf $DIST_DIR
mkdir -p $DIST_DIR/usr/bin
mkdir -p $DIST_DIR/etc/datasafe
mkdir -p $DIST_DIR/etc/init.d

for f in datasafe_tags datasafe_proxy datasafe_has_attr datasafe_encrypt
do
	strip src/$f
	cp -fv src/$f $DIST_DIR/usr/bin
done

for f in ./usr/bin/*
do
	cp -fv $f $DIST_DIR/usr/bin
done

for f in root.pem client.pem
do
	cp -fv src/$f $DIST_DIR/etc/datasafe
done

for f in dsproxy
do
	cp -fv $f $DIST_DIR/etc/init.d
done

