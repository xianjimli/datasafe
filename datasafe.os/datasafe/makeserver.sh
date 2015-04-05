#!/bin/bash

DIST_DIR=spkg
rm -rf $DIST_DIR
mkdir -p $DIST_DIR/usr/bin
mkdir -p $DIST_DIR/etc/datasafe
mkdir -p $DIST_DIR/etc/init.d

cd src && ./gen_apkg.sh; cd -
for f in datasafe_encrypt datasafe_decrypt datasafe_tags datasafe_admin datasafe_proxy datasafe_service datasafe_tags datasafe_has_attr
do
	strip src/$f
	cp -fv src/$f $DIST_DIR/usr/bin
done

for f in ./usr/bin/*
do
	cp -fv $f $DIST_DIR/usr/bin
done

for f in client.pem  dh1024.pem  root.pem  server.pem apkg.tar.gz
do
	cp -fv src/$f $DIST_DIR/etc/datasafe
done

for f in dsservice 
do
	cp -fv $f $DIST_DIR/etc/init.d
done

