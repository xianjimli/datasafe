#!/bin/bash

export CFLAGS="-DANTI_DEBUG -O2"

make distclean
./configure CFLAGS=-DANTI_DEBUG && make

cp -f usr/bin/* /usr/bin/.
cp -f src/datasafe_proxy /usr/bin/
cp -f src/datasafe_tags  /usr/bin/
cp -f src/datasafe_has_attr /usr/bin/

./makeserver.sh
./makeclient.sh

rm -f cpkg.tar.gz spkg.tar.gz
cd cpkg && tar czf ../cpkg.tar.gz etc/ usr/;cd -
cd spkg && tar czf ../spkg.tar.gz etc/ usr/;cd -

rm -rf release
mkdir release
mv *pkg.tar.gz ./release


