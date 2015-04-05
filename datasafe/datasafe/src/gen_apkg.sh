#!/bin/bash

rm -f apkg.tar.gz
for f in datasafe_encrypt datasafe_tags datasafe_proxy datasafe_has_attr
do
	strip $f
	cp -fv $f /usr/bin/$f
done

awk  'BEGIN{cmd="tar czvf apkg.tar.gz "} { cmd =  cmd " " $1} END{system(cmd)}' osfiles.lst dsfiles.lst
echo apkg.tar.gz is ready.

