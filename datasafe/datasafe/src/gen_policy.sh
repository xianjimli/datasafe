#!/bin/bash
awk  '{printf($2" " $3 " ");system("md5sum " $1)}' osfiles.lst files.lst|awk '{print $4";"$3";"$1";"$2}'
