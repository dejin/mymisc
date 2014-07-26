#!/bin/sh

FILES=`find -type f`

for fn in $FILES
do
	echo $fn
	sed -i 's/\s\+$//g' $fn
	chmod 644 $fn
done


for fn in `find -name "*.sh"`
do
	echo $fn
	chmod 755 $fn
done


