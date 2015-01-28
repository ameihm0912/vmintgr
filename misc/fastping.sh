#!/bin/sh
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

# hostfile - List of subnets or addresses which to scan for
# outpath - Path to store output

umask 022

if [ -z "$2" ]; then
	echo usage: nmss.sh hostfile outpath
	exit 1
fi

tmpfile=`mktemp`

outfile="fastping-`date +%s`.out"
out="${2}/${outfile}"

nmap -sn -PE -T5 -oG $tmpfile -n --min-rate 500 --privileged -iL $1
if [ $? -ne 0 ]; then exit 1; fi

while read ln; do
	echo $ln | grep -q 'Status: Up'
	if [ $? -eq 0 ]; then
		ip=`echo $ln | cut -d ' ' -f 2`
		echo $ip >> ${out}.up
	fi
done < $tmpfile

cat $tmpfile > ${out}.nmap

cd $2
rm -f lastscan*
if [ -f ${outfile}.up ]; then
	ln -s ${outfile}.up lastscan.up
fi

rm -f $tmpfile

exit 0
