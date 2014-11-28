#!/bin/sh

# hostfile - List of subnets or addresses which to scan for a given port
# outpath - Path to store output
# port - Port(s) to scan for, comma seperated no spaces

if [ -z "$3" ]; then
	echo usage: nmss.sh hostfile outpath port
	exit 1
fi

tmpfile=`mktemp`

outfile="nmss-`date +%s`.out"
out="${2}/${outfile}"

nmap -iL $1 -sS -p $3 -P0 -T4 -oG $tmpfile

cat $tmpfile | grep '\/open\/' | awk '{ print $2 }' | sort | uniq > $out
cat $tmpfile > ${out}.nmap

rm -f ${2}/lastscan
(cd ${2} && ln -s $outfile lastscan)

rm -f $tmpfile

exit 0
