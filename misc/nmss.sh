#!/bin/sh

# hostfile - List of subnets or addresses which to scan for a given port
# outpath - Path to store output
# port - Port to scan for

if [ -z "$2" ]; then
	echo usage: nmss.sh hostfile outpath port
	exit 1
fi

tmpfile=`mktemp`

outfile="nmss-`date +%s`.out"
out="${2}/${outfile}"

nmap -iL $1 -sS -p 22 -P0 -T4 -oG $tmpfile

cat $tmpfile | grep '\/open\/' | awk '{ print $2 }' > $out

rm -f ${2}/lastscan
(cd ${2} && ln -s $outfile lastscan)

exit 0
