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

nmap -iL $1 -sS -p $3 -PE -T4 -oG $tmpfile

while read ln; do
	echo $ln | grep -q 'Status: Up'
	if [ $? -eq 0 ]; then
		ip=`echo $ln | cut -d ' ' -f 2`
		echo $ip >> ${out}.up
		continue
	fi
	echo $ln | grep -q '^Host\:.*Ports:.*/open/.*'
	if [ $? -ne 0 ]; then
		continue
	fi
	ip=`echo $ln | cut -d ' ' -f 2`
	buf=`echo $ln | sed 's,^Host.*Ports:,,'`
	for j in $buf; do
		echo $j | grep -q '/open/'
		if [ $? -ne 0 ]; then continue; fi
		pn=`echo $j | cut -d '/' -f 1`
		echo $ip >> ${out}.${pn}
	done
done < $tmpfile

cat $tmpfile > ${out}.nmap

cd $2
rm -f lastscan*
for i in `ls ${outfile}.* | grep '\.[[:digit:]]\+$'`; do
	pn=`echo $i | cut -d '.' -f 3`
	ln -s $i lastscan.${pn}
done
if [ -f ${outfile}.up ]; then
	ln -s ${outfile}.up lastscan.up
fi

rm -f $tmpfile

exit 0
