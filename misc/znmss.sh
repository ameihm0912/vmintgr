#!/bin/sh

# hostfile - List of subnets or addresses which to scan for a given port
# outpath - Path to store output
# port - Port(s) to scan for, comma seperated no spaces

PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin

interface=eth0

if [ -z "$3" ]; then
	echo usage: znmss.sh hostfile outpath port
	exit 1
fi

infile=$1
outdir=$2

upout=`mktemp`
outfile="znmss-`date +%s`.out"
out="${outdir}/${outfile}"

zmapscan() {
	port=$1

	zmap -i ${interface} -p $port -w $upout -o ${out}.${port}
	if [ $? -ne 0 ]; then
		exit 1
	fi
}

zmapscan_icmp() {
	zmap -i ${interface} --probe-module=icmp_echoscan -w $infile \
		-o ${upout}
	cp ${upout} ${out}.up
	if [ $? -ne 0 ]; then
		exit 1
	fi
}

zmapscan_icmp

plist=`echo ${3} | sed 's/,/ /'`
for i in $plist; do
	zmapscan $i
done

cd $outdir
rm -f lastscan*
for i in `ls ${outfile}.* | grep '\.[[:digit:]]\+$'`; do
	pn=`echo $i | cut -d '.' -f 3`
	ln -s $i lastscan.${pn}
done
if [ -f ${outfile}.up ]; then
	ln -s ${outfile}.up lastscan.up
fi

rm -f $upout

exit 0
