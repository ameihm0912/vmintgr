#!/bin/sh
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

# hostfile - List of subnets or addresses which to scan for a given port
# outpath - Path to store output
# port - Port(s) to scan for, comma seperated no spaces
# icmp_only - Only send ICMP probes to determine if host is up

PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin

interface=eth1

umask 022

if [ -z "$3" ]; then
	echo "usage: znmss.sh hostfile outpath port icmp_only(0|1)"
	exit 1
fi

icmp_only=0
infile=$1
outdir=$2

if [ $4 -ne "0" ]; then
	icmp_only=1
fi

outfile="znmss-`date +%s`.out"
out="${outdir}/${outfile}"

zmapscan() {
	port=$1

	zmap -i ${interface} -p $port -w $infile -o ${out}.${port}
	if [ $? -ne 0 ]; then
		exit 1
	fi
}

zmapscan_icmp() {
	zmap -i ${interface} --probe-module=icmp_echoscan -w $infile \
		-o ${out}.up
	if [ $? -ne 0 ]; then
		exit 1
	fi
}

zmapscan_icmp

if [ $icmp_only -eq 0 ]; then
	plist=`echo ${3} | sed 's/,/ /g'`
	for i in $plist; do
		zmapscan $i
	done
fi

odir=`pwd`
cd $outdir
rm -f lastscan*
for i in `ls ${outfile}.* | grep '\.[[:digit:]]\+$'`; do
	pn=`echo $i | cut -d '.' -f 3`
	ln -s $i lastscan.${pn}
done
if [ -f ${outfile}.up ]; then
	ln -s ${outfile}.up lastscan.up
fi
cd $odir

chmod 644 ${outdir}/*

exit 0
