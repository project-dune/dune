#!/bin/sh

function check_good()
{
	if [ $? -ne 0 ] ; then
		echo nope
	else
		echo yes
	fi
}

printf "Checking for VT-x... "
cat /proc/cpuinfo | grep flags | grep ept | grep vpid | grep vmx > /dev/null
check_good

printf "Checking kernel version... "
uname -r | awk -F . '{print $1}' | grep 3 > /dev/null
check_good

printf "Checking for kernel headers... "
ls /lib/modules/`uname -r`/source/include > /dev/null 2> /dev/null
check_good
