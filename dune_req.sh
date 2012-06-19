#!/bin/sh

MOD=/lib/modules/`uname -r`

check_good()
{
	if [ $? -ne 0 ] ; then
		echo nope
	else
		echo yes
	fi
}

printf "Checking for x86_64 Linux... "
uname -m | grep x86_64 > /dev/null
check_good

printf "Checking for VT-x (w/ EPT and VPID)... "
cat /proc/cpuinfo | grep flags | grep ept | grep vpid | grep vmx > /dev/null
check_good

printf "Checking kernel version (3.0 or later) ... "
uname -r | awk -F . '{print $1}' | grep 3 > /dev/null 2> /dev/null
check_good

printf "Checking for kernel headers... "
ls $MOD/build/include > /dev/null 2> /dev/null
check_good

printf "Checking for syscall table location... "
kern/extract_symbol.sh sys_call_table > /dev/null 2> /dev/null
check_good
