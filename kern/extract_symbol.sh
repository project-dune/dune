#!/bin/sh

KVER=`uname -r`
SYSTEM_MAP=/boot/System.map-$KVER
SYM=$1

extract()
{
	cat $SYSTEM_MAP | egrep " $SYM\$" | cut -d" " -f1
	exit 0
}

check_file()
{
ls $1 2> /dev/null > /dev/null
if [ $? -eq 0 ] ; then
	extract
fi
}

check_file $SYSTEM_MAP

SYSTEM_MAP=/lib/modules/$KVER/build/System.map
check_file $SYSTEM_MAP

VMLINUX=/lib/modules/$KVER/build/vmlinux
ls $VMLINUX 2> /dev/null > /dev/null
if [ $? -eq 0 ] ; then
	nm $VMLINUX | egrep " $SYM\$" | egrep " (R|T) " | cut -d" " -f1
	exit 0
fi

echo "FAILED - Can't find symbol!"
exit 1
