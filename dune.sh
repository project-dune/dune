#!/bin/sh

ROOT=`readlink -f $0`
ROOT=`dirname $ROOT`
LIBC=$ROOT/eglibc-2.14/eglibc-build/libc.so

LD_PRELOAD=$LIBC  $*
