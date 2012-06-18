#!/bin/sh

ROOT=`readlink -f $0`
ROOT=`dirname $ROOT`
LIBC=$ROOT/eglibc-2.14/eglibc-build/libc.so
CMD=`readlink -f $1`

shift 1

LD_PRELOAD=$LIBC $CMD $*
