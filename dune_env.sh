#!/bin/sh

ROOT=`readlink -f $0`
ROOT=`dirname $ROOT`
LIBCBUILD=$ROOT/eglibc-2.14/eglibc-build
CMD=`readlink -f $1`

shift 1

LD_PRELOAD=$LIBCBUILD/libc.so:$LIBCBUILD/nptl/libpthread.so $CMD $*
