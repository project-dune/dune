#!/bin/sh

CMD=`which $1`
shift 1

#../../dune_env.sh
./sandbox /lib64/ld-linux-x86-64.so.2 $CMD $*
