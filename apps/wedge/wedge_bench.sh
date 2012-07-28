#!/bin/sh

rm -fr wedgeresults
mkdir wedgeresults

echo Running ctx switch benchmark...
../../dune_env.sh ./bench 2 1 300 | grep result > wedgeresults/ctx.dat
echo Done

echo Running create benchmark...
../../dune_env.sh ./bench 0 | grep Avg > wedgeresults/create.dat
echo Done

echo Running web benchmark...
do_http()
{
	../../dune_env.sh ./httpd $1 > /dev/null 2> /dev/null &
	sleep 1
	./bench 1 | grep Avg >> wedgeresults/httpd.dat
	killall -9 httpd
}
do_http 1
do_http 2
do_http 3
echo Done

dmesg > wedgeresults/dmesg.txt

rm -f wedgeresults.tgz                                                                                       
tar zcvf wedgeresults.tgz wedgeresults
rm -fr wedgeresults
ls -l wedgeresults.tgz
