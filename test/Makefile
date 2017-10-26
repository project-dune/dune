CC	:= gcc
CFLAGS	:= -Wall -g -MD -O2 -I ../
LDFLAGS := -ldune -lpthread
MODULE_LIB := /lib/modules/$(shell uname -r)/build

tests_files := hello test timetest test_sandbox hugepages hugepages_mod.ko

obj-m += hugepages_mod.o

all: $(tests_files)

hello: hello.o ../libdune/libdune.a
	$(CC) $(CFLAGS) -static $(<) -L../libdune/ $(LDFLAGS) -o $(@)

timetest: timetest.o ../libdune/libdune.a
	$(CC) $(CFLAGS) -static $(<) -L../libdune $(LDFLAGS) -o $(@)

test: test.o ../libdune/libdune.a
	$(CC) $(CFLAGS) -static $(<) -L../libdune $(LDFLAGS) -o $(@)

test_sandbox: test_sandbox.o
	$(CC) $(CFLAGS) -static $(<) -pthread -o $(@)

hugepages: hugepages.o ../libdune/libdune.a
	$(CC) $(CFLAGS) -static $(<) -L../libdune $(LDFLAGS) -o $(@)

hugepages_mod.ko: hugepages_mod.c
	make -C $(MODULE_LIB) M=$(PWD) CFLAGS= LDFLAGS= modules

clean:
	rm -f *.o test *.d $(tests_files)
	make -C $(MODULE_LIB) M=$(PWD) clean

-include *.d
