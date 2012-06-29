CC	= gcc
CFLAGS	= -Wall -g -MD -O2 -I ../

all: hello test

hello: hello.o ../libdune/libdune.a
	$(CC) $(CFLAGS) $(<) -o hello -L ../libdune -ldune -lpthread

test: test.o ../libdune/libdune.a
	$(CC) $(CFLAGS) $(<) -o test -L ../libdune -ldune -lpthread

clean:
	rm -f *.o test *.d hello test

-include *.d
