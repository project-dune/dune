CC	= gcc
CFLAGS	= -Wall -g -MD -O2 -I ../

all: hello

hello: hello.o ../libdune/libdune.a
	$(CC) $(CFLAGS) $(<) -o hello -L ../libdune -ldune

clean:
	rm -f *.o test *.d hello

-include *.d
