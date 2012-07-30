LIBDUNE	= ../../libdune
CFLAGS	= -Wall -g -MD -I$(LIBDUNE) -fomit-frame-pointer
RANLIB	= ranlib
LIBS	= -lsthread -ldune -lpthread

all: libsthread.a test bench httpd

libsthread.a: sthread.o
	$(AR) cru $(@) $(<)
	$(RANLIB) $(@)

test: test.o libsthread.a
	$(CC) $(CFLAGS) -o $(@) $(<) -L. -L$(LIBDUNE) $(LIBS)

bench: bench.o libsthread.a
	$(CC) $(CFLAGS) -o $(@) $(<) -L. -L$(LIBDUNE) $(LIBS)

httpd: httpd.o libsthread.a
	$(CC) $(CFLAGS) -o $(@) $(<) -L. -L$(LIBDUNE) $(LIBS)

clean:
	rm -f *.o *.d test libsthread.a bench httpd

-include *.d
