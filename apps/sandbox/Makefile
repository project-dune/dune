CC      = gcc
LD	= ld
RANLIB	= ranlib
CFLAGS  = -Wall -O2 -MD -I ../../
LDFLAGS = -O2 -L. -L ../../libdune -lsandbox -ldune -lpthread -T sandbox.ld
OBJ     = main.o umm.o trap.o exec.o

all: libsandbox.a sandbox

libsandbox.a: $(OBJ)
	$(AR) cru $(@) $(OBJ)
	$(RANLIB) $(@)

sandbox: nullsandbox.o libsandbox.a ../../libdune/libdune.a
	$(CC) -o $(@) $(<) $(LDFLAGS)

clean:
	rm -f *.o test *.d sandbox libsandbox.a

-include *.d
