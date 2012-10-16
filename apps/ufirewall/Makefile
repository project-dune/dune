CC      = gcc
LD	= ld
RANLIB	= ranlib
CFLAGS  = -Wall -O2 -MD -I ../../ -I ../sandbox
LDFLAGS = -O2 -L ../sandbox -L ../../libdune -lsandbox -ldune -lpthread -T ../sandbox/sandbox.ld
OBJ     = firewall.o

ufirewall: firewall.o ../sandbox/libsandbox.a ../../libdune/libdune.a
	$(CC) -o $(@) $(<) $(LDFLAGS)

clean:
	rm -f *.o test *.d ufirewall

-include *.d
