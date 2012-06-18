CC      = gcc
LD	= ld
CFLAGS  = -Wall -O2 -MD -I ../
LDFLAGS = -O2 -L ../libdune -ldune -T sandbox.ld
OBJ     = main.o umm.o trap.o

all: sandbox

sandbox: $(OBJ)
	$(CC) -o $(@) $(OBJ) $(LDFLAGS)

clean:
	rm -f *.o test *.d sandbox

-include *.d
