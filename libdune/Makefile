CC      = gcc
CFLAGS  = -Wall -g -O2 -MD
LDFLAGS = -static -L. -ldune
OBJ     = dune.o elf.o entry.o vm.o util.o trap.o page.o procmap.o

all: libdune.a

libdune.a: $(OBJ)
	$(AR) cru $(@) $(OBJ)

clean:
	rm -f *.o test *.d libdune.a

-include *.d
