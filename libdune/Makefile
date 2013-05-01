CC      = gcc
CFLAGS  = -Wall -g -O3 -MD
LDFLAGS = -static -L. -ldune
OBJ     = entry.o dune.o vsyscall.o elf.o vm.o util.o page.o procmap.o
NOFPU_OBJ = trap.o

$(NOFPU_OBJ): EXTRA_FLAGS := -mno-sse -mno-mmx -mno-sse2 -mno-3dnow -msoft-float

all: libdune.a

libdune.a: $(OBJ) $(NOFPU_OBJ)
	$(AR) cru $(@) $(OBJ) $(NOFPU_OBJ)

clean:
	rm -f *.o test *.d libdune.a

-include *.d

%.o: %.c
	$(CC) $(CFLAGS) $(EXTRA_FLAGS) -o $@ -c $<

