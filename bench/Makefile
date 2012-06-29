CC	= gcc
CFLAGS	= -Wall -g -MD -O2 -I ../

all: bench_dune bench_dune_ring bench_linux

bench_dune: bench_dune.o ../libdune/libdune.a
	$(CC) $(CFLAGS) $(<) -o bench_dune -L ../libdune -ldune -lpthread

bench_dune_ring: bench_dune_ring.o ../libdune/libdune.a
	$(CC) $(CFLAGS) $(<) -o bench_dune_ring -L ../libdune -ldune -lpthread

bench_linux: bench_linux.o
	$(CC) $(CFLAGS) $(<) -o bench_linux

clean:
	rm -f *.o test *.d bench_dune bench_dune_ring bench_linux

-include *.d
