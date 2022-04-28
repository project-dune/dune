CC	:= gcc -fPIC
CFLAGS	:= -Wall -O2 -I../
LDFLAGS := -shared -ldl

dunify.so: dunify.c ../libdune/libdune.a
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

hello: hello.c
	$(CC) $(CFLAGS) -o $@ $<
