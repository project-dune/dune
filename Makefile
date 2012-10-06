LIBC	= eglibc-2.14/eglibc-build/libc.so
SUBDIRS	= kern libdune bench test apps

all: $(SUBDIRS)
libc: $(LIBC)

$(SUBDIRS):
	$(MAKE) -C $(@)

$(LIBC):
	sh build-eglibc.sh

clean:
	for dir in $(SUBDIRS); do \
		$(MAKE) -C $$dir $(@); \
	done

distclean: clean
	rm -fr eglibc-2.14

.PHONY: $(SUBDIRS) clean distclean
