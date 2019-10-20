CFLAGS = -I../src -fPIC
DESTDIR ?= /
XTABLES_LIB=$(shell pkg-config --variable=xtlibdir xtables)

all: libxt_tlslist.so
lib%.so: lib%.o
	$(CC) -shared -o $@ $^;
lib%.o: %lib%.c
	$(CC) ${CFLAGS} -D_INIT=lib$*_init -c -o $@ $<;
clean:
	rm -rf libxt_tlslist.so
install:
	install -D -v -m 644 libxt_tlslist.so $(DESTDIR)$(XTABLES_LIB)
uninstall:
	rm $(DESTDIR)$(XTABLES_LIB)/libxt_tlslist.so
