obj-m := xt_tlslist.o
KERNEL_VERSION ?= $(shell uname -r)
IDIR := /lib/modules/$(KERNEL_VERSION)/kernel/net/netfilter/
KDIR := /lib/modules/$(KERNEL_VERSION)/build
DESTDIR ?= /
PWD := $(shell pwd)
VERSION := $(shell git rev-parse HEAD 2>/dev/null)
FLAGS :=
default:
	    $(MAKE) -C $(KDIR) SUBDIRS=$(PWD) CFLAGS_MODULE="$(FLAGS)" modules

debug:
	    $(MAKE) -C $(KDIR) SUBDIRS=$(PWD) CFLAGS_MODULE="-DXT_TLSLIST_DEBUG" modules

install:
	    $(MAKE) -C $(KDIR) SUBDIRS=$(PWD) INSTALL_MOD_PATH=$(DESTDIR) modules_install
	    depmod -a

uninstall:
		depmod -a

clean:
	    rm -rf Module.markers modules.order Module.symvers xt_tlslist.ko xt_tlslist.mod.c xt_tlslist.mod.o xt_tlslist.o .xt_tlslist.*.cmd .tmp_versions
