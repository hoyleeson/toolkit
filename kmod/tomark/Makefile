# Makefile of tomark module
# Author Sinoy Lee <sinoylee@gmail.com>
# Date 2022-02-11

obj-m += tomark.o
tomark_kmod-objs := tomark.o

CURRENT_PATH := $(shell pwd)

ifndef KDIR
LINUX_KERNEL := /lib/modules/$(shell uname -r)/build
else
LINUX_KERNEL := $(KDIR)
endif

all:
	make -C $(LINUX_KERNEL) SUBDIRS=$(PWD) modules

clean:
	make -C $(LINUX_KERNEL) M=$(CURRENT_PATH) clean
	rm -fr out Module.markers

install:
	make -C $(LINUX_KERNEL) M=$(CURRENT_PATH) modules_install INSTALL_MOD_PATH=$(PWD)/out

