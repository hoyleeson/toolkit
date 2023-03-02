# Makefile of toa_i module
# Author hoyleeson
# Date 2018-1-1


obj-m += toa_label.o
toa_label_kmod-objs := toa_label.o

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

