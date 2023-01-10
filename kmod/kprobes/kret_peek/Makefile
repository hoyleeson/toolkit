obj-m += kret_peek.o

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

