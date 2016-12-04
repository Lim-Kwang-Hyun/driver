KERNEL_TREE := /lib/modules/$(shell uname -r)/build
# KERNEL_TREE := $(HOME)/linux-$(KERN_VERSION)

PWD := $(shell pwd)

EXTRA_CFLAGS += -O2 -DCONFIG_DM_DEBUG -fno-inline -Wall
# EXTRA_CFLAGS += -O2 -UCONFIG_DM_DEBUG

obj-m := dm-src.o
dm-src-objs := \
	target.o \
	metadata.o \
	daemon.o \
	lru.o \
	alloc.o 

all:
	$(MAKE) -C $(KERNEL_TREE) M=$(PWD) modules

clean:
	$(MAKE) -C $(KERNEL_TREE) M=$(PWD) clean
