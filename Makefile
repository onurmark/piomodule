ifneq ($(KERNELRELEASE),)
include Kbuild
else

ARCH ?= arm
CROSS_COMPILE ?= /home/ubuntu/Workspaces/allradio/toolchain-arm_cortex-a7_gcc-4.8-linaro_uClibc-1.0.14_eabi/bin/arm-openwrt-linux-
KDIR ?= /home/ubuntu/Workspaces/linux-3.14.77
# KDIR ?= /lib/modules/$(shell uname -r)/build

all:
	make ARCH=$(ARCH) CROSS_COMPILE=$(CROSS_COMPILE) -C $(KDIR) M=$(PWD)

clean:
	make -C $(KDIR) M=$(PWD) clean

endif
