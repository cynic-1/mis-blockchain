#KDIR:=/usr/src/linux-4.2.8
KDIR:=/lib/modules/$(shell  uname -r)/build/

CONFIG_MODULE_SIG=n

obj-m +=ax99100_spi.o

default:
	$(RM) *.mod.c *.o *.ko .*.cmd *.symvers
	$(MAKE) -C $(KDIR) SUBDIRS=$(PWD) modules
	$(RM) *.mod.c *.o .*.cmd *.symvers
	rm -rf .tmp_version* *~
	rm -rf Module.markers modules.*
	rm -rf .*.tmp
clean:
	$(RM) *.mod.c *.o *.ko .*.cmd *.symvers
	rm -rf .tmp_version* *~
	rm -rf Module.markers modules.*
	rm -rf .*.tmp .*.mk *.o.ur-safe

