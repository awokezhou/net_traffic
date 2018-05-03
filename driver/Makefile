
MODULE_NAME = net_traffic

obj-m := $(MODULE_NAME).o
$(MODULE_NAME)-objs := 
$(MODULE_NAME)-objs += nt_netlink.o
$(MODULE_NAME)-objs += net_traffic_drv.o

modules:
	make -C /lib/modules/`uname -r`/build/ M=`pwd` modules

.PHONY: clean_obj
clean_obj:
	rm -rf *.o *.mod.c *.order *.symvers *.cmd .tmp* .*.cmd

.PHONY: clean
clean:
	rm -f *.o *.ko *.mod.* *.symvers .$(MODULE_NAME).* .*.o.cmd
	rm -fr .tmp_versions