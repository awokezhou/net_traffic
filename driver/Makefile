obj-m=net_traffic_drv.o

modules:
	make -C /lib/modules/`uname -r`/build/ M=`pwd` modules
	#make -C /usr/src/kernels/3.10.0-514.el7.x86_64 M='pwd' modules
	make clean_obj


.PHONY: clean_obj
clean_obj:
	rm -rf *.o *.mod.c *.order *.symvers *.cmd .tmp* .*.cmd

.PHONY: clean
clean:
	rm -f *.ko
