obj-m=net_traffic_drv.o

modules:
	make -C /lib/modules/`uname -r`/build/ M=`pwd` modules
	make clean_obj


.PHONY: clean_obj
clean_obj:
	rm -f *.o *.mod.c *.order *.symvers

.PHONY: clean
clean:
	rm -f *.ko
