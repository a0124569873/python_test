# Driver module  
  
KERNSRC ?= /lib/modules/$(shell uname -r)/build  
CC      ?= gcc  
  
obj-m := vnic.o  
  
all: vnic.ko  vnicd  
  
vnic.ko: vnic.c  
	make -C $(KERNSRC) M=$(shell pwd) modules  
vnicd: vnicd.c  
	$(CC) -o $@ $<  
  
clean:  
	find . \( -name '.tmp_versions' -o -name '*.o' -o -name '*.ko' -o -name '.*.cmd' \  
		-o -name '.*.d' -o -name '*.mod.c' -o -name '*.symvers' -o -name '*~' \) -print | xargs rm -fr;  
	rm -f vnicd 