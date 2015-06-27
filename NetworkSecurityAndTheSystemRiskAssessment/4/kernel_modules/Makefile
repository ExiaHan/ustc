obj-m += nssniffer.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	mkake -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
