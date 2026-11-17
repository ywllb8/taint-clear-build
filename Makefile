obj-m := taint_clear.o

# 指定内核源码路径（GitHub Actions 云端会自动配置好这个路径，不用改）
KDIR := /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)

default:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
