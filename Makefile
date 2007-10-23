
# $Id: Makefile,v 1.6 2005/07/08 21:49:02 lars Exp $

NAME=pf4lin
VERSION=0.02

ifneq ($(KERNELRELEASE),)
 obj-m	:=  pf4lin.o	
 pf4lin-objs := pf4lin_main.o 
else
KDIR	:= /lib/modules/$(shell uname -r)/build
PWD	:= $(shell pwd)

module:
	$(MAKE) -C $(KDIR) SUBDIRS=$(PWD) modules
endif

pfctl:
	 gcc -o  pfctl  pfctl.c pfctl_parser.c

dist: clean
	@echo "making new release"
	cd ..; mkdir ${NAME}-${VERSION};\
	cp $(NAME)/* ${NAME}-${VERSION};\
	tar -cvzf \
	${NAME}-${VERSION}.tar.gz ${NAME}-${VERSION}/; \
	rm -rf ${NAME}-${VERSION}/*; rmdir ${NAME}-${VERSION}; cd $(NAME)


clean:
	rm -rf *~ *.ko *.o *.mod.c pfctl .tmp_versions .pf4lin*

