# $Id: Makefile,v 1.6 2005/07/08 21:49:02 lars Exp $

NAME=	pf4lin
VERSION=0.02
PROG=	pfctl
SRC=	pfctl.c pfctl_parser.c
CFLAGS+= -Wall -Wmissing-prototypes -Wno-uninitialized
CFLAGS+= -Wstrict-prototypes 
#MAN=	pfctl.8
DISTFILES=*.[ch] Makefile README COPYING Changelog

ifneq ($(KERNELRELEASE),)
 obj-m	:=  pf4lin.o	
 pf4lin-objs := pf4lin_main.o 
else
KDIR	:= /lib/modules/$(shell uname -r)/build
PWD	:= $(shell pwd)

all:	module pfctl

module:
	$(MAKE) -C $(KDIR) SUBDIRS=$(PWD) modules
endif

$(PROG): $(SRC)
	gcc $(CFLAGS) -o $@ $^

dist: clean
	@echo "making new release"
	cd ..; mkdir ${NAME}-${VERSION};\
	cp $(NAME)/* ${NAME}-${VERSION};\
	tar -cvzf \
	${NAME}-${VERSION}.tar.gz ${NAME}-${VERSION}/; \
	rm -rf ${NAME}-${VERSION}/*; rmdir ${NAME}-${VERSION}; cd $(NAME)


clean:
	rm -rf *~ *.ko *.o *.mod.c pfctl .tmp_versions .pf4lin* Module.symvers

