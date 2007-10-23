#!/bin/sh

#$Id: load.sh,v 1.2 2004/04/10 18:41:07 lars Exp $

NAME=pf4lin

echo "Loading module $NAME.ko";
insmod $NAME.ko

MAJOR=`cat /proc/devices | grep pf4lin | awk '{print $1}'`;
echo "Creating /dev/$DEVNAME with major number $MAJOR";

mknod /dev/pf4lin c $MAJOR 0;
