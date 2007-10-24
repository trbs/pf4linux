#!/bin/sh

#$Id: unload.sh,v 1.1 2004/04/10 18:41:07 lars Exp $

NAME=pf4lin

echo "Unloading module $NAME.ko";
rmmod $NAME.ko

## device entry under /dev is now automaticly added and removed by udev
MAJOR=`cat /proc/devices | grep pf4lin | awk '{print $1}'`;
#echo "Removing /dev/$NAME";
#rm /dev/$NAME;
