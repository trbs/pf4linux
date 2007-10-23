#!/bin/sh

#$Id: unload.sh,v 1.1 2004/04/10 18:41:07 lars Exp $

NAME=pf4lin
MAJOR=`cat /proc/devices | grep pf4lin | awk '{print $1}'`;

echo "Unloading module $NAME.ko";
rmmod $NAME.ko

echo "Removing /dev/$NAME";
rm /dev/$NAME;
