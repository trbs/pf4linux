/* $Id: pf4lin_ioctl.h,v 1.2 2004/04/06 14:34:10 lars Exp $ */

#include <linux/fs.h>  

int pf4lin_ioctl(struct inode *inode, struct file *filp,
		 unsigned int cmd, unsigned long arg);

int pf4lin_open(struct inode *inode, struct file *filp);

int pf4lin_close(struct inode *inode, struct file *filp);

