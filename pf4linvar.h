/* $Id: pf4linvar.h,v 1.9 2004/04/11 23:24:10 lars Exp $ */

#ifndef _PF4LINVAR_H_
#define _PF4LIN_H_

#include "pfvar.h"

#define NAME "pf4lin"
#define PF4LIN_MAJOR 0

#define ETHERADDR_STR_LEN sizeof("00:00:00:00:00:00")
#define IPADDR_STR_LEN sizeof("255.255.255.255")
#define IPADDR_LEN 4
#define ETHER_ADDR_LEN 6


/* from OpenBSD tcp.h */
#define TH_FIN    0x01
#define TH_SYN    0x02
#define TH_RST    0x04
#define TH_PUSH   0x08
#define TH_ACK    0x10
#define TH_URG    0x20
#define TH_ECE    0x40
#define TH_CWR    0x80


/* 
 * Used to cast Linux tcphdr to the BSD version with a __u8 for the flags
 * instead of a bitfield
*/
struct tcphdrbsd {
	__u16	source;
	__u16	dest;
	__u32	seq;
	__u32	ack_seq;
#if defined(__LITTLE_ENDIAN_BITFIELD)
	__u8	res1:4,
		doff:4;
#elif defined(__BIG_ENDIAN_BITFIELD)
	__8	doff:4,
		res1:4;
#else
#error	"Adjust your <asm/byteorder.h> defines"
#endif	
	__u8    th_flags; /* instead of the bitfield */
	__u16	window;
	__u16	check;
	__u16	urg_ptr;
};
	


struct tree_node {
	struct tree_key {
		u_int8_t	 proto;
		u_int32_t	 addr[2];
		u_int16_t	 port[2];
	}			 key;
	struct state		*state;
	signed char		 balance;
	struct tree_node	*left,
				*right;
};

extern int debug;

extern struct rule *rulehead;
extern struct nat *nathead;
extern struct rdr *rdrhead;
extern struct state *statehead;
extern struct tree_node *tree_lan_ext, *tree_ext_gwy;
extern struct timeval tv;
extern struct status status;
extern struct net_device *status_ifp;
extern u_int32_t last_purge;
extern u_int16_t next_port_tcp, next_port_udp;

#define DEBUGMSG(string, args...) if(debug)printk(KERN_ERR NAME ".%d: "string, __LINE__, ##args);
#define INFO(string, args...) printk(KERN_INFO NAME ".%d: " string, __LINE__, ##args)
#define ERR(string, args...) printk(KERN_ERR NAME ".%d: " string, __LINE__, ##args)

#endif /* _PF4LINVAR_H_ */
