/* $Id: pf4lin_main.c,v 1.24 2005/06/28 10:17:27 lars Exp $ */

#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/if_ether.h>
#include <linux/fs.h>  
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <linux/icmp.h>
#include <linux/skbuff.h>
#include <linux/netfilter_ipv4.h>
#include <linux/version.h>

#include "pf4linvar.h"
#include "pfvar.h"

MODULE_LICENSE("Dual BSD/GPL");
MODULE_AUTHOR("Lars Olsson, lo@abstractvoid.se");
MODULE_DESCRIPTION("OpenBSD's PF (Packet Filter) for Linux");

static int pf4lin_major = PF4LIN_MAJOR;

/* changed by DIOCTOGGLEDEBUG */
int debug = 0;

/* global variables */
struct rule		*rulehead = NULL;
struct nat		*nathead = NULL;
struct rdr		*rdrhead = NULL;
struct state		*statehead = NULL;
struct tree_node	*tree_lan_ext = NULL,
			*tree_ext_gwy = NULL;
struct timeval		 tv;
struct status		 status;
struct net_device	 *status_ifp = NULL;
u_int32_t		 last_purge = 0;
u_int16_t		 next_port_tcp = 50001,
			 next_port_udp = 50001;



int pf4lin_open(struct inode *inode, struct file *filp);
int pf4lin_close(struct inode *inode, struct file *filp);
int pf4lin_ioctl(struct inode *inode, struct file *filp,
		 unsigned int cmd, unsigned long arg);
void print_host(u_int32_t a, u_int16_t p);
void print_flags (u_int8_t f);
//void print_flags(struct tcphdr *th);
void print_state(int direction, struct state *s);
inline int match_addr(u_int8_t n, u_int32_t a, u_int32_t m, u_int32_t b);
inline int match_port(u_int8_t op, u_int16_t a1, u_int16_t a2, u_int16_t p);
struct nat *get_nat(const struct net_device *ifp, u_int8_t proto, u_int32_t addr);
struct rdr *get_rdr(const struct net_device *ifp, u_int8_t proto, u_int32_t addr, u_int16_t port);
inline signed char tree_key_compare(struct tree_key *a, struct tree_key *b);
inline void tree_rotate_left(struct tree_node **p);
inline void tree_rotate_right(struct tree_node **p);
int tree_insert(struct tree_node **p, struct tree_key *key, struct state *state);
int tree_remove(struct tree_node **p, struct tree_key *key);
inline struct state *find_state(struct tree_node *p, struct tree_key *key);
void insert_state(struct state *state);
void purge_expired_states(void);
inline u_short fix(u_short cksum, u_short old, u_short new);
void change_ap(u_int32_t *a, u_int16_t *p, u_int16_t *ic, u_int16_t *pc, u_int32_t an,
	       u_int16_t pn);
void change_a(u_int32_t *a, u_int16_t *c, u_int32_t an);
void change_icmp(u_int32_t *ia, u_int16_t *ip, u_int32_t *oa, u_int32_t na,
		 u_int16_t np, u_int16_t *pc, u_int16_t *h2c, u_int16_t *ic, u_int16_t *hc);
void send_reset(int direction, const struct net_device *ifp, struct iphdr *h, struct tcphdr *th);
int pf4lin_test_flags(struct tcphdr *th, u_int8_t flagset, u_int8_t flags);
struct state *pf_test_state_tcp(int direction, const struct net_device *ifp, 
				struct iphdr *h, struct tcphdr *th);
int pf_test_tcp(int direction, const struct net_device *ifp, struct iphdr *h, struct tcphdr *th);
struct state *pf_test_state_udp(int direction, const struct net_device *ifp, 
				struct iphdr *h, struct udphdr *uh);
int pf_test_udp(int direction, const struct net_device *ifp, struct iphdr *h, struct udphdr *uh);
struct state *pf_test_state_icmp(int direction, const struct net_device *ifp, 
				 struct iphdr *h, struct icmphdr *ih);
int pf_test_icmp(int direction, const struct net_device *ifp, struct iphdr *h, struct icmphdr *ih);
static unsigned int pf4lin_hook(unsigned int hook, struct sk_buff **pskb, const struct net_device *indev,
				   const struct net_device *outdev, int (*okfn)(struct sk_buff *));



/* --------------------------------------------------------------------------*/


int 
pf4lin_open(struct inode *inode, struct file *filp)
{
	DEBUGMSG("open\n");

	return 0;
}


int 
pf4lin_close(struct inode *inode, struct file *filp)
{
	DEBUGMSG("close\n");

	return 0;
}



spinlock_t driver_lock = SPIN_LOCK_UNLOCKED;

int 
pf4lin_ioctl(struct inode *inode, struct file *filp,
         unsigned int cmd, unsigned long arg)
{
	int error = NO_ERROR;
	struct ioctlbuffer *ub = NULL;
	void *kb = NULL;
	//	unsigned long flags;

	
	if(_IOC_TYPE(cmd) != PF_IOC_MAGIC)
		return -ENOTTY;
	if(_IOC_NR(cmd) > PF_IOC_MAXNR)
		return -ENOTTY;
	
	
	if (_IOC_DIR(cmd) & _IOC_READ)
		error = !access_ok(VERIFY_WRITE, (void *)arg, _IOC_SIZE(cmd));
	else if (_IOC_DIR(cmd) & _IOC_WRITE)
		error =  !access_ok(VERIFY_READ, (void *)arg, _IOC_SIZE(cmd));
	if (error) return -EFAULT;

	if((cmd != DIOCSTART) && (cmd != DIOCSTOP) && 
	   (cmd != DIOCCLRSTATES) && (cmd != DIOCTOGGLEDEBUG)){
		ub = (struct ioctlbuffer *)arg;
		if (ub == NULL)
			return ERROR_INVALID_PARAMETERS;
		kb = kmalloc(ub->size, GFP_ATOMIC);
		if (kb == NULL)
			return ERROR_MALLOC;
		if (copy_from_user(kb, ub->buffer, ub->size)) {
			kfree(kb);
			return ERROR_INVALID_PARAMETERS;
		}
	}

	/* disable interrupts */
	//save_flags(flags);
	//cli();

	spin_lock_irq(&driver_lock);

	do_gettimeofday(&tv);
	if (tv.tv_sec - last_purge >= 10) {
		purge_expired_states();
		last_purge = tv.tv_sec;
	}

	switch(cmd){
	case DIOCSTART:
		DEBUGMSG("DIOCSTART\n");
		if(status.running)
			error = ERROR_ALREADY_RUNNING;
		else{
			u_int32_t states = status.states;
			memset(&status, 0, sizeof(struct status));
			status.running = 1;
			status.states = states;
			INFO("started\n");
		}
		break;
		
	case DIOCSTOP:
		DEBUGMSG("DIOCSTOP\n");
		if (!status.running)
			error = ERROR_NOT_RUNNING;
		else {
			status.running = 0;
			INFO("packetfilter: stopped\n");
		}
		break;
		
	case DIOCSETRULES:{
		struct rule *rules = (struct rule *)kb, *ruletail = NULL;
		u_int16_t n;
		
		DEBUGMSG("DIOCSETRULES\n");
		while (rulehead != NULL) {
			struct rule *next = rulehead->next;
			kfree(rulehead);
			rulehead = next;
		}
		
		for (n = 0; n < ub->entries; ++n) {
			struct rule *rule;
			rule = kmalloc(sizeof(struct rule), GFP_ATOMIC);
			if (rule == NULL) {
				error = ERROR_MALLOC;
				goto done;
			}
			memcpy(rule, rules + n, sizeof(struct rule));
			rule->ifp = NULL;
			if (rule->ifname[0]) {
				rule->ifp = dev_get_by_name(rule->ifname);
				if (rule->ifp == NULL) {
					kfree(rule);
					error = ERROR_INVALID_PARAMETERS;
					goto done;
				}
			}
			rule->next = NULL;
			if (ruletail != NULL) {
				ruletail->next = rule;
				ruletail = rule;
			} else
				rulehead = ruletail = rule;
		}
		break;
	}
	case DIOCGETRULES: {
		struct rule *rules = (struct rule *)kb;
		struct rule *rule = rulehead;
		u_int16_t n = 0;

		DEBUGMSG("DIOCGETRULES\n");
		
		while ((rule != NULL) && (n < ub->entries)) {
			memcpy(rules + n, rule, sizeof(struct rule));
			n++;
			rule = rule->next;
		}
		ub->entries = n;
		break;
	}
	case DIOCSETNAT:{
		struct nat *nats = (struct nat *)kb;
		u_int16_t n;
		
		DEBUGMSG("DIOCSETNAT\n");
		while (nathead != NULL) {
			struct nat *next = nathead->next;
			kfree(nathead);
			nathead = next;
		}
		for (n = 0; n < ub->entries; ++n) {
			struct nat *nat;
			nat = kmalloc(sizeof(struct nat), GFP_ATOMIC);
			if (nat == NULL) {
				error = ERROR_MALLOC;
				goto done;
			}
			memcpy(nat, nats + n, sizeof(struct nat));
			nat->ifp = dev_get_by_name(nat->ifname);
			if (nat->ifp == NULL) {
				kfree(nat);
				error = ERROR_INVALID_PARAMETERS;
				goto done;
			}
			nat->next = nathead;
			nathead = nat;
		}
		break;
	}
	case DIOCGETNAT:{
		struct nat *nats = (struct nat *)kb;
		struct nat *nat = nathead;
		u_int16_t n = 0;
		
		DEBUGMSG("DIOCGETNAT\n");
		
		while ((nat != NULL) && (n < ub->entries)) {
			memcpy(nats + n, nat, sizeof(struct nat));
			n++;
			nat = nat->next;
		}
		ub->entries = n;
		break;
	}
	case DIOCSETRDR:{
		struct rdr *rdrs = (struct rdr *)kb;
		u_int16_t n;
		
		DEBUGMSG("DIOCSETRDR\n");
		
		while (rdrhead != NULL) {
			struct rdr *next = rdrhead->next;
			kfree(rdrhead);
			rdrhead = next;
		}
		for (n = 0; n < ub->entries; ++n) {
			struct rdr *rdr;
			rdr = kmalloc(sizeof(struct rdr), GFP_ATOMIC);
			if (rdr == NULL) {
				error = ERROR_MALLOC;
				goto done;
			}
			memcpy(rdr, rdrs + n, sizeof(struct rdr));
			rdr->ifp = dev_get_by_name(rdr->ifname);
			if (rdr->ifp == NULL) {
				kfree(rdr);
				error = ERROR_INVALID_PARAMETERS;
				goto done;
			}
			rdr->next = rdrhead;
			rdrhead = rdr;
		}
		break;
	}
	case DIOCGETRDR:{
		struct rdr *rdrs = (struct rdr *)kb;
		struct rdr *rdr = rdrhead;
		u_int16_t n = 0;
		
		DEBUGMSG("DIOCGETRDR\n");

		while ((rdr != NULL) && (n < ub->entries)) {
			memcpy(rdrs + n, rdr, sizeof(struct rdr));
			n++;
			rdr = rdr->next;
		}
		ub->entries = n;
		break;
	}
	case DIOCCLRSTATES:{
		struct state *state = statehead;
		
		DEBUGMSG("DIOCCLRSTATES\n");

		while (state != NULL) {
			state->expire = 0;
			state = state->next;
		}
		purge_expired_states();
		break;
	}
	case DIOCGETSTATES:{
		struct state *states = (struct state *)kb;
		struct state *state;
		u_int16_t n = 0;

		DEBUGMSG("DIOCGETSTATES\n");
		
		state = statehead;
		while ((state != NULL) && (n < ub->entries)) {
			printk("get state\n");
			memcpy(states + n, state, sizeof(struct state));
			states[n].creation = tv.tv_sec - states[n].creation;
			if (states[n].expire <= tv.tv_sec)
				states[n].expire = 0;
			else
				states[n].expire -= tv.tv_sec;
			n++;
			state = state->next;
		}
		ub->entries = n;
		break;
	}
	case DIOCSETSTATUSIF:{
		char *ifname = (char *)kb;
		struct net_device *ifp = dev_get_by_name(ifname);

		DEBUGMSG("DIOCSETSTATUSIF\n");

		if (ifp == NULL)
			error = ERROR_INVALID_PARAMETERS;
		else
			status_ifp = ifp;
		break;
	}
	case DIOCGETSTATUS:{
		struct status *st = (struct status *)kb;
		u_int8_t running = status.running;
		u_int32_t states = status.states;
		
		DEBUGMSG("DIOCGETSTATUSIF\n");
		
		memcpy(st, &status, sizeof(struct status));
		st->since = st->since ? tv.tv_sec - st->since : 0;
		ub->entries = 1;
		memset(&status, 0, sizeof(struct status));
		status.running = running;
		status.states = states;
		status.since = tv.tv_sec;
		break;
	}	
	case DIOCTOGGLEDEBUG:
		DEBUGMSG("DIOCTOGGLEDEBUG\n");
		if(debug)
			debug = 0;
		else
			debug = 1;
		
		INFO("debug is now:%s\n", (debug)? "ON" : "OFF"); 
		
		break;
	default:
		DEBUGMSG("default ioctl - error\n");
		error = ERROR_INVALID_OP;
		break;
	}

 done:
	/* enable interrupts */
	//	restore_flags(flags);
	spin_unlock_irq(&driver_lock);

	if (kb != NULL) {
		if (copy_to_user(ub->buffer, kb, ub->size))
			error = ERROR_INVALID_PARAMETERS;
		kfree(kb);
	}
	
	return error;
}


/* --------------------------------------------------------------------------*/


void
print_host(u_int32_t a, u_int16_t p)
{
	a = ntohl(a);
	p = ntohs(p);
	printk("%u.%u.%u.%u:%u", (a>>24)&255, (a>>16)&255, (a>>8)&255, a&255, p);
}

void
print_state(int direction, struct state *s)
{
	print_host(s->lan.addr, s->lan.port);
	printk(" ");
	print_host(s->gwy.addr, s->gwy.port);
	printk(" ");
	print_host(s->ext.addr, s->ext.port);
	printk(" [%lu+%lu]", (long unsigned int)(s->src.seqlo), (long unsigned int)(s->src.seqhi - s->src.seqlo));
	printk(" [%lu+%lu]", (long unsigned int)(s->dst.seqlo), (long unsigned int)(s->dst.seqhi - s->dst.seqlo));
	printk(" %u:%u", s->src.state, s->dst.state);
}


void
print_flags(u_int8_t f)
{
	if (f) printk(" ");
	if (f & TH_FIN ) printk("F");
	if (f & TH_SYN ) printk("S");
	if (f & TH_RST ) printk("R");
	if (f & TH_PUSH) printk("P");
	if (f & TH_ACK ) printk("A");
	if (f & TH_URG ) printk("U");
}


/* ------------------------------------------------------------------------ */

inline int
match_addr(u_int8_t n, u_int32_t a, u_int32_t m, u_int32_t b)
{
	return n == !((a & m) == (b & m));
}


inline int
match_port(u_int8_t op, u_int16_t a1, u_int16_t a2, u_int16_t p)
{
	switch (op) {
		case 1: return (p >= a1) && (p <= a2);
		case 2: return p == a1;
		case 3: return p != a1;
		case 4: return p <  a1;
		case 5: return p <= a1;
		case 6: return p >  a1;
		case 7: return p >= a1;
	}
	return 0; /* never reached */
}


/* ------------------------------------------------------------------------ */

struct nat *
get_nat(const struct net_device *ifp, u_int8_t proto, u_int32_t addr)
{
	struct nat *n = nathead, *nm = NULL;

	while ((n != NULL) && (nm == NULL)) {
		if ((n->ifp == ifp) &&
		    (!n->proto || (n->proto == proto)) &&
		    match_addr(n->not, n->saddr, n->smask, addr))
			nm = n;
		else
			n = n->next;
	}
	return nm;
}


struct rdr *
get_rdr(const struct net_device *ifp, u_int8_t proto, u_int32_t addr, u_int16_t port)
{
	struct rdr *r = rdrhead, *rm = NULL;
	while ((r != NULL) && (rm == NULL)) {
		if ((r->ifp == ifp) &&
		    (!r->proto || (r->proto == proto)) &&
		    match_addr(r->not, r->daddr, r->dmask, addr) &&
		    (r->dport == port))
			rm = r;
		else
			r = r->next;
	}
	return rm;
}

/* ------------------------------------------------------------------- */

inline signed char
tree_key_compare(struct tree_key *a, struct tree_key *b)
{
	/*
	 * could use memcmp(), but with the best manual order, we can
	 * minimize the number of average compares. what is faster?
	 */
	if (a->proto   < b->proto  ) return -1;
	if (a->proto   > b->proto  ) return  1;
	if (a->addr[0] < b->addr[0]) return -1;
	if (a->addr[0] > b->addr[0]) return  1;
	if (a->addr[1] < b->addr[1]) return -1;
	if (a->addr[1] > b->addr[1]) return  1;
	if (a->port[0] < b->port[0]) return -1;
	if (a->port[0] > b->port[0]) return  1;
	if (a->port[1] < b->port[1]) return -1;
	if (a->port[1] > b->port[1]) return  1;
	return 0;
}


inline void
tree_rotate_left(struct tree_node **p)
{
	struct tree_node *q = *p;
	*p = (*p)->right;
	q->right = (*p)->left;
	(*p)->left = q;
	q->balance--;
	if ((*p)->balance > 0)
		q->balance -= (*p)->balance;
	(*p)->balance--;
	if (q->balance < 0)
		(*p)->balance += q->balance;
}


inline void
tree_rotate_right(struct tree_node **p)
{
	struct tree_node *q = *p;
	*p = (*p)->left;
	q->left = (*p)->right;
	(*p)->right = q;
	q->balance++;
	if ((*p)->balance < 0)
		q->balance -= (*p)->balance;
	(*p)->balance++;
	if (q->balance > 0)
		(*p)->balance += q->balance;
}


int
tree_insert(struct tree_node **p, struct tree_key *key, struct state *state)
{
	int deltaH = 0;
	if (*p == NULL) {
		*p = kmalloc(sizeof(struct tree_node), GFP_ATOMIC);
		if (*p == NULL) {
			ERR("packetfilter: malloc() failed\n");
			return 0;
		}
		memcpy(&(*p)->key, key, sizeof(struct tree_key));
		(*p)->state = state;
		(*p)->balance = 0;
		(*p)->left = (*p)->right = NULL;
		deltaH = 1;
	} else if (tree_key_compare(key, &(*p)->key) > 0) {
		if (tree_insert(&(*p)->right, key, state)) {
			(*p)->balance++;
			if ((*p)->balance == 1)
				deltaH = 1;
			else if ((*p)->balance == 2) {
				if ((*p)->right->balance == -1)
					tree_rotate_right(&(*p)->right);
				tree_rotate_left(p);
			}
		}
	} else {
		if (tree_insert(&(*p)->left, key, state)) {
			(*p)->balance--;
			if ((*p)->balance == -1)
				deltaH = 1;
			else if ((*p)->balance == -2) {
				if ((*p)->left->balance == 1)
					tree_rotate_left(&(*p)->left);
				tree_rotate_right(p);
			}
		}
	}
	return deltaH;
}


int
tree_remove(struct tree_node **p, struct tree_key *key)
{
	int deltaH = 0;
	signed char c;
	if (*p == NULL)
		return 0;
	c = tree_key_compare(key, &(*p)->key);
	if (c < 0) {
		if (tree_remove(&(*p)->left, key)) {
			(*p)->balance++;
			if ((*p)->balance == 0)
				deltaH = 1;
			else if ((*p)->balance == 2) {
				if ((*p)->right->balance == -1)
					tree_rotate_right(&(*p)->right);
				tree_rotate_left(p);
				if ((*p)->balance == 0)
					deltaH = 1;
			}
		}
	} else if (c > 0) {
		if (tree_remove(&(*p)->right, key)) {
			(*p)->balance--;
			if ((*p)->balance == 0)
				deltaH = 1;
			else if ((*p)->balance == -2) {
				if ((*p)->left->balance == 1)
					tree_rotate_left(&(*p)->left);
				tree_rotate_right(p);
				if ((*p)->balance == 0)
					deltaH = 1;
			}
		}
	} else {
		if ((*p)->right == NULL) {
			struct tree_node *p0 = *p;
			*p = (*p)->left;
			kfree(p0);
			deltaH = 1;
		} else if ((*p)->left == NULL) {
			struct tree_node *p0 = *p;
			*p = (*p)->right;
			kfree(p0);
			deltaH = 1;
		} else {
			struct tree_node **qq = &(*p)->left;
			while ((*qq)->right != NULL)
				qq = &(*qq)->right;
			memcpy(&(*p)->key, &(*qq)->key, sizeof(struct tree_key));
			(*p)->state = (*qq)->state;
			memcpy(&(*qq)->key, key, sizeof(struct tree_key));
			if (tree_remove(&(*p)->left, key)) {
				(*p)->balance++;
				if ((*p)->balance == 0)
					deltaH = 1;
				else if ((*p)->balance == 2) {
					if ((*p)->right->balance == -1)
						tree_rotate_right(&(*p)->right);
					tree_rotate_left(p);
					if ((*p)->balance == 0)
						deltaH = 1;
				}
			}
		}
	}
	return deltaH;
}


inline struct state *
find_state(struct tree_node *p, struct tree_key *key)
{
	signed char c;
	while ((p != NULL) && (c = tree_key_compare(&p->key, key)))
		p = (c > 0) ? p->left : p->right;
	status.state_searches++;
	return p ? p->state : NULL;
}


void
insert_state(struct state *state)
{
	struct tree_key key;

	key.proto = state->proto;
	key.addr[0] = state->lan.addr;
	key.port[0] = state->lan.port;
	key.addr[1] = state->ext.addr;
	key.port[1] = state->ext.port;
	/* sanity checks can be removed later, should never occur */
	if (find_state(tree_lan_ext, &key) != NULL)
		printk("packetfilter: ERROR! insert invalid\n");
	else {
		tree_insert(&tree_lan_ext, &key, state);
		if (find_state(tree_lan_ext, &key) != state)
			ERR("packetfilter: ERROR! insert failed\n");
	}

	key.proto   = state->proto;
	key.addr[0] = state->ext.addr;
	key.port[0] = state->ext.port;
	key.addr[1] = state->gwy.addr;
	key.port[1] = state->gwy.port;
	if (find_state(tree_ext_gwy, &key) != NULL)
		ERR("packetfilter: ERROR! insert invalid\n");
	else {
		tree_insert(&tree_ext_gwy, &key, state);
		if (find_state(tree_ext_gwy, &key) != state)
			ERR("packetfilter: ERROR! insert failed\n");
	}

	state->next = statehead;
	statehead = state;

	status.state_inserts++;
	status.states++;
}


void
purge_expired_states(void)
{
	struct tree_key key;
	struct state *cur = statehead, *prev = NULL;
	while (cur != NULL) {
		if (cur->expire <= tv.tv_sec) {
			key.proto = cur->proto;
			key.addr[0] = cur->lan.addr;
			key.port[0] = cur->lan.port;
			key.addr[1] = cur->ext.addr;
			key.port[1] = cur->ext.port;
			/* sanity checks can be removed later */
			if (find_state(tree_lan_ext, &key) != cur)
				ERR("packetfilter: ERROR! remove invalid\n");
			tree_remove(&tree_lan_ext, &key);
			if (find_state(tree_lan_ext, &key) != NULL)
				ERR("packetfilter: ERROR! remove failed\n");
			key.proto   = cur->proto;
			key.addr[0] = cur->ext.addr;
			key.port[0] = cur->ext.port;
			key.addr[1] = cur->gwy.addr;
			key.port[1] = cur->gwy.port;
			if (find_state(tree_ext_gwy, &key) != cur)
				ERR("packetfilter: ERROR! remove invalid\n");
			tree_remove(&tree_ext_gwy, &key);
			if (find_state(tree_ext_gwy, &key) != NULL)
				ERR("packetfilter: ERROR! remove failed\n");
			
			//(prev ? prev->next : statehead) = cur->next;
			
			if(prev)
				prev->next = cur->next;
			else
				statehead = cur->next;


			kfree(cur);
			cur = (prev ? prev->next : statehead);
			status.state_removals++;
			status.states--;
		} else {
			prev = cur;
			cur = cur->next;
		}
	}
}


/* ------------------------------------------------------------------------ */

inline u_short
fix(u_short cksum, u_short old, u_short new)
{
	u_long l = cksum + old - new;
	l = (l >> 16) + (l & 65535); 
	l = l & 65535;
	return l ? l : 65535;
}  


void
change_ap(u_int32_t *a, u_int16_t *p, u_int16_t *ic, u_int16_t *pc, u_int32_t an,
    u_int16_t pn)
{
	u_int32_t ao = *a;
	u_int16_t po = *p;
	*a = an;
	*ic = fix(fix(*ic, ao / 65536, an / 65536), ao % 65536, an % 65536);
	*p = pn;
	*pc = fix(fix(fix(*pc, ao / 65536, an / 65536), ao % 65536, an % 65536),
	    po, pn);
}


void
change_a(u_int32_t *a, u_int16_t *c, u_int32_t an)
{
	u_int32_t ao = *a;
	*a = an;
	*c = fix(fix(*c, ao / 65536, an / 65536), ao % 65536, an % 65536);
}


void
change_icmp(u_int32_t *ia, u_int16_t *ip, u_int32_t *oa, u_int32_t na,
    u_int16_t np, u_int16_t *pc, u_int16_t *h2c, u_int16_t *ic, u_int16_t *hc)
{
	u_int32_t oia = *ia, ooa = *oa, opc = *pc, oh2c = *h2c;
	u_int16_t oip = *ip;
	// change inner protocol port, fix inner protocol checksum
	*ip = np;
	*pc = fix(*pc, oip, *ip);
	*ic = fix(*ic, oip, *ip);
	*ic = fix(*ic, opc, *pc);
	// change inner ip address, fix inner ip checksum and icmp checksum
	*ia = na;
	*h2c = fix(fix(*h2c, oia / 65536, *ia / 65536), oia % 65536, *ia % 65536);
	*ic = fix(fix(*ic, oia / 65536, *ia / 65536), oia % 65536, *ia % 65536);
	*ic = fix(*ic, oh2c, *h2c);
	// change outer ip address, fix outer ip checksum
	*oa = na;
	*hc = fix(fix(*hc, ooa / 65536, *oa / 65536), ooa % 65536, *oa % 65536);
}


void
send_reset(int direction, const struct net_device *ifp, struct iphdr *h, struct tcphdr *th)
{
	/*
	struct mbuf *m;
	int len = sizeof(struct iphdr) + sizeof(struct tcphdr);
	struct ip *h2;
	struct tcphdr *th2;
	*/

	ERR("send_reset not implemented!!\n");
}



/* ----------------------------------------------------------------------------- */


	
/*
 * Watch out!!!! h->tot_len is at this stage in network order in Linux but not OpenBSD!
 * So, use ntohs everywhere for h->tot_len. This took me a while to figure out :-)
 *
 */

struct state *
pf_test_state_tcp(int direction, const struct net_device *ifp, struct iphdr *h, struct tcphdr *th)
{
	struct state *s;
	struct tree_key key;

	key.proto   = IPPROTO_TCP;
	key.addr[0] = h->saddr;
	key.port[0] = th->source;
	key.addr[1] = h->daddr;
	key.port[1] = th->dest;

	s = find_state((direction == PF_IN) ? tree_ext_gwy : tree_lan_ext, &key);
	if (s != NULL) {
		
		u_int16_t len = ntohs(h->tot_len) - ((h->ihl + th->doff) << 2);
		u_int32_t seq = ntohl(th->seq), ack = ntohl(th->ack_seq);

		struct peer *src, *dst;
		if (direction == s->direction) {
			src = &s->src;
			dst = &s->dst;
		} else {
			src = &s->dst;
			dst = &s->src;
		}

		/* some senders do that instead of ACKing FIN */
		if ((th->rst) && !ack && !len &&
		    ((seq == src->seqhi) || (seq == src->seqhi-1)) &&
		    (src->state >= 4) && (dst->state >= 3))
			ack = dst->seqhi;

		if ((dst->seqhi >= dst->seqlo ?
		    (ack >= dst->seqlo) && (ack <= dst->seqhi) :
		    (ack >= dst->seqlo) || (ack <= dst->seqhi)) ||
		    (seq == src->seqlo) || (seq == src->seqlo-1)) {

			s->packets++;
			s->bytes += len;

			/* update sequence number range */
			if (th->ack)
				dst->seqlo = ack;
			if (th->syn || th->fin)
				len++;
			if (th->syn) {
				src->seqhi = seq + len;
				src->seqlo = src->seqhi - 1;
			} else if ((seq + len) - src->seqhi < 65536)
				src->seqhi = seq + len;

			/* update states */
			if (th->syn)
				if (src->state < 1)
					src->state = 1;
			if (th->fin)
				if (src->state < 3)
					src->state = 3;
			if ((th->ack) && (ack == dst->seqhi)) {
				if (dst->state == 1)
					dst->state = 2;
				else if (dst->state == 3)
					dst->state = 4;
			}
			if (th->rst)
				src->state = dst->state = 5;

			/* update expire time */
			if ((src->state >= 4) && (dst->state >= 4))
				s->expire = tv.tv_sec + 5;
			else if ((src->state >= 3) || (dst->state >= 3))
				s->expire = tv.tv_sec + 300;
			else if ((src->state < 2) || (dst->state < 2))
				s->expire = tv.tv_sec + 30;
			else
				s->expire = tv.tv_sec + 24*60*60;

			/* translate source/destination address, if necessary */
			if ((s->lan.addr != s->gwy.addr)
			    || (s->lan.port != s->gwy.port)) {
				if (direction == PF_OUT)
					change_ap(&h->saddr, &th->source,
					    &h->check, &th->check,
					    s->gwy.addr, s->gwy.port);
				else
					change_ap(&h->daddr, &th->dest,
					    &h->check, &th->check,
					    s->lan.addr, s->lan.port);
			}

		} else {
			struct tcphdrbsd *th2 = (struct tcphdrbsd*)th;
			printk("packetfilter: BAD state: ");
			print_state(direction, s);
			print_flags(th2->th_flags);
			printk(" seq=%lu ack=%lu len=%u ", (long unsigned int)seq, (long unsigned int)ack, len);
			printk("\n");
			s = NULL;
		}

		return s;
	}
	return NULL;
}


int
pf_test_tcp(int direction, const struct net_device *ifp, struct iphdr *h, struct tcphdr *th)
{
	struct nat *nat = NULL;
	struct rdr *rdr = NULL;
	u_int32_t baddr = 0;
	u_int16_t bport = 0;
	struct rule *r = rulehead, *rm = NULL;
	u_int16_t nr = 1, mnr = 0;
	struct tcphdrbsd *th2 = (struct tcphdrbsd *)th;

	if (direction == PF_OUT) {
		/* check outgoing packet for NAT */
		if ((nat = get_nat(ifp, IPPROTO_TCP, h->saddr)) != NULL) {
			baddr = h->saddr;
			bport = th->source;
			change_ap(&h->saddr, &th->source, &h->check,
			    &th->check, nat->daddr, htons(next_port_tcp));
		}
	} else {
		/* check incoming packet for RDR */
		if ((rdr = get_rdr(ifp, IPPROTO_TCP, h->daddr,
		    th->dest)) != NULL) {
			baddr = h->daddr;
			bport = th->dest;
			change_ap(&h->daddr, &th->dest,
			    &h->check, &th->check, rdr->raddr, rdr->rport);
		}
	}

	while (r != NULL) {
		if ((r->direction == direction) &&
		    ((r->ifp == NULL) || (r->ifp == ifp)) &&
		    (!r->proto || (r->proto == IPPROTO_TCP)) &&		
		    ((th2->th_flags & r->flagset) == r->flags) && 		    
		    (!r->src.addr || match_addr(r->src.not, r->src.addr,
		    r->src.mask, h->saddr)) &&
		    (!r->dst.addr || match_addr(r->dst.not, r->dst.addr,
		    r->dst.mask, h->daddr)) &&
		    (!r->dst.port_op || match_port(r->dst.port_op, r->dst.port[0],
		    r->dst.port[1], th->dest)) &&
		    (!r->src.port_op || match_port(r->src.port_op, r->src.port[0],
		    r->src.port[1], th->source)) ) {
			rm = r;
			mnr = nr;
			if (r->quick)
				break;
		}
		r = r->next;
		nr++;
	}

	if ((rm != NULL) && rm->log) {
		u_int32_t seq = ntohl(th->seq);
		u_int16_t len = ntohs(h->tot_len) - ((h->ihl + th->doff) << 2);

		printk("packetfilter: @%u", mnr);
		printk(" %s %s", rm->action ? "block" : "pass", direction ? "out" :
		    "in");
		printk(" on %s proto tcp", ifp->name);
		printk(" from ");
		print_host(h->saddr, th->source);
		printk(" to ");
		print_host(h->daddr, th->dest);
		print_flags(th2->th_flags);
		if (len || (th->syn || th->fin || th->rst))//& (TH_SYN | TH_FIN | TH_RST)))
			printk(" %lu:%lu(%u)", (long unsigned int)seq, (long unsigned int)(seq + len), len);
		if (th->ack_seq) printk(" ack=%lu", (long unsigned int)(ntohl(th->ack_seq)));
		printk("\n");
	}

	if ((rm != NULL) && (rm->action == PF_DROP_RST)) {
		/* undo NAT/RST changes, if they have taken place */
		if (nat != NULL)
			change_ap(&h->saddr, &th->source,
			    &h->check, &th->check, baddr, bport);
		else if (rdr != NULL)
			change_ap(&h->daddr, &th->dest,
			    &h->check, &th->check, baddr, bport);
		send_reset(direction, ifp, h, th);
		return PF_DROP;
	}

	if ((rm != NULL) && (rm->action == PF_DROP))
		return PF_DROP;

	if (((rm != NULL) && rm->keep_state) || (nat != NULL) || (rdr != NULL)) {
		/* create new state */
		u_int16_t len = ntohs(h->tot_len) - ((h->ihl + th->doff) << 2);
		struct state *s = kmalloc(sizeof(struct state), GFP_ATOMIC);
		if (s == NULL) {
			ERR("packetfilter: malloc() failed\n");
			return PF_DROP;
		}
		s->proto	= IPPROTO_TCP;
		s->direction	= direction;
		if (direction == PF_OUT) {
			s->gwy.addr	= h->saddr;
			s->gwy.port	= th->source;
			s->ext.addr	= h->daddr;
			s->ext.port	= th->dest;
			if (nat != NULL) {
				s->lan.addr	= baddr;
				s->lan.port	= bport;
				next_port_tcp++;
				if (next_port_tcp == 65535)
					next_port_tcp = 50001;
			} else {
				s->lan.addr	= s->gwy.addr;
				s->lan.port	= s->gwy.port;
			}
		} else {
			s->lan.addr	= h->daddr;
			s->lan.port	= th->dest;
			s->ext.addr	= h->saddr;
			s->ext.port	= th->source;
			if (rdr != NULL) {
				s->gwy.addr	= baddr;
				s->gwy.port	= bport;
			} else {
				s->gwy.addr	= s->lan.addr;
				s->gwy.port	= s->lan.port;
			}
		}
		s->src.seqlo	= ntohl(th->seq) + len; // ???
		s->src.seqhi	= s->src.seqlo + 1;
		s->src.state	= 1;
		s->dst.seqlo	= 0;
		s->dst.seqhi	= 0;
		s->dst.state	= 0;
		s->creation	= tv.tv_sec;
		s->expire	= tv.tv_sec + 60;
		s->packets	= 1;
		s->bytes	= len;
		insert_state(s);
	}

	return PF_PASS;
}



struct state *
pf_test_state_udp(int direction, const struct net_device *ifp, struct iphdr *h, struct udphdr *uh)
{
	struct state *s;
	struct tree_key key;

	key.proto   = IPPROTO_UDP;
	key.addr[0] = h->saddr;
	key.port[0] = uh->source;
	key.addr[1] = h->daddr;
	key.port[1] = uh->dest;

	s = find_state((direction == PF_IN) ? tree_ext_gwy : tree_lan_ext, &key);
	if (s != NULL) {

		u_int16_t len = ntohs(h->tot_len) - (h->ihl << 2) - 8;

		struct peer *src, *dst;
		if (direction == s->direction) {
			src = &s->src;
			dst = &s->dst;
		} else {
			src = &s->dst;
			dst = &s->src;
		}

		s->packets++;
		s->bytes += len;

		/* update states */
		if (src->state < 1)
			src->state = 1;
		if (dst->state == 1)
			dst->state = 2;

		/* update expire time */
		if ((src->state == 2) && (dst->state == 2))
			s->expire = tv.tv_sec + 60;
		else
			s->expire = tv.tv_sec + 20;

		/* translate source/destination address, if necessary */
		if ((s->lan.addr != s->gwy.addr)
		    || (s->lan.port != s->gwy.port)) {
			if (direction == PF_OUT)
				change_ap(&h->saddr, &uh->source,
				    &h->check, &uh->check,
				    s->gwy.addr, s->gwy.port);
			else
				change_ap(&h->daddr, &uh->dest,
					  &h->check, &uh->check,
				    s->lan.addr, s->lan.port);
		}

		return s;
	}
	return NULL;
}


int
pf_test_udp(int direction, const struct net_device *ifp, struct iphdr *h, struct udphdr *uh)
{
	struct nat *nat = NULL;
	struct rdr *rdr = NULL;
	u_int32_t baddr = 0;
	u_int16_t bport = 0;
	struct rule *r = rulehead, *rm = NULL;
	u_int16_t nr = 1, mnr = 0;

	if (direction == PF_OUT) {
		/* check outgoing packet for NAT */
		if ((nat = get_nat(ifp, IPPROTO_UDP, h->saddr)) != NULL) {
			baddr = h->saddr;
			bport = uh->source;
			change_ap(&h->saddr, &uh->source, &h->check,
			    &uh->check, nat->daddr, htons(next_port_udp));
		}
	} else {
		/* check incoming packet for RDR */
		if ((rdr = get_rdr(ifp, IPPROTO_UDP, h->daddr,
		    uh->dest)) != NULL) {
			baddr = h->daddr;
			bport = uh->dest;
			change_ap(&h->daddr, &uh->dest,
			    &h->check, &uh->check, rdr->raddr, rdr->rport);
		}
	}

	while (r != NULL) {
		if ((r->direction == direction) &&
		    ((r->ifp == NULL) || (r->ifp == ifp)) &&
		    (!r->proto || (r->proto == IPPROTO_UDP)) &&
		    (!r->src.addr || match_addr(r->src.not, r->src.addr,
		    r->src.mask, h->saddr)) &&
		    (!r->dst.addr || match_addr(r->dst.not, r->dst.addr,
		    r->dst.mask, h->daddr)) &&
		    (!r->dst.port_op || match_port(r->dst.port_op, r->dst.port[0],
		    r->dst.port[1], uh->dest)) &&
		    (!r->src.port_op || match_port(r->src.port_op, r->src.port[0],
		    r->src.port[1], uh->source)) ) {
			rm = r;
			mnr = nr;
			if (r->quick)
				break;
		}
		r = r->next;
		nr++;
	}

	if ((rm != NULL) && rm->log) {
		printk("packetfilter: @%u", mnr);
		printk(" %s %s", rm->action ? "block" : "pass", direction ? "out" :
		    "in");
		printk(" on %s proto udp", ifp->name);
		printk(" from ");
		print_host(h->saddr, uh->source);
		printk(" to ");
		print_host(h->daddr, uh->dest);
		printk("\n");
	}

	if ((rm != NULL) && (rm->action != PF_PASS))
		return PF_DROP;

	if (((rm != NULL) && rm->keep_state) || (nat != NULL) || (rdr != NULL)) {
		/* create new state */
		u_int16_t len = ntohs(h->tot_len) - (h->ihl << 2) - 8;
		struct state *s = kmalloc(sizeof(struct state), GFP_ATOMIC);
		if (s == NULL) {
			ERR("packetfilter: malloc() failed\n");
			return PF_DROP;
		}
		s->proto	= IPPROTO_UDP;
		s->direction	= direction;
		if (direction == PF_OUT) {
			s->gwy.addr	= h->saddr;
			s->gwy.port	= uh->source;
			s->ext.addr	= h->daddr;
			s->ext.port	= uh->dest;
			if (nat != NULL) {
				s->lan.addr	= baddr;
				s->lan.port	= bport;
				next_port_udp++;
				if (next_port_udp == 65535)
					next_port_udp = 50001;
			} else {
				s->lan.addr	= s->gwy.addr;
				s->lan.port	= s->gwy.port;
			}
		} else {
			s->lan.addr	= h->daddr;
			s->lan.port	= uh->dest;
			s->ext.addr	= h->saddr;
			s->ext.port	= uh->source;
			if (rdr != NULL) {
				s->gwy.addr	= baddr;
				s->gwy.port	= bport;
			} else {
				s->gwy.addr	= s->lan.addr;
				s->gwy.port	= s->lan.port;
			}
		}
		s->src.seqlo	= 0;
		s->src.seqhi	= 0;
		s->src.state	= 1;
		s->dst.seqlo	= 0;
		s->dst.seqhi	= 0;
		s->dst.state	= 0;
		s->creation	= tv.tv_sec;
		s->expire	= tv.tv_sec + 30;
		s->packets	= 1;
		s->bytes	= len;
		insert_state(s);
	}

	return PF_PASS;
}


int
pf_test_icmp(int direction, const struct net_device *ifp, struct iphdr *h, struct icmphdr *ih)
{
	struct nat *nat = NULL;
	u_int32_t baddr = 0;
	struct rule *r = rulehead, *rm = NULL;
	u_int16_t nr = 1, mnr = 0;

	if (direction == PF_OUT) {
		/* check outgoing packet for NAT */
		if ((nat = get_nat(ifp, IPPROTO_ICMP, h->saddr)) != NULL) {
			baddr = h->saddr;
			change_a(&h->saddr, &h->check, nat->daddr);
		}
	}

	while (r != NULL) {
		if ((r->direction == direction) &&
		    ((r->ifp == NULL) || (r->ifp == ifp)) &&
		    (!r->proto || (r->proto == IPPROTO_ICMP)) &&
		    (!r->src.addr || match_addr(r->src.not, r->src.addr,
		    r->src.mask, h->saddr)) &&
		    (!r->dst.addr || match_addr(r->dst.not, r->dst.addr,
		    r->dst.mask, h->daddr)) &&
		    (!r->type || (r->type == ih->type + 1)) &&
		    (!r->code || (r->code == ih->code + 1)) ) {
			rm = r;
			mnr = nr;
			if (r->quick)
				break;
		}
		r = r->next;
		nr++;
	}

	if ((rm != NULL) && rm->log) {
		printk("packetfilter: @%u", mnr);
		printk(" %s %s", rm->action ? "block" : "pass", direction ? "out" :
		    "in");
		printk(" on %s proto icmp", ifp->name);
		printk(" from ");
		print_host(h->saddr, 0);
		printk(" to ");
		print_host(h->daddr, 0);
		printk(" type %u/%u", ih->type, ih->code);
		printk("\n");
	}

	if ((rm != NULL) && (rm->action != PF_PASS))
		return PF_DROP;

	if (((rm != NULL) && rm->keep_state) || (nat != NULL)) {
		/* create new state */
		u_int16_t len = h->tot_len - (h->ihl << 2) - 8;
		u_int16_t id = ih->un.echo.id;
		struct state *s = kmalloc(sizeof(struct state), GFP_ATOMIC);
		if (s == NULL) {
			ERR("packetfilter: malloc() failed\n");
			return PF_DROP;
		}
		s->proto	= IPPROTO_ICMP;
		s->direction	= direction;
		if (direction == PF_OUT) {
			s->gwy.addr	= h->saddr;
			s->gwy.port	= id;
			s->ext.addr	= h->daddr;
			s->ext.port	= id;
			s->lan.addr	= nat ? baddr : s->gwy.addr;
			s->lan.port	= id;
		} else {
			s->lan.addr	= h->daddr;
			s->lan.port	= id;
			s->ext.addr	= h->saddr;
			s->ext.port	= id;
			s->gwy.addr	= s->lan.addr;
			s->gwy.port	= id;
		}
		s->src.seqlo	= 0;
		s->src.seqhi	= 0;
		s->src.state	= 0;
		s->dst.seqlo	= 0;
		s->dst.seqhi	= 0;
		s->dst.state	= 0;
		s->creation	= tv.tv_sec;
		s->expire	= tv.tv_sec + 20;
		s->packets	= 1;
		s->bytes	= len;
		insert_state(s);
	}

	return PF_PASS;
}


struct state *
pf_test_state_icmp(int direction, const struct net_device *ifp, struct iphdr *h, struct icmphdr *ih)
{
	u_int16_t len = ntohs(h->tot_len) - (h->ihl << 2) - 8;

	if ((ih->type != ICMP_HOST_UNREACH) &&
	    (ih->type != ICMP_SOURCE_QUENCH) &&
	    (ih->type != ICMP_REDIRECT) &&
	    (ih->type != ICMP_TIME_EXCEEDED) &&
	    (ih->type != ICMP_PARAMETERPROB)) {

		/*
		 * ICMP query/reply message not related to a TCP/UDP packet.
		 * Search for an ICMP state.
		 */

		struct state *s;
		struct tree_key key;

		key.proto   = IPPROTO_ICMP;
		key.addr[0] = h->saddr;
		key.port[0] = ih->un.echo.id;
		key.addr[1] = h->daddr;
		key.port[1] = ih->un.echo.id;

		s = find_state((direction == PF_IN) ? tree_ext_gwy :
		    tree_lan_ext, &key);
		if (s != NULL) {

			s->packets++;
			s->bytes += len;
			s->expire = tv.tv_sec + 10;

			/* translate source/destination address, if necessary */
			if (s->lan.addr != s->gwy.addr) {
				if (direction == PF_OUT)
					change_a(&h->saddr, &h->check,
					    s->gwy.addr);
				else
					change_a(&h->daddr, &h->check,
					    s->lan.addr);
			}

			return s;
		}
		return NULL;

	} else {

		/*
		 * ICMP error message in response to a TCP/UDP packet.
		 * Extract the inner TCP/UDP header and search for that state.
		 */

		struct iphdr *h2 = (struct iphdr *)(((char *)ih) + 8);
		if (len < 28) {
			ERR("packetfilter: ICMP error message too short\n");
			return NULL;
		}
		switch (h2->protocol) {
		case IPPROTO_TCP: {
			struct tcphdr *th = (struct tcphdr *)(((char *)h2) + 20);
			u_int32_t seq = ntohl(th->seq);
			struct tcphdrbsd *th2 = (struct tcphdrbsd *)th; 
			
			struct state *s;
			struct tree_key key;
			struct peer *src;

			key.proto   = IPPROTO_TCP;
			key.addr[0] = h2->daddr;
			key.port[0] = th->dest;
			key.addr[1] = h2->saddr;
			key.port[1] = th->source;

			s = find_state((direction == PF_IN) ? tree_ext_gwy :
			    tree_lan_ext, &key);
			if (s == NULL)
				return NULL;

			src = (direction == s->direction) ?  &s->dst : &s->src;

			if ((src->seqhi >= src->seqlo ?
			    (seq < src->seqlo) || (seq > src->seqhi) :
			    (seq < src->seqlo) && (seq > src->seqhi))) {
				printk("packetfilter: BAD ICMP state: ");
				print_state(direction, s);
				print_flags(th2->th_flags);
				printk(" seq=%lu\n", (long unsigned int)seq);
				return NULL;
			}

			if ((s->lan.addr != s->gwy.addr) ||
			    (s->lan.port != s->gwy.port)) {
				if (direction == PF_IN) {
					change_icmp(&h2->saddr,
					    &th->source, &h->daddr,
					    s->lan.addr, s->lan.port, &th->check,
					    &h2->check, &ih->checksum,
					    &h->check);
				} else {
					change_icmp(&h2->daddr,
					    &th->dest, &h->saddr,
					    s->gwy.addr, s->gwy.port, &th->check,
					    &h2->check, &ih->checksum,
					    &h->check);
				}
			}
			return s;
			break;
		}
		case IPPROTO_UDP: {
			struct udphdr *uh = (struct udphdr *)(((char *)h2) + 20);
			struct state *s;
			struct tree_key key;

			key.proto   = IPPROTO_UDP;
			key.addr[0] = h2->daddr;
			key.port[0] = uh->dest;
			key.addr[1] = h2->saddr;
			key.port[1] = uh->source;

			s = find_state((direction == PF_IN) ? tree_ext_gwy :
			    tree_lan_ext, &key);
			if (s == NULL)
				return NULL;

			if ((s->lan.addr != s->gwy.addr) ||
			    (s->lan.port != s->gwy.port)) {
				if (direction == PF_IN) {
					change_icmp(&h2->saddr,
					    &uh->source, &h->daddr,
					    s->lan.addr, s->lan.port, &uh->check,
					    &h2->check, &ih->checksum,
					    &h->check);
				} else {
					change_icmp(&h2->daddr,
					    &uh->dest, &h->saddr,
					    s->gwy.addr, s->gwy.port, &uh->check,
					    &h2->check, &ih->checksum,
					    &h->check);
				}
			}
			return s;
			break;
		}
		default:
			printk("packetfilter: ICMP error message for bad proto\n");
			return NULL;
		}
		return NULL;

	}
}



/* -------------------------------------------------------------------------*/


static unsigned int
pf4lin_hook(unsigned int hook,
           struct sk_buff **pskb,
           const struct net_device *indev,
           const struct net_device *outdev,
           int (*okfn)(struct sk_buff *))
{
	struct sk_buff *sb = *pskb;
	#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,22))
	    struct iphdr *iph = (struct iphdr*) sb->network_header;
	#else
	    struct iphdr *iph = sb->nh.iph;
	#endif
	int action = NF_ACCEPT;
	int direction = PF_OUT;

	if (!status.running)
		return NF_ACCEPT;

	if(hook == NF_IP_FORWARD || hook == NF_IP_POST_ROUTING)
		direction = PF_OUT;
	else /* NF_IP_PRE_ROUTING */
		direction = PF_IN;
	
	DEBUGMSG("pf4lin_hook dir:%s\n", (direction == PF_IN) ? "IN" : "OUT");
	

	/* purge expire states, at most once every 10 seconds */
	do_gettimeofday(&tv);
	if ((tv.tv_sec - last_purge) >= 10) {
		purge_expired_states();
		last_purge = tv.tv_sec;
	}
	
	switch(iph->protocol){
	case IPPROTO_TCP:{
		#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,22))
		    struct tcphdr *th = (struct tcphdr *)(sb->data + (((struct iphdr*)sb->network_header)->ihl * 4));
	    	#else
		    struct tcphdr *th = (struct tcphdr *)(sb->data + (sb->nh.iph->ihl * 4));
	    	#endif
		int pf_action = -1;
		
		DEBUGMSG("tcp: SRC=%u.%u.%u.%u:%d DST=%u.%u.%u.%u:%d\n",
			 NIPQUAD(iph->saddr), ntohs(th->source), NIPQUAD(iph->daddr), ntohs(th->dest));

		
		if (pf_test_state_tcp(direction, indev, iph, th))
			action = NF_ACCEPT;
		else
			pf_action = pf_test_tcp(direction, indev, iph, th);

		if(pf_action != -1)
			action = (pf_action == PF_PASS) ? NF_ACCEPT : NF_DROP;

		DEBUGMSG("tcp: %s packet\n", (action == NF_ACCEPT) ? "ACCEPT" : "DROP");
		
		break;
	}
	case IPPROTO_UDP:{
		#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,22))
		    struct udphdr *uh = (struct udphdr *)(sb->data + (((struct iphdr*)sb->network_header)->ihl * 4));
	    	#else
		    struct udphdr *uh = (struct udphdr *)(sb->data + (sb->nh.iph->ihl * 4));			
	    	#endif
		int pf_action = -1;
		
		DEBUGMSG("udp: SRC=%u.%u.%u.%u:%d DST=%u.%u.%u.%u:%d\n",
			 NIPQUAD(iph->saddr), ntohs(uh->source), NIPQUAD(iph->daddr), ntohs(uh->dest));

		if (pf_test_state_udp(direction, indev, iph, uh))
			action = NF_ACCEPT;
		else
			pf_action = pf_test_udp(direction, indev, iph, uh);
		
		if(pf_action != -1)
			action = (pf_action == PF_PASS) ? NF_ACCEPT : NF_DROP;

		DEBUGMSG("udp: %s packet\n", (action == NF_ACCEPT) ? "ACCEPT" : "DROP");
		
		break;
	}		
	case IPPROTO_ICMP:{
		#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,22))
		    struct icmphdr *th = (struct icmphdr *)(sb->data + (((struct iphdr*)sb->network_header)->ihl * 4));
	    	#else
		    struct icmphdr *th = (struct icmphdr *)(sb->data + (sb->nh.iph->ihl * 4));
	    	#endif
		int pf_action = -1;

		DEBUGMSG("icmp: SRC=%u.%u.%u.%u: DST=%u.%u.%u.%u:\n",
			 NIPQUAD(iph->saddr), NIPQUAD(iph->daddr));

		
		if (pf_test_state_icmp(direction, indev, iph, th))
			action = NF_ACCEPT;
		else
			pf_action = pf_test_icmp(direction, indev, iph, th);
		
		if(pf_action != -1)
			action = (pf_action == PF_PASS) ? NF_ACCEPT : NF_DROP;

		DEBUGMSG("icmp: %s packet\n", (action == NF_ACCEPT) ? "ACCEPT" : "DROP");
		
		break;
	}
	default:
		DEBUGMSG("unknown protocol!\n");
	}

	return action;
}


static struct nf_hook_ops forward_ops = {
	.hook		= pf4lin_hook,
	.owner		= THIS_MODULE,
	.pf		= PF_INET,
	.hooknum	= NF_IP_FORWARD,
	.priority	= NF_IP_PRI_FILTER,
};

static struct nf_hook_ops pre_routing_ops = {
	.hook		= pf4lin_hook,
	.owner		= THIS_MODULE,
	.pf		= PF_INET,
	.hooknum	= NF_IP_PRE_ROUTING,
	.priority	= NF_IP_PRI_FILTER,
};

static struct nf_hook_ops post_routing_ops = {
	.hook		= pf4lin_hook,
	.owner		= THIS_MODULE,
	.pf		= PF_INET,
	.hooknum	= NF_IP_POST_ROUTING,
	.priority	= NF_IP_PRI_FILTER,
};


struct file_operations pf4lin_fops = {
    ioctl:      pf4lin_ioctl,
    open:       pf4lin_open,
    release:      pf4lin_close,
};


static int pf4lin_init(void)
{
        int result;
	
	INFO("pf4lin_init\n");

	result = register_chrdev(pf4lin_major, "pf4lin", &pf4lin_fops);
	if (result < 0) {
		ERR("pf4lin: can't get major %d\n", pf4lin_major);
		return result;
	}
	if (pf4lin_major == 0) pf4lin_major = result; /* dynamic */

	nf_register_hook(&forward_ops);
	nf_register_hook(&pre_routing_ops);
	nf_register_hook(&post_routing_ops);

	memset(&status, 0, sizeof(struct status));
	
	
	return 0;
}

static void pf4lin_exit(void)
{
        INFO("pf4lin_exit\n");

	unregister_chrdev(pf4lin_major, "pf4lin");

	nf_unregister_hook(&forward_ops);
	nf_unregister_hook(&pre_routing_ops);
	nf_unregister_hook(&post_routing_ops);
}

module_init(pf4lin_init);
module_exit(pf4lin_exit);
