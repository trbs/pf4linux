/* $Id: pf4lin_ioctl.c,v 1.16 2004/04/10 14:48:20 lars Exp $ */

#include <linux/module.h>
#include <linux/kernel.h> 
#include <linux/interrupt.h> 
#include <linux/fs.h>
#include <linux/string.h>
#include <asm/uaccess.h>
#include <linux/netdevice.h>

#include "pfvar.h"
#include "pf4linvar.h"
#include "pf4lin_ioctl.h"

int pf4lin_open(struct inode *inode, struct file *filp)
{
	//DEBUGMSG("open\n");

	return 0;
}

int pf4lin_close(struct inode *inode, struct file *filp)
{
	//DEBUGMSG("close\n");

	return 0;
}

int pf4lin_ioctl(struct inode *inode, struct file *filp,
         unsigned int cmd, unsigned long arg)
{
	int error = NO_ERROR;
	struct ioctlbuffer *ub = NULL;
	void *kb = NULL;
	unsigned long flags;


	DEBUGMSG("ioctl cmd:%d\n", cmd);
	
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

	/*
	save_flags(flags);
	cli();
	*/

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

		/* XXX fixme!!! XXX */
		
		while (state != NULL) {
			state->expire = 0;
			state = state->next;
		}
		//		purge_expired_states();
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
	
	//restore_flags(flags);
	

	if (kb != NULL) {
		if (copy_to_user(ub->buffer, kb, ub->size))
			error = ERROR_INVALID_PARAMETERS;
		kfree(kb);
	}
	
	return error;
}
