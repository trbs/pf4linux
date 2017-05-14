/* $Id: pfctl_parser.h,v 1.1 2004/04/03 18:29:55 lars Exp $ */

/*	$OpenBSD: pfctl_parser.h,v 1.1 2001/06/24 21:04:16 kjell Exp $ */

/*
 * Copyright (c) 2001, Daniel Hartmeier
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *    - Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer. 
 *    - Redistributions in binary form must reproduce the above
 *      copyright notice, this list of conditions and the following
 *      disclaimer in the documentation and/or other materials provided
 *      with the distribution. 
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * REGENTS OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 */

#ifndef _PFM_PARSER_H_
#define _PFM_PARSER_H_

#include "pfvar.h"

char	*next_line (char **);
int	 parse_rule (int, char *, struct rule *);
int	 parse_nat (int, char *, struct nat *);
int	 parse_rdr (int, char *, struct rdr *);
void	 print_rule (struct rule *);
void	 print_nat (struct nat *);
void	 print_rdr (struct rdr *);
void	 print_state (struct state *);
void	 print_status (struct status *);

struct pfctl {
    int dev;
    int opts;
    u_int16_t rule_nr;
    struct pfioc_rule *prule;
    struct pfioc_nat *pnat;
    struct pfioc_binat *pbinat;
    struct pfioc_rdr *prdr;
};

int	 parse_rules(FILE *, struct pfctl *);

#endif /* _PFM_PARSER_H_ */
