/*
 * Copyright (c) 2014 Intel Corporation, Inc.  All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * OpenIB.org BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#if HAVE_CONFIG_H
#  include <config.h>
#endif /* HAVE_CONFIG_H */

#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/time.h>
#include <unistd.h>

#include "sock.h"

int sock_rdm_getinfo(uint32_t version, const char *node, const char *service,
		     uint64_t flags, struct fi_info *hints, struct fi_info **info)
{
	return -FI_ENODATA;
}

int sock_rdm_ep(struct fid_domain *domain, struct fi_info *info,
		struct fid_ep **ep, void *context)
{
	sock_ep_t *sock_ep;
	sock_domain_t *sock_dom;

	sock_dom = container_of(domain, sock_domain_t, dom_fid);
	if(!sock_dom)
		return -FI_EINVAL;

	sock_ep = (sock_ep_t*)calloc(1, sizeof(*sock_ep));
	if(!sock_ep)
		return -FI_ENOMEM;

	sock_ep->ep.fid.fclass = FI_CLASS_EP;
	sock_ep->ep.fid.context = context;
	
	sock_ep->ep.fid.ops = /*&sock_fi_ops*/NULL;
	sock_ep->ep.ops = /*&sock_ep_ops*/ NULL;
	sock_ep->ep.cm = /*&sock_cm_ops*/ NULL;
	sock_ep->ep.msg = NULL;
	sock_ep->ep.rma = NULL;
	sock_ep->ep.tagged = NULL;
	sock_ep->ep.atomic = NULL;

	sock_ep->dom = sock_dom;

	sock_ep->sock_fd = socket(AF_INET, SOCK_STREAM, 0);
	if(sock_ep->sock_fd <0){
		free(sock_ep);
		return -FI_EAVAIL;
	}

	*ep = &sock_ep->ep;

	if(info){
		sock_ep->op_flags = info->op_flags;
		sock_ep->ep_cap = info->ep_cap;

		if(info->dest_addr){
			return sock_ep_connect(*ep, info->dest_addr, NULL, 0);
		}
	}

	if(0 != alloc_free_recv_buf_lists(sock_ep, DEF_SOCK_EP_NUM_BUFS)){
		free(sock_ep);
		return -FI_EAVAIL;
	}

	return 0;
}

int sock_rdm_pep(struct fid_fabric *fabric, struct fi_info *info,
			struct fid_pep **pep, void *context)
{
	sock_pep_t *sock_pep;
	sock_pep = (sock_pep_t*)calloc(1, sizeof(*sock_pep));
	if(!sock_pep)
		return -FI_ENOMEM;

	sock_pep->pep.fid.fclass = FI_CLASS_PEP;
	sock_pep->pep.fid.context = context;
	
	sock_pep->pep.fid.ops = /*&sock_fi_ops*/ NULL;
	sock_pep->pep.ops = /*&sock_ep_ops*/ NULL;
	sock_pep->pep.cm = /*&sock_cm_ops*/ NULL;

	sock_pep->sock_fd = socket(AF_INET, SOCK_STREAM, 0);
	if(sock_pep->sock_fd <0){
		free(sock_pep);
		return -FI_EAVAIL;
	}

	if(info){
		sock_pep->op_flags = info->op_flags;
		sock_pep->pep_cap = info->ep_cap;

		if(info->src_addr){
			if (bind(sock_pep->sock_fd, (struct sockaddr *) info->src_addr,
				 sizeof(struct sockaddr)) < 0){
				free(sock_pep);
				return -FI_EAVAIL;
			}
		}
	}

	*pep = &sock_pep->pep;
	return 0;
}


