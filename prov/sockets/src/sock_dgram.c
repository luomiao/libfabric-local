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
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/time.h>
#include <unistd.h>

#include "sock.h"

/* FIXME: figure out the sockd caps */
#define SOCKD_EP_CAP (FI_TAGGED | FI_MSG | FI_ATOMICS | FI_INJECT | \
		FI_RMA | FI_BUFFERED_RECV | FI_MULTI_RECV | \
		FI_READ | FI_WRITE | FI_SEND | FI_RECV | \
		FI_REMOTE_READ | FI_REMOTE_WRITE | \
		FI_REMOTE_COMPLETE | FI_REMOTE_SIGNAL | \
		FI_CANCEL | FI_TRIGGER)
#define SOCKD_OP_FLAGS (FI_INJECT | FI_MULTI_RECV | FI_EVENT | \
		FI_TRIGGER | FI_REMOTE_SIGNAL | FI_REMOTE_COMPLETE)
#define SOCKD_DOMAIN_CAP (FI_WRITE_COHERENT | FI_CONTEXT | \
		FI_USER_MR_KEY | FI_DYNAMIC_MR)
#define SOCKD_MTU (512)

static int so_rcvbuf;

void sockd_debug(char *fmt, ...)
{
	static int debug = -1;
	char *env;
	va_list ap;

	if (debug == -1) {
		env = getenv("SFI_SOCKD_DEBUG");
		if (env)
			debug = atoi(env);
		else
			debug = 0;
	}

	if (debug) {
		va_start(ap, fmt);
		vfprintf(stderr, fmt, ap);
		va_end(ap);
	}
}

int sockd_check_hints(struct fi_info *hints)
{
	switch (hints->type) {
	case FI_EP_DGRAM:
		break;
	default:
		sockd_debug("[sockd] %s: hints->type = %d, only FI_EP_DGRAM = %d is supported\n",
				__func__, hints->type, FI_EP_DGRAM);
		return -FI_ENODATA;
	}

	switch (hints->addr_format) {
	case FI_SOCKADDR:
	case FI_SOCKADDR_IN:
	case FI_SOCKADDR_IN6:
		break;
	default:
		sockd_debug("[sockd] %s: hints->addr_format = %d, supported = FI_SOCKADDR or FI_SOCKADDR_IN or FI_SOCKADDR_IN6\n",
				__func__, hints->addr_format);
		return -FI_ENODATA;
	}

	if (hints->ep_attr) {
		switch (hints->ep_attr->protocol) {
		case FI_PROTO_UNSPEC:
			break;
		default:
			sockd_debug("[sockd] %s: hints->ep_attr->protocol=%lu, supported=%d\n",
					__func__, hints->ep_attr->protocol, FI_PROTO_UNSPEC);
			return -FI_ENODATA;
		}
		if (hints->ep_attr->max_msg_size > SOCKD_MTU) {
			sockd_debug("[sockd] %s: hints->ep_attr->max_msg_size=%d, supported=%d\n",
					__func__, hints->ep_attr->max_msg_size, SOCKD_MTU);
			return -FI_ENODATA;
		}
		if (hints->ep_attr->inject_size > SOCKD_MTU) {
			sockd_debug("[sockd] %s: hints->ep_attr->inject_size=%d, supported=%d\n",
					__func__, hints->ep_attr->inject_size, SOCKD_MTU);
			return -FI_ENODATA;
		}
		if (hints->ep_attr->total_buffered_recv > so_rcvbuf) {
			sockd_debug("[sockd] %s: hints->ep_attr->total_buffered_recv=%d, supported=%d\n",
					__func__, hints->ep_attr->total_buffered_recv, so_rcvbuf);
			return -FI_ENODATA;
		}
		/* FIXME: check 
		 * max_order_raw_size,
		 * max_order_war_size,
		 * max_order_waw_size, 
		 * mem_tag_format,
		 * msg_order */
	}

	if ((hints->ep_cap & SOCKD_EP_CAP) != hints->ep_cap) {
		sockd_debug("[sockd] %s: hints->ep_cap=0x%llx, supported=0x%llx\n",
				__func__, hints->ep_cap, SOCKD_EP_CAP);
		return -FI_ENODATA;
	}

	if ((hints->op_flags & SOCKD_OP_FLAGS) != hints->op_flags) {
		sockd_debug("[sockd] %s: hints->op_flags=0x%llx, supported=0x%llx\n",
				__func__, hints->op_flags, SOCKD_OP_FLAGS);
		return -FI_ENODATA;
	}

	if (hints->domain_attr) {
		if ((hints->domain_attr->caps & SOCKD_DOMAIN_CAP) != hints->domain_attr->caps) {
			sockd_debug("[sockd] %s: hints->domain_attr->caps=0x%llx, supported=0x%llx\n",
					__func__, hints->domain_attr->caps, SOCKD_DOMAIN_CAP);
			return -FI_ENODATA;
		}

		/* FIXME: check
		 * threading, control_progress, mr_key_size, eq_data_size */
	}

	if (hints->fabric_attr) {
		/* FIXME: check name */
	}

	return 0;
}

static struct fi_info* sockd_dupinfo(struct fi_info *hints)
{
	struct fi_info *fi;
	if (!(fi = __fi_allocinfo())) {
		goto err1;
	}

	fi->next = NULL;
	fi->type = FI_EP_DGRAM;

	if (hints) {
		fi->ep_cap	= hints->ep_cap;
		fi->op_flags	= hints->op_flags;
		fi->addr_format = hints->addr_format;
	} else {
		fi->ep_cap	= SOCKD_EP_CAP;
		fi->op_flags	= SOCKD_OP_FLAGS;
		fi->addr_format = FI_SOCKADDR;
	}

	fi->ep_attr = calloc(1, sizeof (struct fi_ep_attr));
	if (!fi->ep_attr) {
		goto err2;
	}
	fi->ep_attr->protocol = FI_PROTO_UNSPEC;
	if (hints && hints->ep_attr) {
		fi->ep_attr->max_msg_size 	 = hints->ep_attr->max_msg_size;
		fi->ep_attr->inject_size  	 = hints->ep_attr->inject_size;
		fi->ep_attr->total_buffered_recv = hints->ep_attr->total_buffered_recv;
	} else {
		fi->ep_attr->max_msg_size 	 = SOCKD_MTU;
		fi->ep_attr->inject_size  	 = SOCKD_MTU;
		fi->ep_attr->total_buffered_recv = so_rcvbuf;
	}
	/* fi->ep_attr->mem_tag_format  = fi_tag_format(max_tag_value); */
	/* fi->ep_attr->msg_order 	= FI_ORDER_SAS; */

	fi->domain_attr = calloc(1, sizeof (struct fi_domain_attr));
	if (!fi->domain_attr) {
		goto err3;
	}
	fi->domain_attr->name 		  = strdup("socket");
	fi->domain_attr->threading 	  = FI_THREAD_PROGRESS;
	fi->domain_attr->control_progress = FI_PROGRESS_MANUAL;
	fi->domain_attr->data_progress 	  = FI_PROGRESS_MANUAL; /* FIXME: FI_PROGRESS_AUTO? */
	fi->domain_attr->caps 		  = SOCKD_DOMAIN_CAP;

	fi->fabric_attr = calloc(1, sizeof (struct fi_fabric_attr));
	if (!fi->fabric_attr) {
		goto err4;
	}
	fi->fabric_attr->name 		= strdup("socket"); /* FIXME: fabric name for socket */
	fi->fabric_attr->prov_name 	= strdup("socket"); /* FIXME: fabric prov_name for socket */
	/* fi->fabric_attr->prov_name 	= PROVIDER_VERSION; */

#if 0
	if ((hints->ep_cap & FI_PASSIVE)) /* FIXME: FI_SOURCE? */
		sockd_info->ep_cap = FI_PASSIVE;
#endif

	if (hints && hints->src_addr) {
		fi->src_addr = malloc(hints->src_addrlen);
		if (!fi->src_addr) {
			goto err5;
		}
		memcpy(fi->src_addr, hints->src_addr, hints->src_addrlen);
		fi->src_addrlen = hints->src_addrlen;
	} else {
		fi->src_addr = NULL;
		fi->src_addrlen = 0;
	}
	if (hints && hints->dest_addr) {
		fi->dest_addr = malloc(hints->dest_addrlen);
		if (!fi->dest_addr) {
			goto err6;
		}
		memcpy(fi->dest_addr, hints->dest_addr, hints->dest_addrlen);
		fi->dest_addrlen = hints->dest_addrlen;
	} else {
		fi->dest_addr = NULL;
		fi->dest_addrlen = 0;
	}

	if (hints && hints->data) {
		fi->data = (uint8_t *) malloc(hints->datalen);
		if (!fi->data) {
			goto err7;
		}
		memcpy(fi->data, hints->data, hints->datalen);
		fi->datalen = hints->datalen;
	} else {
		fi->datalen = 0;
		fi->data = NULL;
	}

	return fi;
err7:
	free(fi->dest_addr);
err6:
	free(fi->src_addr);
err5:
	free(fi->fabric_attr);
err4:
	free(fi->domain_attr);
err3:
	free(fi->ep_attr);
err2:
	free(fi);
err1:
	return NULL;
}

int sock_dgram_getinfo(uint32_t version, const char *node, const char *service,
		     uint64_t flags, struct fi_info *hints, struct fi_info **info)
{
	int ret = 0;
	struct fi_info *sockd_info;
	int sockfd = -1;
	int optval;
	socklen_t optlen;
	*info = NULL;

	/* solve user specified name or address */
	if (node || service) {
		struct addrinfo *res;
		struct addrinfo sock_hints = {
			.ai_family   = AF_INET,
			.ai_socktype = SOCK_DGRAM,
			.ai_protocol = IPPROTO_UDP
		};
		ret = getaddrinfo(node, service, &sock_hints, &res);
		if (ret) {
			sockd_debug("%s: couldn't getaddrinfo for (%s:%s):%s\n", __func__, node, service, gai_strerror(ret));
			return -FI_ENODATA;
		}
		freeaddrinfo(res);
	}

	sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (sockfd < 0) {
		sockd_debug("%s: couldn't open DGRAM socket\n", __func__);
		return -FI_ENODATA;
	}

	optlen = sizeof(int);
	getsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, (int *)&optval, &optlen);
	so_rcvbuf = optval;

	if (hints) {
		ret = sockd_check_hints(hints);
		if (ret)
			return ret;
	}

	if (flags & FI_SOURCE) {
		/* FIXME: what FI_SOURCE indicates? */
		sockd_debug("[sockd] FI_SOURCE is set for hints\n");
	}


	/* dup prov info */
	if (!(sockd_info = sockd_dupinfo(hints))) {
		ret = -ENOMEM;
		return ret;
	}

	*info = sockd_info;

	close(sockfd);
	return ret;
}

int sock_dgram_ep(struct fid_domain *domain, struct fi_info *info,
		struct fid_ep **ep, void *context)
{
	return -FI_ENOSYS;
}
