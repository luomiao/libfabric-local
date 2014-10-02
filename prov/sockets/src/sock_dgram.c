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

int sockd_supported(struct fi_info *hints)
{
	if (hints->ep_attr) {
		switch (hints->ep_attr->protocol) {
		case FI_PROTO_UNSPEC:
			break;
		default:
			fprintf(stderr, "[sockd] %s: hints->ep_attr->protocol=%lu, supported=%d\n",
					__func__, hints->ep_attr->protocol, FI_PROTO_UNSPEC);
			return 0;
		}
	}

	if ((hints->ep_cap & SOCKD_EP_CAP) != hints->ep_cap) {
		fprintf(stderr, "[sockd] %s: hints->ep_cap=0x%llx, supported=0x%llx\n",
				__func__, hints->ep_cap, SOCKD_EP_CAP);
		return 0;
	}

	if ((hints->op_flags & SOCKD_OP_FLAGS) != hints->op_flags) {
		fprintf(stderr, "[sockd] %s: hints->op_flags=0x%llx, supported=0x%llx\n",
				__func__, hints->op_flags, SOCKD_OP_FLAGS);
		return 0;
	}

	if (hints->domain_attr && 
			((hints->domain_attr->caps & SOCKD_DOMAIN_CAP) !=
			 hints->domain_attr->caps)) {
		fprintf(stderr, "[sockd] %s: hints->domain_attr->caps=0x%llx, supported=0x%llx\n",
				__func__, hints->domain_attr->caps, SOCKD_DOMAIN_CAP);
		return 0;
	}

	/* FIXME: check all the support */
	return 1;
}

int sock_dgram_getinfo(uint32_t version, const char *node, const char *service,
		     uint64_t flags, struct fi_info *hints, struct fi_info **info)
{
	int ret = 0;
	int err = -ENODATA;
	struct fi_info *sockd_info;
	int sockfd = -1;
	int optval;
	socklen_t optlen;

	*info = NULL;

	if (hints && !sockd_supported(hints)) {
		err = -EINVAL;
		goto err_out;
	}

	/* user specified name or address */
	if (node || service) {
		struct addrinfo *res;
		struct addrinfo sock_hints = {
			.ai_family   = AF_INET,
			.ai_socktype = SOCK_DGRAM,
			.ai_protocol = IPPROTO_UDP
		};
		ret = getaddrinfo(node, service, &sock_hints, &res);
		if (ret) {
			fprintf(stderr, "%s: couldn't getaddrinfo for (%s:%s):%s\n", __func__, node, service, gai_strerror(ret));
			err = -EINVAL;
			goto err_out;
		}
		freeaddrinfo(res);
	}

	sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (sockfd < 0) {
		fprintf(stderr, "%s: couldn't open DGRAM socket\n", __func__);
		err = -EINVAL;
		goto err_out;
	}

	if (flags & FI_SOURCE) {
		/* FIXME: what FI_SOURCE indicates? */
		fprintf(stderr, "[sockd] FI_SOURCE is set for hints\n");
	}

	sockd_info = __fi_allocinfo();
	if (!sockd_info) {
		err = -ENOMEM;
		goto err_out;
	}

	if ((hints->ep_cap & FI_PASSIVE)) /* FIXME: FI_SOURCE? */
		sockd_info->ep_cap = FI_PASSIVE;

	/* FIXME: dup prov info */
#if 0
	sockd_info->ep_attr->protocol = SOCKD_OUI_INTEL << FI_OUI_SHIFT | SOCKD_PROTOCOL;
#endif
	sockd_info->ep_attr->max_msg_size = SOCKD_MTU;
	sockd_info->ep_attr->inject_size = SOCKD_MTU;
	optlen = sizeof(int);
	getsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, (int *)&optval, &optlen);
	sockd_info->ep_attr->total_buffered_recv = optval;
#if 0
	sockd_info->ep_attr->mem_tag_format = fi_tag_format(max_tag_value);
	sockd_info->ep_attr->msg_order = FI_ORDER_SAS;
	sockd_info->domain_attr->threading = FI_THREAD_PROGRESS;
#endif

	sockd_info->domain_attr->control_progress = FI_PROGRESS_MANUAL;
	sockd_info->domain_attr->data_progress = FI_PROGRESS_MANUAL; /* FIXME: FI_PROGRESS_AUTO? */
	sockd_info->domain_attr->caps = (hints && hints->domain_attr &&
			hints->domain_attr->caps) ?
		hints->domain_attr->caps : SOCKD_DOMAIN_CAP;
	sockd_info->domain_attr->name = strdup("socket");

	sockd_info->next = NULL;
	sockd_info->type = hints ? hints->type : FI_EP_DGRAM; /* FIXME: sockd CAPS */
	sockd_info->ep_cap = (hints && hints->ep_cap) ? hints->ep_cap : SOCKD_EP_CAP;
	sockd_info->op_flags = (hints && hints->op_flags) ? hints->op_flags : SOCKD_OP_FLAGS;
	sockd_info->addr_format = (hints && hints->addr_format) ? hints->addr_format : FI_ADDR_PROTO;
	if (hints && hints->src_addr) {
		sockd_info->src_addr = malloc(hints->src_addrlen);
		if (!hints->src_addr) {
			goto dupinfo_error;
		}
		memcpy(sockd_info->src_addr, hints->src_addr, hints->src_addrlen);
		sockd_info->src_addrlen = hints->src_addrlen;
	} else {
		sockd_info->src_addr = NULL;
		sockd_info->src_addrlen = 0;
	}
	if (hints && hints->dest_addr) {
		sockd_info->dest_addr = malloc(hints->dest_addrlen);
		if (!sockd_info->dest_addr) {
			goto dupinfo_error;
		}
		memcpy(sockd_info->dest_addr, hints->dest_addr, hints->dest_addrlen);
		sockd_info->dest_addrlen = hints->dest_addrlen;
	} else {
		sockd_info->dest_addr = NULL;
		sockd_info->dest_addrlen = 0;
	}
	if (hints && hints->fabric_attr) {
		sockd_info->fabric_attr->name =
			strdup(hints->fabric_attr->name);
		if (!sockd_info->fabric_attr->name) {
			goto dupinfo_error;
		}
	} else {
		sockd_info->fabric_attr->name = strdup("socket");
	}
	if (hints && hints->data) {
		sockd_info->data = (uint8_t *) malloc(hints->datalen);
		if (!sockd_info->data) {
			goto dupinfo_error;
		}
		memcpy(sockd_info->data, hints->data, hints->datalen);
		sockd_info->datalen = hints->datalen;
	} else {
		sockd_info->datalen = 0;
		sockd_info->data = NULL;
	}

	*info = sockd_info;

	close(sockfd);
	return ret;

dupinfo_error:
	if (sockd_info->dest_addr)    free(sockd_info->dest_addr);
	if (sockd_info->src_addr)     free(sockd_info->src_addr);
	if (sockd_info->fabric_attr)  free(sockd_info->fabric_attr);
	if (sockd_info->data)         free(sockd_info->data);
	free(sockd_info);
	err = -ENOMEM;
err_out:
	return err;
}

int sock_dgram_ep(struct fid_domain *domain, struct fi_info *info,
		struct fid_ep **ep, void *context)
{
	return -FI_ENOSYS;
}
