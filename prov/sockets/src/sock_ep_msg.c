/*
 * Copyright (c) 2014 Intel Corporation, Inc.  All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * BSD license below:
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
#include <arpa/inet.h>
#include <limits.h>

#include "sock.h"
#include "sock_util.h"


extern const struct fi_domain_attr sock_domain_attr;
extern const struct fi_fabric_attr sock_fabric_attr;

extern struct fi_ops_rma sock_ctx_rma;
extern struct fi_ops_rma sock_ep_rma;

extern struct fi_ops_msg sock_ctx_msg_ops;
extern struct fi_ops_tagged sock_ctx_tagged;

extern struct fi_ops_msg sock_ep_msg_ops;
extern struct fi_ops_tagged sock_ep_tagged;


const struct fi_ep_attr sock_msg_ep_attr = {
	.protocol = FI_PROTO_SOCK_TCP,
	.max_msg_size = SOCK_EP_MAX_MSG_SZ,
	.inject_size = SOCK_EP_MAX_INJECT_SZ,
	.total_buffered_recv = SOCK_EP_MAX_BUFF_RECV,
	.max_order_raw_size = SOCK_EP_MAX_ORDER_RAW_SZ,
	.max_order_war_size = SOCK_EP_MAX_ORDER_WAR_SZ,
	.max_order_waw_size = SOCK_EP_MAX_ORDER_WAW_SZ,
	.mem_tag_format = SOCK_EP_MEM_TAG_FMT,
	.msg_order = SOCK_EP_MSG_ORDER,
	.tx_ctx_cnt = SOCK_EP_MAX_TX_CNT,
	.rx_ctx_cnt = SOCK_EP_MAX_RX_CNT,
};

const struct fi_tx_ctx_attr sock_msg_tx_attr = {
	.caps = SOCK_EP_MSG_CAP,
	.op_flags = SOCK_OPS_CAP,
	.msg_order = 0,
	.inject_size = SOCK_EP_MAX_INJECT_SZ,
	.size = SOCK_EP_MAX_TX_CTX_SZ,
	.iov_limit = SOCK_EP_MAX_IOV_LIMIT,
};

const struct fi_rx_ctx_attr sock_msg_rx_attr = {
	.caps = SOCK_EP_MSG_CAP,
	.op_flags = SOCK_OPS_CAP,
	.msg_order = 0,
	.total_buffered_recv = SOCK_EP_MAX_BUFF_RECV,
	.size = SOCK_EP_MAX_MSG_SZ,
	.iov_limit = SOCK_EP_MAX_IOV_LIMIT,
};

static int sock_msg_verify_rx_attr(const struct fi_rx_ctx_attr *attr)
{
	if (!attr)
		return 0;

	if ((attr->caps | sock_msg_rx_attr.caps) != sock_msg_rx_attr.caps)
		return -FI_ENODATA;

	if ((attr->op_flags | sock_msg_rx_attr.op_flags) != 
	   sock_msg_rx_attr.op_flags)
		return -FI_ENODATA;

	if (attr->msg_order != sock_msg_rx_attr.msg_order)
		return -FI_ENODATA;

	if (attr->total_buffered_recv > sock_msg_rx_attr.total_buffered_recv)
		return -FI_ENODATA;

	if (attr->size > sock_msg_rx_attr.size)
		return -FI_ENODATA;

	if (attr->iov_limit > sock_msg_rx_attr.iov_limit)
		return -FI_ENODATA;

	return 0;
}

static int sock_msg_verify_tx_attr(const struct fi_tx_ctx_attr *attr)
{
	if (!attr)
		return 0;

	if ((attr->caps | sock_msg_tx_attr.caps) != sock_msg_tx_attr.caps)
		return -FI_ENODATA;

	if ((attr->op_flags | sock_msg_tx_attr.op_flags) != 
	   sock_msg_tx_attr.op_flags)
		return -FI_ENODATA;

	if (attr->msg_order != sock_msg_tx_attr.msg_order)
		return -FI_ENODATA;

	if (attr->inject_size > sock_msg_tx_attr.inject_size)
		return -FI_ENODATA;

	if (attr->size > sock_msg_tx_attr.size)
		return -FI_ENODATA;

	if (attr->iov_limit > sock_msg_tx_attr.iov_limit)
		return -FI_ENODATA;

	return 0;
}

int sock_msg_verify_ep_attr(struct fi_ep_attr *ep_attr,
			    struct fi_tx_ctx_attr *tx_attr,
			    struct fi_rx_ctx_attr *rx_attr)
{
	if (ep_attr) {
		switch (ep_attr->protocol) {
		case FI_PROTO_UNSPEC:
		case FI_PROTO_SOCK_TCP:
			break;
		default:
			return -FI_ENODATA;
		}

		if (ep_attr->max_msg_size > sock_msg_ep_attr.max_msg_size)
			return -FI_ENODATA;

		if (ep_attr->inject_size > sock_msg_ep_attr.inject_size)
			return -FI_ENODATA;

		if (ep_attr->total_buffered_recv > 
		   sock_msg_ep_attr.total_buffered_recv)
			return -FI_ENODATA;

		if (ep_attr->max_order_raw_size >
		   sock_msg_ep_attr.max_order_raw_size)
			return -FI_ENODATA;

		if (ep_attr->max_order_war_size >
		   sock_msg_ep_attr.max_order_war_size)
			return -FI_ENODATA;

		if (ep_attr->max_order_waw_size > 
		   sock_msg_ep_attr.max_order_waw_size)
			return -FI_ENODATA;

		if (ep_attr->msg_order !=
		   sock_msg_ep_attr.msg_order)
			return -FI_ENODATA;

		if (ep_attr->tx_ctx_cnt > sock_msg_ep_attr.tx_ctx_cnt)
			return -FI_ENODATA;

		if (ep_attr->rx_ctx_cnt > sock_msg_ep_attr.rx_ctx_cnt)
			return -FI_ENODATA;
	}

	if (sock_msg_verify_tx_attr(tx_attr) || sock_msg_verify_rx_attr(rx_attr))
		return -FI_ENODATA;

	return 0;
}


static struct fi_info *allocate_fi_info(enum fi_ep_type ep_type, 
					int addr_format, struct fi_info *hints,
					void *src_addr, void *dest_addr)
{
	struct fi_info *_info = fi_allocinfo_internal();
	if (!_info)
		return NULL;

	_info->src_addr = calloc(1, sizeof(struct sockaddr_in));
	_info->dest_addr = calloc(1, sizeof(struct sockaddr_in));
	
	_info->ep_type = ep_type;
	_info->mode = SOCK_MODE;
	_info->addr_format = addr_format;
	_info->dest_addrlen =_info->src_addrlen = sizeof(struct sockaddr_in);

	if (src_addr) {
		memcpy(_info->src_addr, src_addr, sizeof(struct sockaddr_in));
	}
	
	if (dest_addr) {
		memcpy(_info->dest_addr, dest_addr, sizeof(struct sockaddr_in));
	}

	if (hints->caps) {
		_info->caps = hints->caps;
	} else {
		_info->caps = SOCK_EP_MSG_CAP;
	}

	*(_info->tx_attr) = sock_msg_tx_attr;
	*(_info->rx_attr) = sock_msg_rx_attr;
	*(_info->ep_attr) = sock_msg_ep_attr;

	*(_info->domain_attr) = sock_domain_attr;
	_info->domain_attr->name = strdup(sock_dom_name);

	*(_info->fabric_attr) = sock_fabric_attr;
	_info->fabric_attr->name = strdup(sock_fab_name);
	_info->fabric_attr->prov_name = strdup(sock_fab_name);

	return _info;
}

int sock_msg_getinfo(uint32_t version, const char *node, const char *service,
		     uint64_t flags, struct fi_info *hints, struct fi_info **info)
{
	int ret;
	int udp_sock;
	socklen_t len;
	struct fi_info *_info;
	struct addrinfo sock_hints;
	struct addrinfo *result = NULL;
	struct sockaddr_in *src_addr = NULL, *dest_addr = NULL;
	char sa_ip[INET_ADDRSTRLEN];
	char hostname[HOST_NAME_MAX];

	if (!info)
		return -FI_EBADFLAGS;

	*info = NULL;
	
	if (!node && !service && !hints)
		return -FI_EBADFLAGS;

	if (version != FI_VERSION(SOCK_MAJOR_VERSION, 
				 SOCK_MINOR_VERSION))
		return -FI_ENODATA;

	if (hints) {
		if ((SOCK_EP_MSG_CAP | hints->caps) != SOCK_EP_MSG_CAP) {
			SOCK_LOG_INFO(
				   "Cannot support requested options!\n");
			return -FI_ENODATA;
		}
		
		ret = sock_msg_verify_rx_attr(hints->rx_attr);
		if (ret)
			return ret;

		ret = sock_msg_verify_tx_attr(hints->tx_attr);
		if (ret)
			return ret;
	}

	src_addr = calloc(1, sizeof(struct sockaddr_in));
	dest_addr = calloc(1, sizeof(struct sockaddr_in));

	memset(&sock_hints, 0, sizeof(struct addrinfo));
	sock_hints.ai_family = AF_INET;
	sock_hints.ai_socktype = SOCK_STREAM;

	if (flags & FI_NUMERICHOST)
		sock_hints.ai_flags |= AI_NUMERICHOST;

	if ((flags & FI_SOURCE) || !node) {

		if (!node) {
			gethostname(hostname, HOST_NAME_MAX);
		}

		ret = getaddrinfo(node ? node : hostname, service, 
				  &sock_hints, &result);
		if (ret != 0) {
			ret = FI_ENODATA;
			SOCK_LOG_INFO("getaddrinfo failed!\n");
			goto err;
		}

		while (result) {
			if (result->ai_family == AF_INET && 
			    result->ai_addrlen == sizeof(struct sockaddr_in))
				break;
			result = result->ai_next;
		}

		if (!result) {
			SOCK_LOG_ERROR("getaddrinfo failed\n");
			ret = -FI_EINVAL;
			goto err;
		}
		
		memcpy(src_addr, result->ai_addr, result->ai_addrlen);
		freeaddrinfo(result); 
	} else if (node || service) {

		ret = getaddrinfo(node, service, &sock_hints, &result);
		if (ret != 0) {
			ret = FI_ENODATA;
			SOCK_LOG_INFO("getaddrinfo failed!\n");
			goto err;
		}
		
		while (result) {
			if (result->ai_family == AF_INET && 
			    result->ai_addrlen == sizeof(struct sockaddr_in))
				break;
			result = result->ai_next;
		}

		if (!result) {
			SOCK_LOG_ERROR("getaddrinfo failed\n");
			ret = -FI_EINVAL;
			goto err;
		}
		
		memcpy(dest_addr, result->ai_addr, result->ai_addrlen);
		
		udp_sock = socket(AF_INET, SOCK_DGRAM, 0);
		ret = connect(udp_sock, result->ai_addr, 
			      result->ai_addrlen);
		if ( ret != 0) {
			SOCK_LOG_ERROR("Failed to create udp socket\n");
			ret = FI_ENODATA;
			goto err;
		}

		len = sizeof(struct sockaddr_in);				
		ret = getsockname(udp_sock, (struct sockaddr*)src_addr, &len);
		if (ret != 0) {
			SOCK_LOG_ERROR("getsockname failed\n");
			close(udp_sock);
			ret = FI_ENODATA;
			goto err;
		}
		
		close(udp_sock);
		freeaddrinfo(result); 
	}

	if (dest_addr) {
		memcpy(sa_ip, inet_ntoa(dest_addr->sin_addr), INET_ADDRSTRLEN);
		SOCK_LOG_INFO("dest_addr: family: %d, IP is %s\n",
			      ((struct sockaddr_in*)dest_addr)->sin_family, sa_ip);
	}
	
	if (src_addr) {
		memcpy(sa_ip, inet_ntoa(src_addr->sin_addr), INET_ADDRSTRLEN);
		SOCK_LOG_INFO("src_addr: family: %d, IP is %s\n",
			      ((struct sockaddr_in*)src_addr)->sin_family, sa_ip);
	}

	_info = allocate_fi_info(FI_EP_MSG, FI_SOCKADDR_IN, hints, 
				 src_addr, dest_addr);
	if (!_info) {
		ret = FI_ENOMEM;
		goto err;
	}

	*info = _info;
	free(src_addr);
	free(dest_addr);
	return 0;

err:
	free(src_addr);
	free(dest_addr);
	SOCK_LOG_ERROR("fi_getinfo failed\n");
	return ret;	
}

int	sock_msg_ctx_close(struct fid *fid)
{
	struct sock_ep *ep;
	struct dlist_entry *entry;
	struct sock_tx_ctx *tx_ctx;
	struct sock_rx_ctx *rx_ctx;

	switch (fid->fclass) {
	case FI_CLASS_TX_CTX:
		tx_ctx = container_of(fid, struct sock_tx_ctx, ctx);
		
		for (entry = tx_ctx->ep_list.next; entry != &tx_ctx->ep_list;
		    entry = entry->next) {
			ep = container_of(entry, struct sock_ep, tx_ctx_entry);
			atomic_dec(&ep->num_tx_ctx);
		}
		sock_tx_ctx_free(tx_ctx);
		break;

	case FI_CLASS_RX_CTX:
		rx_ctx = container_of(fid, struct sock_rx_ctx, ctx);
		
		for (entry = rx_ctx->ep_list.next; entry != &rx_ctx->ep_list;
		    entry = entry->next) {
			ep = container_of(entry, struct sock_ep, rx_ctx_entry);
			atomic_dec(&ep->num_rx_ctx);
		}
		sock_rx_ctx_free(rx_ctx);
		break;

	default:
		SOCK_LOG_ERROR("Invalid fid\n");
		return -FI_EINVAL;
	}
	return 0;
}

int	sock_msg_ctx_bind_cq(struct fid *fid, struct fid *bfid, uint64_t flags)
{
	struct sock_cq *sock_cq;
	struct sock_tx_ctx *tx_ctx;
	struct sock_rx_ctx *rx_ctx;

	sock_cq = container_of(bfid, struct sock_cq, cq_fid.fid);
	switch (fid->fclass) {
	case FI_CLASS_TX_CTX:
		tx_ctx = container_of(fid, struct sock_tx_ctx, ctx);
		if (flags & FI_SEND) {
			tx_ctx->send_cq = sock_cq;
			if (flags & FI_EVENT)
				tx_ctx->send_cq_event = 1;
		}

		if (flags & FI_READ) {
			tx_ctx->read_cq = sock_cq;
			if (flags & FI_EVENT)
				tx_ctx->read_cq_event = 1;
		}

		if (flags & FI_WRITE) {
			tx_ctx->write_cq = sock_cq;
			if (flags & FI_EVENT)
				tx_ctx->write_cq_event = 1;
		}

		if (!tx_ctx->progress) {
			tx_ctx->progress = 1;
			sock_pe_add_tx_ctx(tx_ctx->domain->pe, tx_ctx);
		}
		break;
		
	case FI_CLASS_RX_CTX:
		rx_ctx = container_of(fid, struct sock_rx_ctx, ctx);
		if (flags & FI_RECV) {
			rx_ctx->recv_cq = sock_cq;
			if (flags & FI_EVENT)
				rx_ctx->recv_cq_event = 1;
		}

		if (flags & FI_REMOTE_READ) {
			rx_ctx->rem_read_cq = sock_cq;
			if (flags & FI_EVENT)
				rx_ctx->rem_read_cq_event = 1;
		}

		if (flags & FI_REMOTE_WRITE) {
			rx_ctx->rem_write_cq = sock_cq;
			if (flags & FI_EVENT)
				rx_ctx->rem_write_cq_event = 1;
		}

		if (!rx_ctx->progress) {
			rx_ctx->progress = 1;
			sock_pe_add_rx_ctx(rx_ctx->domain->pe, rx_ctx);
		}
		break;
			
	default:
		SOCK_LOG_ERROR("Invalid fid\n");
		return -FI_EINVAL;
	}
	return 0;
}

int	sock_msg_ctx_bind_cntr(struct fid *fid, struct fid *bfid, uint64_t flags)
{
	struct sock_cntr *cntr;
	struct sock_tx_ctx *tx_ctx;
	struct sock_rx_ctx *rx_ctx;

	cntr = container_of(bfid, struct sock_cntr, cntr_fid.fid);
	switch (fid->fclass) {
	case FI_CLASS_TX_CTX:
		tx_ctx = container_of(fid, struct sock_tx_ctx, ctx);
		if (flags & FI_SEND)
			tx_ctx->send_cntr = cntr;
		
		if (flags & FI_READ)
			tx_ctx->read_cntr = cntr;

		if (flags & FI_WRITE)
			tx_ctx->write_cntr = cntr;

		if (!tx_ctx->progress) {
			tx_ctx->progress = 1;
			sock_pe_add_tx_ctx(tx_ctx->domain->pe, tx_ctx);
		}
		break;
		
	case FI_CLASS_RX_CTX:
		rx_ctx = container_of(fid, struct sock_rx_ctx, ctx);
		if (flags & FI_RECV) 
			rx_ctx->recv_cntr = cntr;

		if (flags & FI_REMOTE_READ) 
			rx_ctx->rem_read_cntr = cntr;

		if (flags & FI_REMOTE_WRITE) 
			rx_ctx->rem_write_cntr = cntr;
		
		if (!rx_ctx->progress) {
			rx_ctx->progress = 1;
			sock_pe_add_rx_ctx(rx_ctx->domain->pe, rx_ctx);
		}
		break;
			
	default:
		SOCK_LOG_ERROR("Invalid fid\n");
		return -FI_EINVAL;
	}
	return 0;
}

int	sock_msg_ctx_bind(struct fid *fid, struct fid *bfid, uint64_t flags)
{
	switch (bfid->fclass) {
	case FI_CLASS_CQ:
		return sock_msg_ctx_bind_cq(fid, bfid, flags);

	case FI_CLASS_CNTR:
		return sock_msg_ctx_bind_cntr(fid, bfid, flags);

	default:
		SOCK_LOG_ERROR("Invalid bind()\n");
		return -FI_EINVAL;
	}

}

struct fi_ops sock_msg_ctx_ops = {
	.size = sizeof(struct fi_ops),
	.close = sock_msg_ctx_close,
	.bind = sock_msg_ctx_bind,
	.control = fi_no_control,
};

int sock_msg_ctx_enable(struct fid_ep *ep)
{
	struct sock_tx_ctx *tx_ctx;
	struct sock_rx_ctx *rx_ctx;

	switch (ep->fid.fclass) {
	case FI_CLASS_RX_CTX:
		rx_ctx = container_of(ep, struct sock_rx_ctx, ctx);
		rx_ctx->enabled = 1;
		return 0;

	case FI_CLASS_TX_CTX:
		tx_ctx = container_of(ep, struct sock_tx_ctx, ctx);
		tx_ctx->enabled = 1;
		return 0;

	default:
		SOCK_LOG_ERROR("Invalid CTX\n");
		break;
	}
	return -FI_EINVAL;
}

int sock_msg_ctx_getopt(fid_t fid, int level, int optname,
			void *optval, size_t *optlen)
{
	switch (level) {
	case FI_OPT_ENDPOINT:
		return -FI_ENOPROTOOPT;
	default:
		return -FI_ENOPROTOOPT;
	}
	return 0;
}

int sock_msg_ctx_setopt(fid_t fid, int level, int optname,
			const void *optval, size_t optlen)
{
	switch (level) {
	case FI_OPT_ENDPOINT:
		return -FI_ENOPROTOOPT;
	default:
		return -FI_ENOPROTOOPT;
	}
	return 0;
}

struct fi_ops_ep sock_msg_ctx_ep_ops = {
	.size = sizeof(struct fi_ops_ep),
	.enable = sock_msg_ctx_enable,
	.cancel = fi_no_cancel,
	.getopt = sock_msg_ctx_getopt,
	.setopt = sock_msg_ctx_setopt,
	.tx_ctx = fi_no_tx_ctx,
	.rx_ctx = fi_no_rx_ctx,
};

int sock_msg_ep_fi_close(struct fid *fid)
{
	struct sock_ep *sock_ep;
	sock_ep = container_of(fid, struct sock_ep, ep.fid);

	if (atomic_get(&sock_ep->ref) || atomic_get(&sock_ep->num_rx_ctx) ||
	   atomic_get(&sock_ep->num_tx_ctx))
		return -FI_EBUSY;

	sock_tx_ctx_free(sock_ep->tx_array[sock_ep->ep_attr.tx_ctx_cnt]);
	sock_rx_ctx_free(sock_ep->rx_array[sock_ep->ep_attr.rx_ctx_cnt]);

	free(sock_ep->tx_array);
	free(sock_ep->rx_array);

	if (sock_ep->src_addr)
		free(sock_ep->src_addr);
	if (sock_ep->dest_addr)
		free(sock_ep->dest_addr);
	
	free(sock_ep);
	return 0;
}

int sock_msg_ep_fi_bind(struct fid *fid, struct fid *bfid, uint64_t flags)
{
	int ret, i;
	struct sock_ep *ep;
	struct sock_cq *cq;
	struct sock_av *av;
	struct sock_cntr *cntr;
	struct sock_rx_ctx *rx_ctx;
	struct sock_tx_ctx *tx_ctx;

	ep = container_of(fid, struct sock_ep, ep.fid);
	
	switch (bfid->fclass) {
	case FI_CLASS_EQ:
		return -FI_ENOSYS;

	case FI_CLASS_CQ:
		cq = container_of(bfid, struct sock_cq, cq_fid.fid);
		if (ep->domain != cq->domain)
			return -EINVAL;

		if (flags & FI_SEND) {
			ep->send_cq = cq;
			if (flags & FI_EVENT)
				ep->send_cq_event = 1;
		}

		if (flags & FI_READ) {
			ep->read_cq = cq;
			if (flags & FI_EVENT)
				ep->read_cq_event = 1;
		}

		if (flags & FI_WRITE) {
			ep->write_cq = cq;
			if (flags & FI_EVENT)
				ep->write_cq_event = 1;
		}

		if (flags & FI_RECV) {
			ep->recv_cq = cq;
			if (flags & FI_EVENT)
				ep->recv_cq_event = 1;
		}

		if (flags & FI_REMOTE_READ) {
			ep->rem_read_cq = cq;
			if (flags & FI_EVENT)
				ep->rem_read_cq_event = 1;
		}

		if (flags & FI_REMOTE_WRITE) {
			ep->rem_write_cq = cq;
			if (flags & FI_EVENT)
				ep->rem_write_cq_event = 1;
		}

		for (i=0; i<=ep->ep_attr.tx_ctx_cnt; i++) {
			tx_ctx = ep->tx_array[i];

			if (!tx_ctx)
				continue;

			if ((ret = sock_msg_ctx_bind_cq(&tx_ctx->ctx.fid, 
							bfid, flags)))
				return ret;
		}

		for (i=0; i<=ep->ep_attr.rx_ctx_cnt; i++) {
			rx_ctx = ep->rx_array[i];

			if (!rx_ctx)
				continue;

			if ((ret = sock_msg_ctx_bind_cq(&rx_ctx->ctx.fid, 
							bfid, flags)))
				return ret;
		}
		break;

	case FI_CLASS_CNTR:
		cntr = container_of(bfid, struct sock_cntr, cntr_fid.fid);
		if (ep->domain != cntr->dom)
			return -EINVAL;

		if (flags & FI_SEND)
			ep->send_cntr = cntr;

		if (flags & FI_RECV)
			ep->recv_cntr = cntr;

		if (flags & FI_READ)
			ep->read_cntr = cntr;

		if (flags & FI_WRITE)
			ep->write_cntr = cntr;

		if (flags & FI_REMOTE_READ)
			ep->rem_read_cntr = cntr;
		
		if (flags & FI_REMOTE_WRITE)
			ep->rem_write_cntr = cntr;
		
		for (i=0; i<=ep->ep_attr.tx_ctx_cnt; i++) {
			tx_ctx = ep->tx_array[i];
			
			if (!tx_ctx)
				continue;

			if ((ret = sock_msg_ctx_bind_cntr(&tx_ctx->ctx.fid, 
							  bfid, flags)))
				return ret;
		}

		for (i=0; i<=ep->ep_attr.rx_ctx_cnt; i++) {
			rx_ctx = ep->rx_array[i];

			if (!rx_ctx)
				continue;

			if ((ret = sock_msg_ctx_bind_cntr(&rx_ctx->ctx.fid, 
							  bfid, flags)))
				return ret;
		}
		break;

	case FI_CLASS_AV:
		av = container_of(bfid,
				struct sock_av, av_fid.fid);
		if (ep->domain != av->dom)
			return -EINVAL;
		ep->av = av;
		av->cmap = &av->dom->r_cmap;

		if (ep->tx_ctx && 
		    ep->tx_ctx->ctx.fid.fclass == FI_CLASS_TX_CTX) {
			ep->tx_ctx->av = av;
		}
		
		if (ep->rx_ctx && 
		    ep->rx_ctx->ctx.fid.fclass == FI_CLASS_RX_CTX)
			ep->rx_ctx->av = av;
		
		for (i=0; i<ep->ep_attr.tx_ctx_cnt; i++) {
			if (ep->tx_array[i])
				ep->tx_array[i]->av = av;
		}

		for (i=0; i<ep->ep_attr.rx_ctx_cnt; i++) {
			if (ep->rx_array[i])
				ep->rx_array[i]->av = av;
		}
		
		break;

	case FI_CLASS_MR:
		return -FI_ENOSYS;
/*
		if (!bfid->ops || !bfid->ops->bind)
			return -EINVAL;
		err = bfid->ops->bind(bfid, fid, flags);
		if (err)
			return err;
		break;
*/

	default:
		return -ENOSYS;
	}

	return 0;
}

struct fi_ops sock_msg_ep_fi_ops = {
	.size = sizeof(struct fi_ops),
	.close = sock_msg_ep_fi_close,
	.bind = sock_msg_ep_fi_bind,
	.control = fi_no_control,
	.ops_open = fi_no_ops_open,
};

int sock_msg_ep_enable(struct fid_ep *ep)
{
	int i;
	struct sock_ep *sock_ep;

	sock_ep = container_of(ep, struct sock_ep, ep);
	sock_ep->enabled = 1;

	if (sock_ep->tx_ctx && 
	    sock_ep->tx_ctx->ctx.fid.fclass == FI_CLASS_TX_CTX)
		sock_ep->tx_ctx->enabled = 1;

	if (sock_ep->rx_ctx && 
	    sock_ep->rx_ctx->ctx.fid.fclass == FI_CLASS_RX_CTX)
		sock_ep->rx_ctx->enabled = 1;

	for (i=0; i<sock_ep->ep_attr.tx_ctx_cnt; i++) {
		if (sock_ep->tx_array[i])
			sock_ep->tx_array[i]->enabled = 1;
	}

	for (i=0; i<sock_ep->ep_attr.rx_ctx_cnt; i++) {
		if (sock_ep->rx_array[i])
			sock_ep->rx_array[i]->enabled = 1;
	}
	return 0;
}

int sock_msg_ep_getopt(fid_t fid, int level, int optname,
		       void *optval, size_t *optlen)
{
	switch (level) {
	case FI_OPT_ENDPOINT:
		return -FI_ENOPROTOOPT;
	default:
		return -FI_ENOPROTOOPT;
	}
	return 0;
}

int sock_msg_ep_setopt(fid_t fid, int level, int optname,
		       const void *optval, size_t optlen)
{
	switch (level) {
	case FI_OPT_ENDPOINT:
		return -FI_ENOPROTOOPT;
	default:
		return -FI_ENOPROTOOPT;
	}
	return 0;
}

int sock_msg_ep_tx_ctx(struct fid_ep *ep, int index, struct fi_tx_ctx_attr *attr, 
		    struct fid_ep **tx_ep, void *context)
{
	struct sock_ep *sock_ep;
	struct sock_tx_ctx *tx_ctx;

	sock_ep = container_of(ep, struct sock_ep, ep.fid);
	if (index >= sock_ep->ep_attr.tx_ctx_cnt)
		return -FI_EINVAL;

	tx_ctx = sock_tx_ctx_alloc(&sock_ep->tx_attr, context);
	if (!tx_ctx)
		return -FI_ENOMEM;

	tx_ctx->tx_id = index;
	tx_ctx->ep = sock_ep;
	tx_ctx->domain = sock_ep->domain;
	sock_tx_ctx_add_ep(tx_ctx, sock_ep);

	tx_ctx->ctx.ops = &sock_msg_ctx_ep_ops;
	tx_ctx->ctx.msg = &sock_ctx_msg_ops;
	tx_ctx->ctx.tagged = &sock_ctx_tagged;
	tx_ctx->ctx.rma = &sock_ctx_rma;

	/* TODO */
	tx_ctx->ctx.atomic = NULL;

	*tx_ep = &tx_ctx->ctx;
	sock_ep->tx_array[index] = tx_ctx;
	atomic_inc(&sock_ep->num_tx_ctx);
	return 0;
}

int sock_msg_ep_rx_ctx(struct fid_ep *ep, int index, struct fi_rx_ctx_attr *attr,
		    struct fid_ep **rx_ep, void *context)
{
	struct sock_ep *sock_ep;
	struct sock_rx_ctx *rx_ctx;

	sock_ep = container_of(ep, struct sock_ep, ep.fid);
	if (index >= sock_ep->ep_attr.rx_ctx_cnt)
		return -FI_EINVAL;

	rx_ctx = sock_rx_ctx_alloc(attr, context);
	if (!rx_ctx)
		return -FI_ENOMEM;

	rx_ctx->rx_id = index;
	rx_ctx->ep = sock_ep;
	rx_ctx->domain = sock_ep->domain;
	sock_rx_ctx_add_ep(rx_ctx, sock_ep);

	rx_ctx->ctx.ops = &sock_msg_ctx_ep_ops;
	rx_ctx->ctx.msg = &sock_ctx_msg_ops;
	rx_ctx->ctx.tagged = &sock_ctx_tagged;

	*rx_ep = &rx_ctx->ctx;
	sock_ep->rx_array[index] = rx_ctx;
	atomic_inc(&sock_ep->num_rx_ctx);
	return 0;
}

struct fi_ops_ep sock_msg_ep_ops ={
	.size = sizeof(struct fi_ops_ep),
	.enable = sock_msg_ep_enable,
	.cancel = fi_no_cancel,
	.getopt = sock_msg_ep_getopt,
	.setopt = sock_msg_ep_setopt,
	.tx_ctx = sock_msg_ep_tx_ctx,
	.rx_ctx = sock_msg_ep_rx_ctx,
};

int sock_msg_ep_cm_getname(fid_t fid, void *addr, size_t *addrlen)
{
	struct sock_ep *sock_ep;
	if (*addrlen == 0) {
		*addrlen = sizeof(struct sockaddr_in);
		return -FI_ETOOSMALL;
	}

	sock_ep = container_of(fid, struct sock_ep, ep.fid);
	*addrlen = MIN(*addrlen, sizeof(struct sockaddr_in));
	memcpy(addr, sock_ep->src_addr, *addrlen);
	return 0;
}

int sock_msg_ep_cm_getpeer(struct fid_ep *ep, void *addr, size_t *addrlen)
{
	struct sock_ep *sock_ep;

	if (*addrlen == 0) {
		*addrlen = sizeof(struct sockaddr_in);
		return -FI_ETOOSMALL;
	}

	sock_ep = container_of(ep, struct sock_ep, ep);
	*addrlen = MIN(*addrlen, sizeof(struct sockaddr_in));
	memcpy(addr, sock_ep->dest_addr, *addrlen);
	return 0;
}

int sock_msg_ep_cm_connect(struct fid_ep *ep, const void *addr,
			   const void *param, size_t paramlen)
{
	return -FI_ENOSYS;
}

int sock_msg_ep_cm_listen(struct fid_pep *pep)
{
	return -FI_ENOSYS;
}

int sock_msg_ep_cm_accept(struct fid_ep *ep, const void *param, size_t paramlen)
{
	return -FI_ENOSYS;
}

int sock_msg_ep_cm_reject(struct fid_pep *pep, fi_connreq_t connreq,
			const void *param, size_t paramlen)
{
	return -FI_ENOSYS;
}

int sock_msg_ep_cm_shutdown(struct fid_ep *ep, uint64_t flags)
{
	return -FI_ENOSYS;
}

struct fi_ops_cm sock_msg_ep_cm_ops = {
	.size = sizeof(struct fi_ops_cm),
	.getname = sock_msg_ep_cm_getname,
	.getpeer = sock_msg_ep_cm_getpeer,
	.connect = sock_msg_ep_cm_connect,
	.listen = sock_msg_ep_cm_listen,
	.accept = sock_msg_ep_cm_accept,
	.reject = sock_msg_ep_cm_reject,
	.shutdown = sock_msg_ep_cm_shutdown,
	.join = fi_no_join,
	.leave = fi_no_leave,
};

int sock_msg_ep(struct fid_domain *domain, struct fi_info *info,
		struct fid_ep **ep, void *context)
{
	int ret;
	struct sock_ep *sock_ep;
	struct sock_tx_ctx *tx_ctx;
	struct sock_rx_ctx *rx_ctx;
	struct sock_domain *sock_dom;

	if (info) {
		ret = sock_verify_info(info);
		if (ret) {
			SOCK_LOG_INFO("Cannot support requested options!\n");
			return -FI_EINVAL;
		}
	}
	
	sock_dom = container_of(domain, struct sock_domain, dom_fid);
	if (!sock_dom)
		return -FI_EINVAL;

	sock_ep = (struct sock_ep*)calloc(1, sizeof(*sock_ep));
	if (!sock_ep)
		return -FI_ENOMEM;

	atomic_init(&sock_ep->ref, 0);
	sock_ep->ep.fid.fclass = FI_CLASS_EP;
	sock_ep->ep.fid.context = context;	
	sock_ep->ep.fid.ops = &sock_msg_ep_fi_ops;
	
	sock_ep->ep.ops = &sock_msg_ep_ops;
	sock_ep->ep.cm = &sock_msg_ep_cm_ops;
	sock_ep->ep.msg = &sock_ep_msg_ops;
	sock_ep->ep.rma = &sock_ep_rma;
	sock_ep->ep.tagged = &sock_ep_tagged;
	
	/* TODO */
	sock_ep->ep.atomic = NULL;

	*ep = &sock_ep->ep;	
	if (info) {
		sock_ep->info.caps = info->caps;
		sock_ep->info.addr_format = FI_SOCKADDR_IN;
		
		if (info->src_addr) {
			sock_ep->src_addr = calloc(1, sizeof(struct sockaddr_in));
			memcpy(sock_ep->src_addr, info->src_addr, 
			       sizeof(struct sockaddr_in));
		}

		if (info->dest_addr) {
			sock_ep->dest_addr = calloc(1, sizeof(struct sockaddr_in));
			memcpy(sock_ep->dest_addr, info->dest_addr, 
			       sizeof(struct sockaddr_in));
		}

		if (info->ep_attr) {
			ret = sock_msg_verify_ep_attr(info->ep_attr, 
						      info->tx_attr, 
						      info->rx_attr);
			if (ret)
				goto err;
			sock_ep->ep_attr = *info->ep_attr;
		}

		if (info->tx_attr)
			sock_ep->tx_attr = *info->tx_attr;
		else
			sock_ep->tx_attr = sock_msg_tx_attr;

		if (info->rx_attr)
			sock_ep->rx_attr = *info->rx_attr;
		else
			sock_ep->rx_attr = sock_msg_rx_attr;
	} else {
		sock_ep->ep_attr = sock_msg_ep_attr;
		sock_ep->tx_attr = sock_msg_tx_attr;
		sock_ep->rx_attr = sock_msg_rx_attr;
	}

	atomic_init(&sock_ep->ref, 0);
	atomic_init(&sock_ep->num_tx_ctx, 0);
	atomic_init(&sock_ep->num_rx_ctx, 0);

	sock_ep->tx_array = calloc(sock_ep->ep_attr.tx_ctx_cnt + 1, 
				 sizeof(struct sock_tx_ctx *));
	sock_ep->rx_array = calloc(sock_ep->ep_attr.rx_ctx_cnt + 1,
				 sizeof(struct sock_rx_ctx *));
	
	/* default tx ctx */
	tx_ctx = sock_tx_ctx_alloc(&sock_ep->tx_attr, context);
	tx_ctx->ep = sock_ep;
	tx_ctx->domain = sock_dom;
	tx_ctx->tx_id = sock_ep->ep_attr.tx_ctx_cnt;
	sock_tx_ctx_add_ep(tx_ctx, sock_ep);
	sock_ep->tx_array[sock_ep->ep_attr.tx_ctx_cnt] = tx_ctx;
	sock_ep->tx_ctx = tx_ctx;
	
	/* default rx_ctx */
	rx_ctx = sock_rx_ctx_alloc(&sock_ep->rx_attr, context);
	rx_ctx->ep = sock_ep;
	rx_ctx->domain = sock_dom;
	rx_ctx->rx_id = sock_ep->ep_attr.rx_ctx_cnt;
	sock_rx_ctx_add_ep(rx_ctx, sock_ep);
	sock_ep->rx_array[sock_ep->ep_attr.rx_ctx_cnt] = rx_ctx;
	sock_ep->rx_ctx = rx_ctx;
	
  	sock_ep->domain = sock_dom;
	atomic_inc(&sock_dom->ref);
	return 0;
	
err:
	free(sock_ep);
	return -FI_EAVAIL;
}

int sock_msg_pep(struct fid_fabric *fabric, struct fi_info *info,
			struct fid_pep **pep, void *context)
{
	return -FI_EINVAL;
}
