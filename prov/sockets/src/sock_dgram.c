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

#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netdb.h>
#include <poll.h>
#include <unistd.h>

#include "sock_util.h"
#include "sock.h"


/* FIXME: figure out the sockd caps */
#if 0
#define SOCKD_EP_CAP (FI_TAGGED | FI_MSG | FI_ATOMICS | FI_INJECT | \
		FI_RMA | FI_BUFFERED_RECV | FI_MULTI_RECV | \
		FI_READ | FI_WRITE | FI_SEND | FI_RECV | \
		FI_REMOTE_READ | FI_REMOTE_WRITE | \
		FI_REMOTE_COMPLETE | FI_REMOTE_SIGNAL | \
		FI_CANCEL | FI_TRIGGER)
#endif
#define SOCKD_OP_FLAGS (FI_INJECT | FI_EVENT | \
		FI_TRIGGER | FI_REMOTE_SIGNAL | FI_CANCEL)
#define SOCKD_DOMAIN_CAP (FI_WRITE_COHERENT | FI_CONTEXT | \
		FI_USER_MR_KEY | FI_DYNAMIC_MR)
#define SOCKD_MTU (512)

static int so_rcvbuf;

extern struct fi_ops_msg sock_rdm_ep_msg_ops;

const struct fi_ep_attr _sockd_ep_attr = {
	.protocol 		= FI_PROTO_UDP,
	.max_msg_size 		= SOCK_EP_MAX_MSG_SZ,
	.inject_size 		= SOCK_EP_MAX_INJECT_SZ,
	.total_buffered_recv 	= SOCK_EP_MAX_BUFF_RECV,
	.max_order_raw_size 	= SOCK_EP_MAX_ORDER_RAW_SZ,
	.max_order_war_size 	= SOCK_EP_MAX_ORDER_WAR_SZ,
	.max_order_waw_size 	= SOCK_EP_MAX_ORDER_WAW_SZ,
	.mem_tag_format 	= SOCK_EP_MEM_TAG_FMT,
	.msg_order 		= SOCK_EP_MSG_ORDER,
	.tx_ctx_cnt 		= SOCK_EP_MAX_TX_CNT,
	.rx_ctx_cnt 		= SOCK_EP_MAX_RX_CNT,
};

const struct fi_domain_attr _sockd_domain_attr = {
	.name 			= NULL,
	.threading 		= FI_THREAD_SAFE,
	.control_progress 	= FI_PROGRESS_AUTO,
	.data_progress 		= FI_PROGRESS_AUTO,
	.mr_key_size 		= 0,
	.cq_data_size 		= 0,
	.ep_cnt 			= SOCK_EP_MAX_EP_CNT,
	.tx_ctx_cnt 		= 0,
	.rx_ctx_cnt 		= 0,
	.max_ep_tx_ctx 		= SOCK_EP_MAX_TX_CNT,
	.max_ep_rx_ctx 		= SOCK_EP_MAX_RX_CNT,
	.op_size 		= 0,
	.iov_size 		= 8,
};

const struct fi_fabric_attr _sockd_fabric_attr = {
	.fabric 	= NULL,
	.name 		= NULL,
	.prov_name 	= NULL,
	.prov_version 	= FI_VERSION(SOCK_MAJOR_VERSION, SOCK_MINOR_VERSION),
};


const struct fi_tx_ctx_attr _sockd_tx_attr = {
	.caps 		= SOCK_EP_DGRAM_CAP,
	.op_flags 	= SOCK_OPS_CAP,
	.msg_order 	= 0,
	.inject_size 	= SOCK_EP_MAX_INJECT_SZ,
	.size 		= SOCK_EP_MAX_MSG_SZ,
	.iov_limit 	= SOCK_EP_MAX_IOV_LIMIT,
	.op_alignment 	= 0,
};

const struct fi_rx_ctx_attr _sockd_rx_attr = {
	.caps 			= SOCK_EP_DGRAM_CAP,
	.op_flags 		= SOCK_OPS_CAP,
	.msg_order 		= 0,
	.total_buffered_recv 	= 0,
	.size 			= SOCK_EP_MAX_MSG_SZ,
	.iov_limit 		= SOCK_EP_MAX_IOV_LIMIT,
	.op_alignment 		= 0,
};

int sockd_check_hints(struct fi_info *hints)
{
	switch (hints->ep_type) {
	case FI_EP_DGRAM:
		break;
	default:
		SOCK_LOG_ERROR("[sockd] %s: hints->type = %d, only FI_EP_DGRAM = %d is supported\n",
				__func__, hints->ep_type, FI_EP_DGRAM);
		return -FI_ENODATA;
	}

	switch (hints->addr_format) {
	case FI_SOCKADDR:
	case FI_SOCKADDR_IN:
	case FI_SOCKADDR_IN6:
		break;
	default:
		SOCK_LOG_ERROR("[sockd] %s: hints->addr_format = %d, supported = FI_SOCKADDR or FI_SOCKADDR_IN or FI_SOCKADDR_IN6\n",
				__func__, hints->addr_format);
		return -FI_ENODATA;
	}

	if (hints->ep_attr) {
		switch (hints->ep_attr->protocol) {
		case FI_PROTO_UNSPEC:
		case FI_PROTO_UDP:
			break;
		default:
			/*
			SOCK_LOG_ERROR("[sockd] %s: hints->ep_attr->protocol=%lu, supported=%d\n",
					__func__, hints->ep_attr->protocol, FI_PROTO_UNSPEC);
			*/
			return -FI_ENODATA;
		}
		if (hints->ep_attr->max_msg_size > SOCKD_MTU) {
			/*
			SOCK_LOG_ERROR("[sockd] %s: hints->ep_attr->max_msg_size=%d, supported=%d\n",
					__func__, hints->ep_attr->max_msg_size, SOCKD_MTU);
			*/
			return -FI_ENODATA;
		}
		if (hints->ep_attr->inject_size > SOCKD_MTU) {
			/*
			SOCK_LOG_ERROR("[sockd] %s: hints->ep_attr->inject_size=%d, supported=%d\n",
			__func__, hints->ep_attr->inject_size, SOCKD_MTU);
			*/
			return -FI_ENODATA;
		}
		if (hints->ep_attr->total_buffered_recv > so_rcvbuf) {
			/*
			SOCK_LOG_ERROR("[sockd] %s: hints->ep_attr->total_buffered_recv=%d, supported=%d\n",
					__func__, hints->ep_attr->total_buffered_recv, so_rcvbuf);
			*/
			return -FI_ENODATA;
		}
		/* FIXME: check 
		 * max_order_raw_size,
		 * max_order_war_size,
		 * max_order_waw_size, 
		 * mem_tag_format,
		 * msg_order */
	}

	if ((hints->caps & SOCK_EP_DGRAM_CAP) != hints->caps) {
		/*
		SOCK_LOG_ERROR("[sockd] %s: hints->ep_cap=0x%llx, supported=0x%llx\n",
				__func__, hints->caps, SOCK_EP_DGRAM_CAP);
		*/
		return -FI_ENODATA;
	}

	if (hints->tx_attr && ((hints->tx_attr->op_flags & SOCKD_OP_FLAGS) != hints->tx_attr->op_flags)) {
		/*
		SOCK_LOG_ERROR("[sockd] %s: hints->tx_attr->op_flags=0x%llx, supported=0x%llx\n",
				__func__, hints->tx_attr->op_flags, SOCKD_OP_FLAGS);
		*/
		return -FI_ENODATA;
	}

	if (hints->fabric_attr) {
		if(hints->fabric_attr->name){
			if (strcmp(hints->fabric_attr->name, sock_fab_name))
				return -FI_ENODATA;
		}
	}

#if 0 /* TODO */
	if ((hints->domain_cap & SOCKD_DOMAIN_CAP) != hints->domain_cap) {
		SOCK_LOG_ERROR("[sockd] %s: hints->domain_cap=0x%llx, supported=0x%llx\n",
				__func__, hints->domain_cap, SOCKD_DOMAIN_CAP);
		return -FI_ENODATA;
		/* FIXME: check
		 * threading, control_progress, mr_key_size, eq_data_size */
	}
#endif
	if (hints->domain_attr) {
		if(hints->domain_attr->name){
			if (strcmp(hints->domain_attr->name, sock_dom_name))
				return -FI_ENODATA;
		}
	}

	struct sockaddr_in *si_src;
	if (!hints->src_addr || !hints->src_addrlen) {
		SOCK_LOG_ERROR("[sockd] src_addr and src_addrlen are required from hints\n");
		return -FI_ENODATA;
	} else {
		si_src = (struct sockaddr_in *)(hints->src_addr);
		if (ntohs(si_src->sin_port)<1024) {
			SOCK_LOG_ERROR("[sockd] port number should be above 1023\n");
			return -FI_ENODATA;
		}
		SOCK_LOG_ERROR("[sockd] port is set to %d\n", ntohs(si_src->sin_port));
	}

	return 0;
}

static struct fi_info* sockd_dupinfo(struct fi_info *hints)
{
	struct fi_info *fi;
	fi = fi_allocinfo_internal();

	fi->next = NULL;
	fi->ep_type = FI_EP_DGRAM;

	if (hints) {
		fi->caps	= hints->caps;
		fi->addr_format = hints->addr_format;
	} else {
		fi->caps	= SOCK_EP_DGRAM_CAP;
		fi->addr_format = FI_SOCKADDR;
	}

	memcpy(fi->ep_attr, &_sockd_ep_attr, 
	       sizeof(struct fi_ep_attr));

	memcpy(fi->domain_attr, &_sockd_domain_attr, 
	       sizeof(struct fi_domain_attr));
	fi->domain_attr->name 		  = strdup(sock_dom_name);

	memcpy(fi->fabric_attr, &_sockd_fabric_attr, 
	       sizeof(struct fi_fabric_attr));
	fi->fabric_attr->name 			= strdup(sock_fab_name);
	fi->fabric_attr->prov_name 		= strdup(sock_fab_name);
	/* fi->fabric_attr->prov_version 	= PROVIDER_VERSION; */

	if (hints && hints->src_addr) {
		fi->src_addr = malloc(hints->src_addrlen);
		if (!fi->src_addr) {
			goto err;
		}
		memcpy(fi->src_addr, hints->src_addr, hints->src_addrlen);
		fi->src_addrlen = hints->src_addrlen;
	} else {
		SOCK_LOG_ERROR("[sockd] hints must have src_addr\n");
#if 0
		fi->src_addr = NULL;
		fi->src_addrlen = 0;
#endif
		goto err;
	}
	if (hints && hints->dest_addr) {
		fi->dest_addr = malloc(hints->dest_addrlen);
		if (!fi->dest_addr) {
			goto err;
		}
		memcpy(fi->dest_addr, hints->dest_addr, hints->dest_addrlen);
		fi->dest_addrlen = hints->dest_addrlen;
	} else {
		fi->dest_addr = NULL;
		fi->dest_addrlen = 0;
	}

	*(fi->tx_attr) = _sockd_tx_attr;
	*(fi->rx_attr) = _sockd_rx_attr;

	return fi;
err:
	fi_freeinfo_internal(fi);
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

#if 0
	if (!(flags & FI_SOURCE)) {
		/* FIXME: FI_SOURCE is required for DGRAM */
		fprintf(stderr, "[sockd] FI_SOURCE is required for EP_DGRAM\n");
		errno = EINVAL;
		return -errno;
	}
#endif

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
			SOCK_LOG_ERROR("%s: couldn't getaddrinfo for (%s:%s):%s\n", __func__, node, service, gai_strerror(ret));
			return -FI_ENODATA;
		}
		freeaddrinfo(res);
	}

	sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (sockfd < 0) {
		SOCK_LOG_ERROR("%s: couldn't open DGRAM socket\n", __func__);
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


	/* dup prov info */
	if (!(sockd_info = sockd_dupinfo(hints))) {
		ret = -ENOMEM;
		return ret;
	}

	*info = sockd_info;

	close(sockfd);
	return ret;
}

/* sockd_fi_ops */

static int sockd_ep_close(fid_t fid)
{
	struct sock_ep *ep;

	ep = container_of(fid, struct sock_ep, ep.fid);
	if (ep->sock_fd)
		if (close(ep->sock_fd)) {
			SOCK_LOG_ERROR("[sockd] cannot close sock_fd\n");
			return -FI_ENODATA;
		}

	free(ep);
	return 0;
}

static int sockd_ep_bind(struct fid *fid, struct fid *bfid, uint64_t flags) 
{
	struct sock_ep *ep;
	struct sock_cntr *cntr;
	struct sock_eq *eq;
	struct sock_cq *cq;
	struct sock_av *av;

	ep = container_of(fid, struct sock_ep, ep.fid);

	switch (bfid->fclass) {
	case FI_CLASS_CNTR:
		SOCK_LOG_ERROR("[sockd] bind counter to ep\n");
		cntr = container_of(bfid, struct sock_cntr, cntr_fid.fid);
		if (!(flags &
			(FI_WRITE | FI_READ | FI_SEND | FI_RECV))) {
			SOCK_LOG_ERROR("[sockd] Counter only support FI_WRITE | FI_READ | FI_SEND | FI_RECV\n");
			errno = FI_EINVAL;
			return -errno;
		}
		if (flags & FI_WRITE) {
			if (ep->write_cntr)
				return -EINVAL;
			ep->write_cntr = cntr;
		}
		if (flags & FI_READ) {
			if (ep->read_cntr)
				return -EINVAL;
			ep->read_cntr = cntr;
		}
		if (flags & FI_SEND) {
			if (ep->send_cntr)
				return -EINVAL;
			ep->send_cntr = cntr;
		}
		if (flags & FI_RECV) {
			if (ep->recv_cntr)
				return -EINVAL;
			ep->recv_cntr = cntr;
		}
		break;
	case FI_CLASS_CQ:
		SOCK_LOG_ERROR("[sockd] bind CQ to ep\n");
		cq = container_of(bfid, struct sock_cq, cq_fid.fid);
		if (!(flags &
			(FI_SEND | FI_RECV))) {
			SOCK_LOG_ERROR("[sockd] CQ only support FI_SEND | FI_RECV\n");
			errno = FI_EINVAL;
			return -errno;
		}
		if (flags & FI_SEND) {
			if (ep->send_cq)
				return -EINVAL;
			ep->send_cq = cq;
		}
		if (flags & FI_RECV) {
			if (ep->recv_cq)
				return -EINVAL;
			ep->recv_cq = cq;
		}
		break;
	case FI_CLASS_EQ:
		SOCK_LOG_ERROR("[sockd] bind EQ to ep\n");
		/* FIXME: bind EQ to sockd EP */
		eq = container_of(bfid, struct sock_eq, eq.fid);
		if (ep->eq) {
			return -EINVAL;
		}
		ep->eq = eq;
		break;
	case FI_CLASS_AV:
		SOCK_LOG_ERROR("[sockd] bind AV to ep\n");
		av = container_of(bfid,
				struct sock_av, av_fid.fid);
		if (ep->domain != av->dom)
			return -EINVAL;
		ep->av = av;
		av->cmap = &av->dom->u_cmap;
		break;
	default:
		return -FI_ENOSYS;
	}

	return 0;
}

static int sockd_ep_sync(fid_t fid, uint64_t flags, void *context)
{
	errno = FI_ENOSYS;
	return -errno;
}

static int sockd_ep_control(fid_t fid, int command, void *arg)
{
	errno = FI_ENOSYS;
	return -errno;
}

static int sockd_ep_ops_open(struct fid *fid, const char *name,
		uint64_t flags, void **ops, void *context)
{
	errno = FI_ENOSYS;
	return -errno;
}

/* sockd_ops_ep */

static int sockd_ep_enable(struct fid_ep *ep)
{
	struct sock_ep *sock_ep;
	int i;
	sock_ep = container_of(ep, struct sock_ep, ep);
	if(!sock_ep)
		return -FI_EINVAL;

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
			sock_ep->rx_array[i]->enabled =
				1;
	}
	return 0;
}

static ssize_t	sockd_ep_cancel(fid_t fid, void *context)
{
	errno = FI_ENOSYS;
	return -errno;
}

static int sockd_ep_getopt(fid_t fid, int level, int optname,
		void *optval, size_t *optlen)
{
	errno = FI_ENOSYS;
	return -errno;
}

static int sockd_ep_setopt(fid_t fid, int level, int optname,
		const void *optval, size_t optlen)
{
	errno = FI_ENOSYS;
	return -errno;
}

static int sockd_ep_tx_ctx(struct fid_ep *ep, int index,
		struct fi_tx_ctx_attr *attr, struct fid_ep **tx_ep,
		void *context)
{
	errno = FI_ENOSYS;
	return -errno;
}


static int	sockd_ep_rx_ctx(struct fid_ep *ep, int index,
			struct fi_rx_ctx_attr *attr, struct fid_ep **rx_ep,
			void *context)
{
	errno = FI_ENOSYS;
	return -errno;
}

/* sockd_ops_cm */

static int sockd_cm_getname(fid_t fid, void *addr, size_t *addrlen)
{
	errno = FI_ENOSYS;
	return -errno;
}

static int sockd_cm_getpeer(struct fid_ep *ep, void *addr, size_t *addrlen)
{
	errno = FI_ENOSYS;
	return -errno;
}

static int sockd_cm_connect(struct fid_ep *ep, const void *addr,
		const void *param, size_t paramlen)
{
	fprintf(stderr, "[sockd_cm_connect] enter\n");
	errno = FI_ENOSYS;
	return -errno;
}

static int sockd_cm_listen(struct fid_pep *pep)
{
	errno = FI_ENOSYS;
	return -errno;
}

static int sockd_cm_accept(struct fid_ep *ep, const void *param, size_t paramlen)
{
	errno = FI_ENOSYS;
	return -errno;
}

static int sockd_cm_reject(struct fid_pep *pep, fi_connreq_t connreq,
		const void *param, size_t paramlen)
{
	errno = FI_ENOSYS;
	return -errno;
}

static int sockd_cm_shutdown(struct fid_ep *ep, uint64_t flags)
{
	errno = FI_ENOSYS;
	return -errno;
}

static int sockd_cm_join(struct fid_ep *ep, void *addr, fi_addr_t *fi_addr,
		uint64_t flags, void *context)
{
	errno = FI_ENOSYS;
	return -errno;
}

static int sockd_cm_leave(struct fid_ep *ep, void *addr, fi_addr_t fi_addr,
		uint64_t flags)
{
	errno = FI_ENOSYS;
	return -errno;
}

/* sockd_ops_msg */
static ssize_t sockd_msg_recvv(struct fid_ep *ep, const struct iovec *iov, void **desc,
		size_t count, void *context)
{
	errno = FI_ENOSYS;
	return -errno;
}

static ssize_t sockd_msg_recvfrom(struct fid_ep *ep, void *buf, size_t len, void *desc,
		fi_addr_t src_addr, void *context)
{
	struct sock_ep *sock_ep;
	struct sock_req_item *recv_req;
	void *addr;
#if 0

	if (src_addr) {
		sock_debug(SOCK_ERROR, "fi_recvfrom is not supported for dgram socket provider\n");
		errno = FI_ENOSYS;
		return errno;
	}

	sock_ep = container_of(ep, struct sock_ep, ep);
	if(!sock_ep)
		return -FI_EINVAL;

	recv_req = calloc(1, sizeof(struct sock_req_item));
	if(!recv_req)
		return -FI_ENOMEM;
	
	recv_req->item.buf = (void*)buf;
	recv_req->req_type = SOCK_REQ_TYPE_RECV;
	recv_req->comm_type = SOCK_COMM_TYPE_SENDTO;
	recv_req->context = context;
	recv_req->total_len = len;
	recv_req->done_len = 0;

	if (src_addr) {
		addr = _sock_av_lookup_addr(sock_ep, src_addr);
		if(!addr)
			return -FI_EINVAL;

		memcpy(&recv_req->sock_addr, addr, _sock_addrlen(sock_ep->domain));
	}
	       
	if(0 != enqueue_item(sock_ep->recv_list, recv_req)){
		free(recv_req);
		return -FI_ENOMEM;	
	}
#endif
	return 0;
}

static ssize_t sockd_msg_recv(struct fid_ep *ep, void *buf, size_t len, void *desc,
		void *context)
{
	return sockd_msg_recvfrom(ep, buf, len, desc, 0, context);
}

static ssize_t sockd_msg_recvmsg(struct fid_ep *ep, const struct fi_msg *msg,
		uint64_t flags)
{
	errno = FI_ENOSYS;
	return -errno;
}

static ssize_t sockd_msg_send(struct fid_ep *ep, const void *buf, size_t len, void *desc,
		void *context)
{
	errno = FI_ENOSYS;
	return -errno;
}

static ssize_t sockd_msg_sendv(struct fid_ep *ep, const struct iovec *iov, void **desc,
		size_t count, void *context)
{
	errno = FI_ENOSYS;
	return -errno;
}

static ssize_t sockd_msg_sendto(struct fid_ep *ep, const void *buf, size_t len, void *desc,
		fi_addr_t dest_addr, void *context)
{
	struct sock_ep *sock_ep;
	struct sock_req_item *send_req;
	void *addr;

#if 0
	sock_ep = container_of(ep, struct sock_ep, ep);
	if(!sock_ep)
		return -FI_EINVAL;

	send_req = calloc(1, sizeof(struct sock_req_item));
	if(!send_req)
		return -FI_ENOMEM;
	
	send_req->item.buf = (void*)buf;
	send_req->req_type = SOCK_REQ_TYPE_SEND;
	send_req->comm_type = SOCK_COMM_TYPE_SENDTO;
	send_req->context = context;
	send_req->total_len = len;
	send_req->done_len = 0;

	addr = _sock_av_lookup_addr(sock_ep, dest_addr);
	if(!addr)
		return -FI_EINVAL;
	
	memcpy(&send_req->sock_addr, addr, _sock_addrlen(sock_ep->domain));

	if(0 != enqueue_item(sock_ep->send_list, send_req)){
		free(send_req);
		return -FI_ENOMEM;	
	}
#endif
	return 0;
}

static ssize_t sockd_msg_sendmsg(struct fid_ep *ep, const struct fi_msg *msg,
		uint64_t flags)
{
	errno = FI_ENOSYS;
	return -errno;
}

static ssize_t sockd_msg_inject(struct fid_ep *ep, const void *buf, size_t len)
{
	errno = FI_ENOSYS;
	return -errno;
}

static ssize_t sockd_msg_injectto(struct fid_ep *ep, const void *buf, size_t len,
		fi_addr_t dest_addr)
{
	errno = FI_ENOSYS;
	return -errno;
}

static ssize_t sockd_msg_senddata(struct fid_ep *ep, const void *buf, size_t len, void *desc,
		uint64_t data, void *context)
{
	errno = FI_ENOSYS;
	return -errno;
}

static ssize_t sockd_msg_senddatato(struct fid_ep *ep, const void *buf, size_t len, void *desc,
		uint64_t data, fi_addr_t dest_addr, void *context)
{
	errno = FI_ENOSYS;
	return -errno;
}

static struct fi_ops sockd_ep_fi_ops = {
	.size		= sizeof(struct fi_ops),
	.close		= sockd_ep_close,
	.bind		= sockd_ep_bind,
	.sync		= sockd_ep_sync,
	.control	= sockd_ep_control,
	.ops_open	= sockd_ep_ops_open
};

static struct fi_ops_ep sockd_ops_ep = {
	.size 	= sizeof(struct fi_ops_ep),
	.cancel = sockd_ep_cancel,
	.getopt = sockd_ep_getopt,
	.setopt = sockd_ep_setopt,
	.enable = sockd_ep_enable,
	.tx_ctx = sockd_ep_tx_ctx,
	.rx_ctx = sockd_ep_rx_ctx,
};

static struct fi_ops_cm sockd_ops_cm = {
	.size           = sizeof(struct fi_ops_cm),
	.getname        = sockd_cm_getname,
	.getpeer        = sockd_cm_getpeer,
	.connect        = sockd_cm_connect,
	.listen         = sockd_cm_listen,
	.accept         = sockd_cm_accept,
	.reject         = sockd_cm_reject,
	.shutdown       = sockd_cm_shutdown,
	.join           = sockd_cm_join,
	.leave          = sockd_cm_leave
};

static struct fi_ops_msg sockd_ops_msg = {
	.size 		= sizeof(struct fi_ops_msg),
	.recv 		= sockd_msg_recv,
	.recvv 		= sockd_msg_recvv,
	.recvfrom 	= sockd_msg_recvfrom,
	.recvmsg 	= sockd_msg_recvmsg,
	.send 		= sockd_msg_send,
	.sendv 		= sockd_msg_sendv,
	.sendto 	= sockd_msg_sendto,
	.sendmsg 	= sockd_msg_sendmsg,
	.inject 	= sockd_msg_inject,
	.injectto 	= sockd_msg_injectto,
	.senddata 	= sockd_msg_senddata,
	.senddatato 	= sockd_msg_senddatato
};

static inline int _sock_ep_dgram_progress(struct sock_ep *ep, struct sock_cq *cq)
{
	struct sock_req_item *item;
#if 0
	if((item = dequeue_item(ep->send_list))) {
		SOCK_LOG_ERROR("[ep_dgram_progress] found a send req\n");
	}
	if((item = dequeue_item(ep->recv_list))) {
		SOCK_LOG_ERROR("[ep_dgram_progress] found a recv req\n");
	}
#endif
	return -FI_ENOSYS;
}

int sock_dgram_ep(struct fid_domain *domain, struct fi_info *info,
		struct fid_ep **ep, void *context)
{
	SOCK_LOG_ERROR("[sockd] enter sock_dgram_ep\n");
	struct sock_ep *_ep;
	struct sock_domain *_dom;
	struct sockaddr_in si_me;

	_dom = container_of(domain, struct sock_domain, dom_fid);
	if(!_dom)
		return -FI_EINVAL;

	_ep = (struct sock_ep*)calloc(1, sizeof(*_ep));
	if(!_ep)
		return -FI_ENOMEM;

	_ep->ep.fid.fclass	= FI_CLASS_EP;
	_ep->ep.fid.context 	= context;
	_ep->ep.fid.ops		= &sockd_ep_fi_ops;
	_ep->ep.ops 		= &sockd_ops_ep;
	_ep->ep.cm 			= &sockd_ops_cm;
	_ep->ep.msg 		= &sock_rdm_ep_msg_ops;
	_ep->ep.rma 		= NULL;
	_ep->ep.tagged		= NULL;
	_ep->ep.atomic		= NULL;
	_ep->domain		= _dom;

	_ep->sock_fd 	= socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (_ep->sock_fd < 0) {
		SOCK_LOG_ERROR("%s: couldn't open DGRAM socket\n", __func__);
		errno = FI_ENODATA;
		goto err1;
	}

	si_me.sin_family 	= AF_INET;
	si_me.sin_port		= ((struct sockaddr_in *)(info->src_addr))->sin_port;
	si_me.sin_addr.s_addr	= htonl(INADDR_ANY);
	if (bind(_ep->sock_fd, &si_me, sizeof(si_me)) == -1) {
		SOCK_LOG_ERROR("[sockd] %s: failed to bind sock_fd to port %d\n", __func__, ntohs(si_me.sin_port));
		goto err2;
	}

	if(!(_ep->send_list = new_list(SOCK_EP_SNDQ_LEN)))
		goto err2;

	if(!(_ep->recv_list = new_list(SOCK_EP_RCVQ_LEN)))
		goto err3;

/*	
	_ep->progress_fn = _sock_ep_dgram_progress;
*/

	*ep = &_ep->ep;

	return 0;

err3:
	free_list(_ep->send_list);

err2:
	close(_ep->sock_fd);

err1:
	free(_ep);

	return -errno;
}
