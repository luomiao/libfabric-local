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

static struct fi_ep_attr sock_ep_attr = {
	.protocol = FI_PROTO_UNSPEC,
	.max_msg_size = SOCK_EP_MAX_MSG_SZ,
	.inject_size = SOCK_EP_MAX_INJECT_SZ,
	.total_buffered_recv = SOCK_EP_MAX_BUFF_RECV,
	.max_order_raw_size = SOCK_EP_MAX_ORDER_RAW_SZ,
	.max_order_war_size = SOCK_EP_MAX_ORDER_WAR_SZ,
	.max_order_waw_size = SOCK_EP_MAX_ORDER_WAW_SZ,
	.mem_tag_format = SOCK_EP_MEM_TAG_FMT,
	.msg_order = SOCK_EP_MSG_ORDER,
	.tx_ctx_cnt = SOCK_EP_TX_CTX_CNT,
	.rx_ctx_cnt = SOCK_EP_RX_CTX_CNT,
};

static int sock_check_hints(struct fi_info *hints)
{
	switch (hints->type) {
	case FI_EP_UNSPEC:
	case FI_EP_MSG:
	case FI_EP_DGRAM:
	case FI_EP_RDM:
		break;
	default:
		return -FI_ENODATA;
	}
	
	if (hints->ep_attr) {
		switch (hints->ep_attr->protocol) {
		case FI_PROTO_UNSPEC:
			break;
		default:
			return -FI_ENODATA;
		}
	}

	if(hints->ep_cap){
		if(SOCK_EP_CAP | hints->ep_cap != SOCK_EP_CAP)
			return -FI_ENODATA;
	}

	switch (hints->addr_format){
	case FI_ADDR_PROTO:
	case FI_SOCKADDR:
	case FI_SOCKADDR_IN:
	case FI_SOCKADDR_IN6:
		break;
	default:
		return -FI_ENODATA;
	}

	if (hints->fabric_attr && hints->fabric_attr->name &&
	    strcmp(hints->fabric_attr->name, fab_name))
		return -FI_ENODATA;

	return 0;
}

static struct fi_info *allocate_fi_info(enum fi_ep_type ep_type, 
					enum fi_addr_format addr_format,
					struct fi_info *hints)
{
	struct fi_info *_info;
	_info = (struct fi_info *)malloc(sizeof(struct fi_info));
	if(!_info)
		return NULL;
	
	_info->next = NULL;
	
	_info->type = ep_type;
	_info->op_flags = 0;
	_info->addr_format = addr_format;

	if(hints->ep_cap){
		_info->ep_cap = hints->ep_cap;
	}else{
		_info->ep_cap = SOCK_EP_CAP;
	}

	_info->ep_attr = &sock_ep_attr;
	_info->domain_attr = NULL;
	_info->fabric_attr = NULL;
	return _info;
}

void free_fi_info(struct fi_info *info)
{
	if(!info)
		return;
	
	if(info->next)
		free_fi_info(info->next);
	
	free(info);
}

int sock_rdm_getinfo(uint32_t version, const char *node, const char *service,
		     uint64_t flags, struct fi_info *hints, struct fi_info **info)
{
	int ret;
	struct fi_info *_info;

	if(!info)
		return -FI_EBADFLAGS;

	*info = NULL;
	
	if(!node && !service && !hints)
		return -FI_EBADFLAGS;

	if(version != FI_VERSION(SOCK_MAJOR_VERSION, 
				 SOCK_MINOR_VERSION))
		return -FI_ENODATA;

	if (hints){
		ret = sock_check_hints(hints);
		if(ret)
			return ret;
	}

	if(node || service){
		struct addrinfo sock_hints;
		struct addrinfo *result = NULL;
		
		memset(&sock_hints, 0, sizeof(struct addrinfo));
		sock_hints.ai_family = AF_INET;
		sock_hints.ai_socktype = SOCK_STREAM;
		sock_hints.ai_flags = 0;
		sock_hints.ai_protocol = 0;
		sock_hints.ai_canonname = NULL;
		sock_hints.ai_addr = NULL;
		sock_hints.ai_next = NULL;
		
		ret = getaddrinfo(node, service, &sock_hints, &result);
		if (ret != 0) {
			return -FI_ENODATA;
		}
		freeaddrinfo(result); 
	}

	if(hints && hints->type != FI_EP_UNSPEC){
		_info = allocate_fi_info(hints->type, FI_SOCKADDR, hints);
		if(!_info)
			return -FI_ENOMEM;
	}else{
		_info = allocate_fi_info(FI_EP_MSG, FI_SOCKADDR, hints);
		if(!_info)
			return -FI_ENOMEM;

		_info->next = allocate_fi_info(FI_EP_DGRAM, FI_SOCKADDR, hints);
		if(!_info->next){
			free_fi_info(_info);
			return -FI_ENOMEM;
		}
		
		_info->next->next = allocate_fi_info(FI_EP_RDM, FI_SOCKADDR, hints);
		if(!_info->next->next){
			free_fi_info(_info);
			return -FI_ENOMEM;
		}
	}

	*info = _info;
	return 0;
}

int sock_rdm_ep_fi_close(struct fid *fid)
{
	return -FI_ENOSYS;
}

int sock_rdm_ep_fi_bind(struct fid *fid, struct fid *bfid, uint64_t flags)
{
	return -FI_ENOSYS;
}

int sock_rdm_ep_fi_sync(struct fid *fid, uint64_t flags, void *context)
{
	return -FI_ENOSYS;
}

int sock_rdm_ep_fi_control(struct fid *fid, int command, void *arg)
{
	return -FI_ENOSYS;
}

int sock_rdm_ep_fi_ops_open(struct fid *fid, const char *name,
			uint64_t flags, void **ops, void *context)
{
	return -FI_ENOSYS;
}

struct fi_ops sock_rdm_ep_fi_ops = {
	.size = sizeof(struct fi_ops),
	.close = sock_rdm_ep_fi_close,
	.bind = sock_rdm_ep_fi_bind,
	.sync = sock_rdm_ep_fi_sync,
	.control = sock_rdm_ep_fi_control,
	.ops_open = sock_rdm_ep_fi_ops_open,
};

int sock_rdm_ep_enable(struct fid_ep *ep)
{
	return -FI_ENOSYS;
}

ssize_t sock_rdm_ep_cancel(fid_t fid, void *context)
{
	return -FI_ENOSYS;
}

int sock_rdm_ep_getopt(fid_t fid, int level, int optname,
		       void *optval, size_t *optlen)
{
	return -FI_ENOSYS;
}

int sock_rdm_ep_setopt(fid_t fid, int level, int optname,
		       const void *optval, size_t optlen)
{
	return -FI_ENOSYS;
}

struct fi_ops_ep sock_rdm_ep_ops ={
	.size = sizeof(struct fi_ops_ep),
	.enable = sock_rdm_ep_enable,
	.getopt = sock_rdm_ep_getopt,
	.setopt = sock_rdm_ep_setopt,
};

int sock_rdm_ep_cm_getname(fid_t fid, void *addr, size_t *addrlen)
{
	return -FI_ENOSYS;
}

int sock_rdm_ep_cm_getpeer(struct fid_ep *ep, void *addr, size_t *addrlen)
{
	return -FI_ENOSYS;
}

int sock_rdm_ep_cm_connect(struct fid_ep *ep, const void *addr,
			   const void *param, size_t paramlen)
{
	return -FI_ENOSYS;
}

int sock_rdm_ep_cm_listen(struct fid_pep *pep)
{
	return -FI_ENOSYS;
}

int sock_rdm_ep_cm_accept(struct fid_ep *ep, fi_connreq_t connreq,
			   const void *param, size_t paramlen)
{
	return -FI_ENOSYS;
}

int sock_rdm_ep_cm_reject(struct fid_pep *pep, fi_connreq_t connreq,
			   const void *param, size_t paramlen)
{
	return -FI_ENOSYS;
}

int sock_rdm_ep_cm_shutdown(struct fid_ep *ep, uint64_t flags)
{
	return -FI_ENOSYS;
}

int sock_rdm_ep_cm_join(struct fid_ep *ep, void *addr, fi_addr_t *fi_addr,
			 uint64_t flags, void *context)
{
	return -FI_ENOSYS;
}

int sock_rdm_ep_cm_leave(struct fid_ep *ep, void *addr, fi_addr_t fi_addr,
			  uint64_t flags)
{
	return -FI_ENOSYS;
}


struct fi_ops_cm sock_rdm_ep_cm_ops = {
	.size = sizeof(struct fi_ops_cm),
	.getname = sock_rdm_ep_cm_getname,
	.getpeer = sock_rdm_ep_cm_getpeer,
	.connect = sock_rdm_ep_cm_connect,
	.listen = sock_rdm_ep_cm_listen,
	.accept = sock_rdm_ep_cm_accept,
	.reject = sock_rdm_ep_cm_reject,
	.shutdown = sock_rdm_ep_cm_shutdown,
	.join = sock_rdm_ep_cm_join,
	.leave = sock_rdm_ep_cm_leave,
};

ssize_t sock_rdm_ep_msg_recv(struct fid_ep *ep, void *buf, size_t len, void *desc,
			     void *context)
{
	return -FI_ENOSYS;
}

ssize_t sock_rdm_ep_msg_recvv(struct fid_ep *ep, const struct iovec *iov, void **desc,
			      size_t count, void *context)
{
	return -FI_ENOSYS;
}

ssize_t sock_rdm_ep_msg_recvfrom(struct fid_ep *ep, void *buf, size_t len, void *desc,
				 fi_addr_t src_addr, void *context)
{
	return -FI_ENOSYS;
}

ssize_t sock_rdm_ep_msg_recvmsg(struct fid_ep *ep, const struct fi_msg *msg,
				uint64_t flags)
{
	return -FI_ENOSYS;
}

ssize_t sock_rdm_ep_msg_send(struct fid_ep *ep, const void *buf, size_t len, void *desc,
			     void *context)
{
	return -FI_ENOSYS;
}

ssize_t sock_rdm_ep_msg_sendv(struct fid_ep *ep, const struct iovec *iov, void **desc,
			      size_t count, void *context)
{
	return -FI_ENOSYS;
}

ssize_t sock_rdm_ep_msg_sendto(struct fid_ep *ep, const void *buf, size_t len, 
			       void *desc, fi_addr_t dest_addr, void *context)
{
	return -FI_ENOSYS;
}

ssize_t sock_rdm_ep_msg_sendmsg(struct fid_ep *ep, const struct fi_msg *msg,
				uint64_t flags)
{
	return -FI_ENOSYS;
}

ssize_t sock_rdm_ep_msg_inject(struct fid_ep *ep, const void *buf, size_t len)
{
	return -FI_ENOSYS;
}

ssize_t sock_rdm_ep_msg_injectto(struct fid_ep *ep, const void *buf, size_t len,
				 fi_addr_t dest_addr)
{
	return -FI_ENOSYS;
}

ssize_t sock_rdm_ep_msg_senddata(struct fid_ep *ep, const void *buf, size_t len, 
				 void *desc, uint64_t data, void *context)
{
	return -FI_ENOSYS;
}

ssize_t sock_rdm_ep_msg_senddatato(struct fid_ep *ep, const void *buf, size_t len, 
				   void *desc, uint64_t data, fi_addr_t dest_addr, void *context)
{
	return -FI_ENOSYS;
}

struct fi_ops_msg sock_rdm_ep_msg_ops = {
	.size = sizeof(struct fi_ops_msg),
	.recv = sock_rdm_ep_msg_recv,
	.recvv = sock_rdm_ep_msg_recvv,
	.recvfrom = sock_rdm_ep_msg_recvfrom,
	.recvmsg = sock_rdm_ep_msg_recvmsg,
	.send = sock_rdm_ep_msg_send,
	.sendv = sock_rdm_ep_msg_sendv,
	.sendto = sock_rdm_ep_msg_sendto,
	.sendmsg = sock_rdm_ep_msg_sendmsg,
	.inject = sock_rdm_ep_msg_inject,
	.injectto = sock_rdm_ep_msg_injectto,
	.senddata = sock_rdm_ep_msg_senddata,
	.senddatato = sock_rdm_ep_msg_senddatato,
};

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
	sock_ep->ep.fid.ops = &sock_rdm_ep_fi_ops;
	
	sock_ep->ep.ops = &sock_rdm_ep_ops;
	sock_ep->ep.cm = &sock_rdm_ep_cm_ops;
	sock_ep->ep.msg = &sock_rdm_ep_msg_ops;

	/* TODO */
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

	if(0 != (sock_ep->send_list = new_list(SOCK_EP_SNDQ_LEN)))
		goto err1;

	if(0 != (sock_ep->recv_list = new_list(SOCK_EP_RCVQ_LEN)))
		goto err2;

	return 0;

err2:
	free_list(sock_ep->send_list);

err1:
	free(sock_ep);

	return -FI_EAVAIL;
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


