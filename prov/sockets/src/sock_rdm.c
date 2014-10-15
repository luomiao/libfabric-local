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

#include "sock.h"

typedef struct _sock_rdm_header_t{
	size_t msg_len;
}sock_rdm_header_t;

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

static int sock_ep_check_hints(struct fi_info *hints)
{
	if(!hints)
		return 0;

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
		if((SOCK_EP_CAP | hints->ep_cap) != SOCK_EP_CAP)
			return -FI_ENODATA;
	}

	switch (hints->addr_format){
	case FI_ADDR_PROTO:
	case FI_SOCKADDR:
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
					struct fi_info *hints,
					void *src_addr, void *dest_addr)
{
	struct fi_info *_info;
	_info = (struct fi_info *)malloc(sizeof(struct fi_info));
	if(!_info)
		return NULL;
	
	_info->next = NULL;
	
	_info->type = ep_type;
	_info->addr_format = addr_format;

	_info->src_addr = src_addr;
	_info->dest_addr = dest_addr;

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
	else{
		if(info->src_addr)
			free(info->src_addr);
		if(info->dest_addr)
			free(info->dest_addr);
	}
	free(info);
}

int sock_rdm_getinfo(uint32_t version, const char *node, const char *service,
		     uint64_t flags, struct fi_info *hints, struct fi_info **info)
{
	int ret;
	struct fi_info *_info;
	void *src_addr, *dest_addr;

	struct addrinfo sock_hints;
	struct addrinfo *result = NULL;
	
	if(!info)
		return -FI_EBADFLAGS;

	*info = NULL;
	
	if(!node && !service && !hints)
		return -FI_EBADFLAGS;

	if(version != FI_VERSION(SOCK_MAJOR_VERSION, 
				 SOCK_MINOR_VERSION))
		return -FI_ENODATA;

	if (hints){
		ret = sock_ep_check_hints(hints);
		if(ret)
			return ret;
	}

	src_addr = malloc(sizeof(struct sockaddr));
	dest_addr = malloc(sizeof(struct sockaddr));

			
	memset(&sock_hints, 0, sizeof(struct addrinfo));
	sock_hints.ai_family = PF_RDS;
	sock_hints.ai_socktype = SOCK_STREAM;
		
	if(flags & FI_SOURCE || flags & FI_PASSIVE)
		sock_hints.ai_flags = AI_PASSIVE;
	else
		sock_hints.ai_flags = 0;

	sock_hints.ai_protocol = 0;
	sock_hints.ai_canonname = NULL;
	sock_hints.ai_addr = NULL;
	sock_hints.ai_next = NULL;
		
	ret = getaddrinfo(node, service, &sock_hints, &result);
	if (ret != 0) {
		ret = FI_ENODATA;
		goto err;
	}
		
	memcpy(src_addr, result->ai_addr, sizeof(struct sockaddr));
	if(AI_PASSIVE != sock_hints.ai_flags){
		socklen_t len;
		int udp_sock = socket(AF_INET, SOCK_DGRAM, 0);
		if (0 != connect(udp_sock, result->ai_addr, result->ai_addrlen)){
			ret = FI_ENODATA;
			goto err;
		}
		if(0!= getsockname(udp_sock, (struct sockaddr *) dest_addr, &len)){
			close(udp_sock);
			ret = FI_ENODATA;
			goto err;
		}
		close(udp_sock);
	}
	freeaddrinfo(result); 

	if(hints && hints->type != FI_EP_UNSPEC){
		_info = allocate_fi_info(hints->type, FI_SOCKADDR, hints, 
					 src_addr, dest_addr);
		if(!_info){
			ret = FI_ENOMEM;
			goto err;
		}
	}else{
		_info = allocate_fi_info(FI_EP_MSG, FI_SOCKADDR, hints,
					 src_addr, dest_addr);
		if(!_info){
			ret = FI_ENOMEM;
			goto err;
		}

		_info->next = allocate_fi_info(FI_EP_DGRAM, FI_SOCKADDR, hints,
					       src_addr, dest_addr);
		if(!_info->next){
			free_fi_info(_info);
			ret = FI_ENOMEM;
			goto err;
		}
		
		_info->next->next = allocate_fi_info(FI_EP_RDM, FI_SOCKADDR, hints,
						     src_addr, dest_addr);
		if(!_info->next->next){
			free_fi_info(_info);
			ret = FI_ENOMEM;
			goto err;
		}
	}

	*info = _info;
	return 0;

err:
	free(src_addr);
	free(dest_addr);
	return ret;	
}

int sock_rdm_ep_fi_close(struct fid *fid)
{
	sock_ep_t *sock_ep;
	
	sock_ep = container_of(fid, sock_ep_t, ep.fid);
	if(!sock_ep)
		return -FI_EINVAL;

	if(sock_ep->alias)
		return -FI_EINVAL;

	if(!sock_ep->is_alias)
		close(sock_ep->sock_fd);

	free_list(sock_ep->send_list);
	free_list(sock_ep->posted_rcv_list);
	free_list(sock_ep->completed_rcv_list);
	
	if(sock_ep->prev)
		sock_ep->prev->next = sock_ep->next;
	
	free(sock_ep);
	return 0;
}

int sock_rdm_ep_fi_bind(struct fid *fid, struct fid *bfid, uint64_t flags)
{
	sock_ep_t *sock_ep;
	sock_cq_t *sock_cq;
	sock_av_t *sock_av;

	sock_ep = container_of(fid, sock_ep_t, ep.fid);
	if(!sock_ep)
		return -FI_EINVAL;

	if (!bfid)
		return -FI_EINVAL;
	
	switch (bfid->fclass) {
	case FI_CLASS_EQ:
		return -FI_ENOSYS;

	case FI_CLASS_CQ:
		sock_cq = container_of(bfid, sock_cq_t, cq_fid.fid);
		if (sock_ep->domain != sock_cq->domain)
			return -EINVAL;
		
		if (flags & (FI_SEND | FI_READ | FI_WRITE)) {
			sock_ep->send_cq = sock_cq;
			if (flags & FI_EVENT)
				sock_ep->send_cq_event_flag = 1;
		}
		if (flags & FI_RECV) {
			sock_ep->recv_cq = sock_cq;
			if (flags & FI_EVENT)
				sock_ep->recv_cq_event_flag = 1;
		}
		break;

	case FI_CLASS_CNTR:
		return -FI_ENOSYS;
/*
		cntr = container_of(bfid, struct psmx_fid_cntr, cntr.fid);
		if (ep->domain != cntr->domain)
			return -EINVAL;
		if (flags & FI_SEND) {
			ep->send_cntr = cntr;
			if (flags & FI_EVENT)
				ep->send_cntr_event_flag = 1;
		}
		if (flags & FI_RECV){
			ep->recv_cntr = cntr;
			if (flags & FI_EVENT)
				ep->recv_cntr_event_flag = 1;
		}
		if (flags & FI_WRITE) {
			ep->write_cntr = cntr;
			if (flags & FI_EVENT)
				ep->write_cntr_event_flag = 1;
		}
		if (flags & FI_READ){
			ep->read_cntr = cntr;
			if (flags & FI_EVENT)
				ep->read_cntr_event_flag = 1;
		}
		break;
*/

	case FI_CLASS_AV:
		sock_av = container_of(bfid,
				sock_av_t, av_fid.fid);
		if (sock_ep->domain != sock_av->dom)
			return -EINVAL;
		sock_ep->av = sock_av;
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
	/* TODO */
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
	sock_ep_t *sock_ep;
	sock_ep = container_of(ep, sock_ep_t, ep);
	if(!sock_ep)
		return -FI_EINVAL;

	sock_ep->enabled = 1;
	return 0;
}

ssize_t sock_rdm_ep_cancel(fid_t fid, void *context)
{
	return -FI_ENOSYS;
}

int sock_rdm_ep_getopt(fid_t fid, int level, int optname,
		       void *optval, size_t *optlen)
{
	/* TODO */
	return -FI_ENOSYS;
}

int sock_rdm_ep_setopt(fid_t fid, int level, int optname,
		       const void *optval, size_t optlen)
{
	/* TODO */
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
	sock_ep_t *sock_ep;
	
	if (!addr || !addrlen)
		return -FI_EINVAL;

	sock_ep = container_of(fid, sock_ep_t, ep.fid);
	if(!sock_ep)
		return -FI_EINVAL;

	*addrlen = MIN(*addrlen, sizeof(struct sockaddr));

	memcpy(addr, &sock_ep->src_addr, *addrlen);
	return 0;
}

int sock_rdm_ep_cm_getpeer(struct fid_ep *ep, void *addr, size_t *addrlen)
{
	sock_ep_t *sock_ep;
	
	if (!addr || !addrlen)
		return -FI_EINVAL;

	sock_ep = container_of(ep, sock_ep_t, ep);
	if(!sock_ep)
		return -FI_EINVAL;

	*addrlen = MIN(*addrlen, sizeof(struct sockaddr));

	memcpy(addr, &sock_ep->dest_addr, *addrlen);
	return 0;
}

int sock_rdm_ep_cm_connect(struct fid_ep *ep, const void *addr,
			   const void *param, size_t paramlen)
{
	sock_ep_t *sock_ep;

	if(!addr)
		return -FI_EINVAL;

	sock_ep = container_of(ep, sock_ep_t, ep);
	if(!sock_ep)
		return -FI_EINVAL;

	if(sock_ep->info.addr_format == FI_SOCKADDR){
		if(memcmp((void*)&(sock_ep->dest_addr), 
			  addr, sizeof(struct sockaddr)) != 0){
			memcpy(&(sock_ep->dest_addr), addr, sizeof(struct sockaddr));
		}
	}else{
		return -FI_EINVAL;
	}

	if(paramlen > 0){
		int ret;
		struct iovec msg_iov ={
			.iov_base = (void*) param,
			.iov_len = paramlen,
		};
		
		struct msghdr msg = {
			.msg_name = NULL,
			.msg_namelen = 0,
			.msg_iov = &msg_iov,
			.msg_iovlen = 1,
			.msg_control = NULL,
			.msg_controllen = 0,
			.msg_flags = 0,
		};
		ret = sendmsg(sock_ep->sock_fd, &msg, 0);
		if(ret)
			return -FI_EINVAL;
	}
	sock_ep->enabled = 1;
	return 0;
}

int sock_rdm_ep_cm_listen(struct fid_pep *pep)
{
	return -FI_ENOSYS;
}

int sock_rdm_ep_cm_accept(struct fid_ep *ep, 
			  const void *param, 
			  size_t paramlen)
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
/*
	sock_ep_t *sock_ep;
	sock_comm_item_t *comm_item;
	
	sock_ep = container_of(ep, sock_ep_t, ep);
	if(!sock_ep)
		return -FI_EINVAL;
	
	if(!sock_ep->enabled)
		return -FI_EINVAL;

	comm_item = (sock_comm_item_t*)calloc(1, sizeof(sock_comm_item_t));
	if(!comm_item)
		return -FI_ENOMEM;
	
	comm_item->type = SOCK_SENDMSG;
	comm_item->context = msg->context;
	comm_item->done_len = 0;
	comm_item->flags = flags;
	memcpy(&comm_item->item.msg, msg, sizeof(struct fi_msg));

	if(0 != enqueue_item(sock_ep->posted_rcv_list, comm_item)){
		free(comm_item);
		return -FI_ENOMEM;
	}
*/		
	return 0;
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
	int i;
	ssize_t total_len = 0, ret;
	sock_ep_t *sock_ep;
	sock_comm_item_t *send_item;

	sock_ep = container_of(ep, sock_ep_t, ep);
	if(!sock_ep)
		return -FI_EINVAL;

	send_item = calloc(1, sizeof(sock_comm_item_t));
	if(!send_item)
		return -FI_ENOMEM;
	
	memcpy(&send_item->item.msg, msg, sizeof(struct fi_msg));

/*
	send_item->type = SOCK_SENDMSG;
*/
	send_item->context = msg->context;
	if(msg->addr){
		//send_item->addr = malloc(sizeof(struct sockaddr));
		if(NULL == send_item){
			free(send_item);
			return -FI_ENOMEM;
		}
		//memcpy(send_item->addr, msg->addr, sizeof(struct sockaddr));
	}
	
	for(i=0; i< msg->iov_count; i++)
		total_len += msg->msg_iov[i].iov_len;
	
	send_item->total_len = total_len;
	//send_item->completed = 0;
	send_item->done_len = 0;

	if(0 != enqueue_item(sock_ep->send_list, send_item)){
		//free(send_item->addr);
		free(send_item);
		return -FI_ENOMEM;	
	}
	return 0;
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
	int ret, flags;
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

	sock_ep->domain = sock_dom;

	sock_ep->sock_fd = socket(PF_RDS, SOCK_STREAM, 0);
	if(sock_ep->sock_fd <0){
		goto err1;
	}

	flags = fcntl(sock_ep->sock_fd, F_GETFL, 0);
	if(-1 == flags)
		goto err1;
	fcntl(sock_ep->sock_fd, F_SETFL, flags | O_NONBLOCK);
	
	*ep = &sock_ep->ep;	
	if(info){
		ret = sock_ep_check_hints(info);
		if(ret)
			goto err2;
		
		sock_ep->info.ep_cap = info->ep_cap;
		sock_ep->info.addr_format = FI_SOCKADDR;
		
		if(info->src_addr){
			memcpy(&sock_ep->src_addr, info->src_addr, 
			       sizeof(struct sockaddr));
			ret = bind(sock_ep->sock_fd, &sock_ep->src_addr, 
				   sizeof(struct sockaddr));
		}
		
		if(info->dest_addr){
			ret = sock_ep_connect(*ep, info->dest_addr, NULL, 0);
			sock_ep->enabled = 0;
		}
	}

	if(0 != (sock_ep->send_list = new_list(SOCK_EP_SNDQ_LEN)))
		goto err2;

	if(0 != (sock_ep->posted_rcv_list = new_list(SOCK_EP_RCVQ_LEN)))
		goto err3;
	
	if(0 != (sock_ep->completed_rcv_list = new_list(SOCK_EP_RCVQ_LEN)))
		goto err4;

	return 0;

err4:
	free_list(sock_ep->posted_rcv_list);

err3:
	free_list(sock_ep->send_list);

err2:
	close(sock_ep->sock_fd);

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
	
	sock_pep->sock_fd = socket(PF_RDS, SOCK_STREAM, 0);
	if(sock_pep->sock_fd <0){
		free(sock_pep);
		return -FI_EAVAIL;
	}

	if(info){
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

int sock_rdm_recv_progress(sock_ep_t *ep)
{
	return 0;
}

int sock_rdm_progress_send(sock_ep_t *ep)
{
	return 0;
}

int _sock_ep_rdm_progress(sock_ep_t *sock_ep, sock_cq_t *sock_cq)
{
	return -FI_ENOSYS;
}
