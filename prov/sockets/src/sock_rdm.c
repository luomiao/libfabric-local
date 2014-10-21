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
#include "sock_util.h"

int _sock_verify_info(struct fi_info *hints)
{
	int ret;
	if(!hints)
		return 0;

	switch (hints->ep_type) {
	case FI_EP_UNSPEC:
	case FI_EP_MSG:
	case FI_EP_DGRAM:
	case FI_EP_RDM:
		break;
	default:
		return -FI_ENODATA;
	}
	
	if(hints->caps){
		if((SOCK_EP_CAP | hints->caps) != SOCK_EP_CAP)
			return -FI_ENODATA;
	}

	switch (hints->addr_format){
	case FI_ADDR_UNSPEC:
	case FI_SOCKADDR:
		break;
	default:
		return -FI_ENODATA;
	}

	if(hints->ep_attr){
		ret = _sock_verify_ep_attr(hints->ep_attr);
		if(ret)
			return ret;
	}

	if(hints->domain_attr){
		ret = _sock_verify_domain_attr(hints->domain_attr);
		if(ret)
			return ret;
	}

	if(hints->fabric_attr){
		ret = _sock_verify_fabric_attr(hints->fabric_attr);
		if(ret)
			return ret;
	}

	return 0;
}

const struct fi_ep_attr _sock_ep_attr = {
	.protocol = FI_PROTO_SOCK_RDS,
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

const struct fi_domain_attr _sock_domain_attr = {
	.name = NULL,
	.threading = FI_THREAD_SAFE,
	.control_progress = FI_PROGRESS_AUTO,
	.data_progress = FI_PROGRESS_AUTO,
	.mr_key_size = 0,
	.cq_data_size = 0,
	.ep_cnt = 128,
	.tx_ctx_cnt = 128,
	.rx_ctx_cnt = 128,
	.max_ep_tx_ctx = 1,
	.max_ep_rx_ctx = 1,
	.op_size = 0,
	.iov_size = 8,
};

const struct fi_fabric_attr _sock_fabric_attr = {
	.fabric = NULL,
	.name = NULL,
	.prov_name = NULL,
	.prov_version = FI_VERSION(SOCK_MAJOR_VERSION, SOCK_MINOR_VERSION),
};


const struct fi_tx_ctx_attr _sock_tx_attr = {
	.caps = SOCK_EP_CAP,
	.op_flags = SOCK_OPS_CAP,
	.msg_order = 0,
	.inject_size = SOCK_EP_MAX_INJECT_SZ,
	.size = SOCK_EP_MAX_MSG_SZ,
	.iov_limit = SOCK_EP_MAX_IOV_LIMIT,
	.op_alignment = 0,
};

const struct fi_rx_ctx_attr _sock_rx_attr = {
	.caps = SOCK_EP_CAP,
	.op_flags = SOCK_OPS_CAP,
	.msg_order = 0,
	.total_buffered_recv = 0,
	.size = SOCK_EP_MAX_MSG_SZ,
	.iov_limit = SOCK_EP_MAX_IOV_LIMIT,
	.op_alignment = 0,
};

static struct fi_info *allocate_fi_info(enum fi_ep_type ep_type, 
					int addr_format,
					struct fi_info *hints,
					void *src_addr, void *dest_addr)
{
	struct fi_info *_info = fi_allocinfo_internal();
	if(!_info)
		return NULL;
	
	_info->next = NULL;	
	_info->ep_type = ep_type;
	_info->addr_format = addr_format;

	_info->src_addr = calloc(1, sizeof(struct sockaddr));
	memcpy(_info->src_addr, src_addr, sizeof(struct sockaddr));
	_info->dest_addr = calloc(1, sizeof(struct sockaddr));
	memcpy(_info->dest_addr, dest_addr, sizeof(struct sockaddr));

	if(hints->caps){
		_info->caps = hints->caps;
	}else{
		_info->caps = SOCK_EP_CAP;
	}

	memcpy(_info->tx_attr, &_sock_tx_attr, 
	       sizeof(struct fi_tx_ctx_attr));

	memcpy(_info->rx_attr, &_sock_rx_attr, 
	       sizeof(struct fi_rx_ctx_attr));

	memcpy(_info->ep_attr, &_sock_ep_attr, 
	       sizeof(struct fi_ep_attr));

	memcpy(_info->domain_attr, &_sock_domain_attr, 
	       sizeof(struct fi_domain_attr));
	_info->domain_attr->name = strdup(sock_dom_name);

	memcpy(_info->fabric_attr, &_sock_fabric_attr, 
	       sizeof(struct fi_fabric_attr));
	_info->fabric_attr->name = strdup(sock_fab_name);
	_info->fabric_attr->prov_name = strdup(sock_fab_name);

	return _info;
}

void free_fi_info(struct fi_info *info)
{
	if(!info)
		return;
	
	fi_freeinfo_internal(info);
}

int sock_rdm_getinfo(uint32_t version, const char *node, const char *service,
		     uint64_t flags, struct fi_info *hints, struct fi_info **info)
{
	int ret;
	struct fi_info *_info;
	void *src_addr = NULL, *dest_addr = NULL;

	if(!info)
		return -FI_EBADFLAGS;

	*info = NULL;
	
	if(!node && !service && !hints)
		return -FI_EBADFLAGS;

	if(version != FI_VERSION(SOCK_MAJOR_VERSION, 
				 SOCK_MINOR_VERSION))
		return -FI_ENODATA;

	if (hints){
		ret = _sock_verify_info(hints);
		if(ret){
			sock_debug(SOCK_INFO, "Cannot support requested options!\n");
			return ret;
		}
	}

	if(node || service){
		struct addrinfo sock_hints;
		struct addrinfo *result = NULL;
	
		src_addr = malloc(sizeof(struct sockaddr));
		dest_addr = malloc(sizeof(struct sockaddr));
			
		memset(&sock_hints, 0, sizeof(struct sockaddr));
		sock_hints.ai_family = AF_INET;
		sock_hints.ai_socktype = SOCK_SEQPACKET;
		
		if(flags & FI_SOURCE)
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
			sock_debug(SOCK_INFO, "Cannot support requested node, service!\n");
			goto err;
		}
		
		memcpy(src_addr, result->ai_addr, sizeof(struct sockaddr));
		if(AI_PASSIVE == sock_hints.ai_flags){
			socklen_t len;
			int udp_sock = socket(AF_INET, SOCK_DGRAM, 0);
			if (0 != connect(udp_sock, result->ai_addr, result->ai_addrlen)){
				sock_debug(SOCK_ERROR, "[SOCK_RDM] %s:%d: Failed to get dest_addr\n", __func__, __LINE__);
				ret = FI_ENODATA;
				goto err;
			}
			if(0!= getsockname(udp_sock, (struct sockaddr *) dest_addr, &len)){
				sock_debug(SOCK_ERROR, "[SOCK_RDM] %s:%d: Failed to get dest_addr\n", __func__, __LINE__);
				close(udp_sock);
				ret = FI_ENODATA;
				goto err;
			}
			close(udp_sock);
		}
		freeaddrinfo(result); 
	}

	_info = allocate_fi_info(FI_EP_RDM, FI_SOCKADDR, hints, src_addr, dest_addr);
	if(!_info){
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
	sock_debug(SOCK_ERROR, "[SOCK_RDM] %s:%d: fi_getinfo failed\n", __func__, __LINE__);
	return ret;	
}

int sock_rdm_ep_fi_close(struct fid *fid)
{
	struct sock_ep *sock_ep;
	
	sock_ep = container_of(fid, struct sock_ep, ep.fid);
	if(!sock_ep)
		return -FI_EINVAL;

	if(sock_ep->alias)
		return -FI_EINVAL;

	if(!sock_ep->is_alias)
		close(sock_ep->sock_fd);

	free_list(sock_ep->send_list);
	free_list(sock_ep->recv_list);
	
	if(sock_ep->prev)
		sock_ep->prev->next = sock_ep->next;
	
	free(sock_ep);
	return 0;
}

int sock_rdm_ep_fi_bind(struct fid *fid, struct fid *bfid, uint64_t flags)
{
	struct sock_ep *sock_ep;
	struct sock_cq *sock_cq;
	struct sock_av *sock_av;

	sock_ep = container_of(fid, struct sock_ep, ep.fid);
	if(!sock_ep)
		return -FI_EINVAL;

	if (!bfid)
		return -FI_EINVAL;
	
	switch (bfid->fclass) {
	case FI_CLASS_EQ:
		return -FI_ENOSYS;

	case FI_CLASS_CQ:
		sock_cq = container_of(bfid, struct sock_cq, cq_fid.fid);
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
				struct sock_av, av_fid.fid);
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
	struct sock_ep *sock_ep;
	sock_ep = container_of(ep, struct sock_ep, ep);
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
	size_t len;
	struct sock_ep *sock_ep;
	
	if (!addr || !addrlen)
		return -FI_EINVAL;

	sock_ep = container_of(fid, struct sock_ep, ep.fid);
	if(!sock_ep)
		return -FI_EINVAL;

	len = min(*addrlen, sizeof(struct sockaddr));
	memcpy(addr, &sock_ep->src_addr, len);
	*addrlen = sizeof(struct sockaddr);
	return 0;
}

int sock_rdm_ep_cm_getpeer(struct fid_ep *ep, void *addr, size_t *addrlen)
{
	struct sock_ep *sock_ep;
	
	if (!addr || !addrlen)
		return -FI_EINVAL;

	sock_ep = container_of(ep, struct sock_ep, ep);
	if(!sock_ep)
		return -FI_EINVAL;

	*addrlen = min(*addrlen, sizeof(struct sockaddr));

	memcpy(addr, &sock_ep->dest_addr, *addrlen);
	return 0;
}

int sock_rdm_ep_cm_connect(struct fid_ep *ep, const void *addr,
			   const void *param, size_t paramlen)
{
	struct sock_ep *sock_ep;

	if(!addr)
		return -FI_EINVAL;

	sock_ep = container_of(ep, struct sock_ep, ep);
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
	void *addr;
	struct sock_ep *sock_ep;
	struct sock_req_item *req_item;
	
	sock_ep = container_of(ep, struct sock_ep, ep);
	if(!sock_ep)
		return -FI_EINVAL;
	
	if(!sock_ep->enabled)
		return -FI_EINVAL;

	addr = _sock_av_lookup_addr(sock_ep, msg->addr);
	if(!addr)
		return -FI_EINVAL;
	
	req_item = (struct sock_req_item*)
		calloc(1, sizeof(struct sock_req_item));
	if(!req_item)
		return -FI_ENOMEM;
	
	req_item->req_type = SOCK_REQ_TYPE_RECV;
	req_item->comm_type = SOCK_COMM_TYPE_SENDMSG;
	req_item->ep = sock_ep;

	req_item->context = msg->context;
	req_item->data = msg->data;
	req_item->flags = flags;

	req_item->done_len = 0;
	req_item->total_len = msg->msg_iov->iov_len;
	req_item->item.msg = *msg;

	if(0 != enqueue_item(sock_ep->recv_list, req_item)){
		free(req_item);
		return -FI_ENOMEM;
	}
	
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
	void *addr;
	struct sock_ep *sock_ep;
	struct sock_req_item *req_item;

	sock_ep = container_of(ep, struct sock_ep, ep);
	if(!sock_ep)
		return -FI_EINVAL;

	addr = _sock_av_lookup_addr(sock_ep, msg->addr);
	if(!addr)
		return -FI_EINVAL;

	req_item = calloc(1, sizeof(struct sock_req_item));
	if(!req_item)
		return -FI_ENOMEM;
	
	req_item->item.msg = *msg;
	
	req_item->req_type = SOCK_REQ_TYPE_SEND;
	req_item->comm_type = SOCK_COMM_TYPE_SENDMSG;
	req_item->ep = sock_ep;
	req_item->context = msg->context;

	memcpy(&req_item->sock_addr, addr, _sock_addrlen(sock_ep));
	req_item->data = msg->data;

	req_item->done_len = 0;
	req_item->total_len = msg->msg_iov->iov_len;
	
	if(0 != enqueue_item(sock_ep->send_list, req_item)){
		free(req_item);
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

static int sock_rdm_progress_recv(struct sock_ep *ep, struct sock_cq *cq)
{
	struct sock_req_item *recv_item;
	struct pollfd ufds = {0};
	struct msghdr message = {0};
	int ret;

	recv_item = peek_item(ep->recv_list);
	if(!recv_item)
		return 0;
	
	ufds.events = POLLIN;
	ufds.fd = ep->sock_fd;

	ret = poll(&ufds, 1, 0);
	if (ret == -1) {
		sock_debug(SOCK_ERROR, "[rdm_recv_progress] poll failed\n");
		return -FI_EINVAL;
	} else if (ret == 0) {
		sock_debug(SOCK_ERROR, "[rdm_recv_progress] poll timeout\n");
		return -FI_EINVAL;
	}

	message.msg_name = (void*)&recv_item->sock_addr;
	message.msg_namelen = _sock_addrlen(ep);
	message.msg_iov = (struct iovec*)recv_item->item.msg.msg_iov;
	message.msg_iovlen = recv_item->item.msg.iov_count;
	message.msg_control = &recv_item->data;
	message.msg_controllen = sizeof(uint64_t);
	
	ret = recvmsg(ep->sock_fd, &message, recv_item->flags);
	if(ret == EAGAIN || ret == EWOULDBLOCK)
		return 0;

	if(ret < 0){
		sock_debug(SOCK_ERROR, "[rdm_recv_progress] recvmsg failed\n");
		return -FI_EINVAL;
	}

	recv_item->done_len = ret;
	dequeue_item(ep->recv_list);
	_sock_cq_report_completion(ep->recv_cq, recv_item);
	return 0;
}

static int sock_rdm_progress_send(struct sock_ep *ep, struct sock_cq *cq)
{
	struct sock_req_item *send_item;
	struct pollfd ufds = {0};
	struct msghdr message = {0};
	int ret;

	send_item = peek_item(ep->send_list);
	if(!send_item)
		return 0;
	
	ufds.events = POLLOUT;
	ufds.fd = ep->sock_fd;

	ret = poll(&ufds, 1, 0);
	if (ret == -1) {
		sock_debug(SOCK_ERROR, "[rdm_send_progress] poll failed\n");
		return -FI_EINVAL;
	} else if (ret == 0) {
		sock_debug(SOCK_ERROR, "[rdm_send_progress] poll timeout\n");
		return -FI_EINVAL;
	}

	message.msg_name = &send_item->sock_addr;
	message.msg_namelen = _sock_addrlen(ep);
	message.msg_iov = (struct iovec*)send_item->item.msg.msg_iov;
	message.msg_iovlen = send_item->item.msg.iov_count;
	message.msg_control = &send_item->data;
	message.msg_controllen = sizeof(uint64_t);

	ret = sendmsg(ep->sock_fd, &message, send_item->flags);
	if(ret == EAGAIN || ret == EWOULDBLOCK)
		return 0;
	
	if(ret < 0){
		sock_debug(SOCK_ERROR, "[rdm_send_progress] sendmsg failed\n");
		return -FI_EINVAL;
	}

	if(ret + send_item->done_len == send_item->total_len){
		send_item->done_len = send_item->total_len;
		dequeue_item(ep->send_list);
		_sock_cq_report_completion(ep->send_cq, send_item);
	}else{
		send_item->done_len += ret;
	}
	return 0;
}

static int _sock_rdm_progress(struct sock_ep *ep, struct sock_cq *cq)
{
	int ret;
	if(ep->send_cq == cq){
		ret = sock_rdm_progress_send(ep, cq);
		if(ret)
			return ret;
	}
	if(ep->recv_cq == cq)
		ret = sock_rdm_progress_recv(ep, cq);

	return ret;
}

int sock_rdm_ep(struct fid_domain *domain, struct fi_info *info,
		struct fid_ep **ep, void *context)
{
	int ret, flags;
	struct sock_ep *sock_ep;
	struct sock_domain *sock_dom;

	if(info){
		ret = _sock_verify_info(info);
		if(ret)
			return -FI_EINVAL;
	}
	
	sock_dom = container_of(domain, struct sock_domain, dom_fid);
	if(!sock_dom)
		return -FI_EINVAL;

	sock_ep = (struct sock_ep*)calloc(1, sizeof(*sock_ep));
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
		sock_ep->info.caps = info->caps;
		sock_ep->info.addr_format = FI_SOCKADDR;
		
		if(info->src_addr){
			memcpy(&sock_ep->src_addr, info->src_addr, 
			       sizeof(struct sockaddr));
			ret = bind(sock_ep->sock_fd, (struct sockaddr *)&sock_ep->src_addr, 
				   _sock_addrlen(sock_ep));
			if(!ret){
				sock_debug(SOCK_ERROR, "Failed to bind to local address\n");
				return ret;
			}
		}
		
		if(info->dest_addr){
			ret = sock_ep_connect(*ep, info->dest_addr, NULL, 0);
			sock_ep->enabled = 0;
			if(!ret){
				sock_debug(SOCK_ERROR, "Failed to connect to remote address\n");
				return ret;
			}
		}
	}

	if(0 != (sock_ep->send_list = new_list(SOCK_EP_SNDQ_LEN)))
		goto err2;

	if(0 != (sock_ep->recv_list = new_list(SOCK_EP_RCVQ_LEN)))
		goto err3;
	
	sock_ep->progress_fn = _sock_rdm_progress;
	sock_ep->addr_lookup_fn = _sock_av_lookup_in;
	return 0;

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
	struct sock_pep *sock_pep;
	sock_pep = (struct sock_pep*)calloc(1, sizeof(*sock_pep));
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
		sock_pep->pep_cap = info->caps;

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


