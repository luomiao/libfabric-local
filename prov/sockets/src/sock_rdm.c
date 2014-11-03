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

const struct fi_ep_attr _sock_rdm_ep_attr = {
	.protocol = FI_PROTO_SOCK_RDS,
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

const struct fi_domain_attr _sock_domain_attr = {
	.name = NULL,
	.threading = FI_THREAD_SAFE,
	.control_progress = FI_PROGRESS_AUTO,
	.data_progress = FI_PROGRESS_AUTO,
	.mr_key_size = 0,
	.cq_data_size = 0,
	.ep_cnt = SOCK_EP_MAX_EP_CNT,
	.tx_ctx_cnt = SOCK_EP_MAX_TX_CNT,
	.rx_ctx_cnt = SOCK_EP_MAX_RX_CNT,
	.max_ep_tx_ctx = SOCK_EP_MAX_TX_CNT,
	.max_ep_rx_ctx = SOCK_EP_MAX_RX_CNT,
	.op_size = -1, /* TODO */
	.iov_size = -1, /* TODO */
};

const struct fi_fabric_attr _sock_fabric_attr = {
	.fabric = NULL,
	.name = NULL,
	.prov_name = NULL,
	.prov_version = FI_VERSION(SOCK_MAJOR_VERSION, SOCK_MINOR_VERSION),
};


const struct fi_tx_ctx_attr _sock_rdm_tx_attr = {
	.caps = SOCK_EP_CAP,
	.op_flags = SOCK_OPS_CAP,
	.msg_order = 0,
	.inject_size = SOCK_EP_MAX_INJECT_SZ,
	.size = SOCK_EP_MAX_TXRX_SZ,
	.iov_limit = SOCK_EP_MAX_IOV_LIMIT,
	.op_alignment = 0,
};

const struct fi_rx_ctx_attr _sock_rdm_rx_attr = {
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

	*(_info->tx_attr) = _sock_rdm_tx_attr;
	*(_info->rx_attr) = _sock_rdm_rx_attr;
	*(_info->ep_attr) = _sock_rdm_ep_attr;

	*(_info->domain_attr) = _sock_domain_attr;
	_info->domain_attr->name = strdup(sock_dom_name);

	*(_info->fabric_attr) = _sock_fabric_attr;
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
				sock_debug(SOCK_ERROR, "Failed to get dest_addr\n");
				ret = FI_ENODATA;
				goto err;
			}
			if(0!= getsockname(udp_sock, (struct sockaddr *) dest_addr, &len)){
				sock_debug(SOCK_ERROR, "Failed to get dest_addr\n");
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

	free_list(sock_ep->send_list);
	free_list(sock_ep->recv_list);
	
	
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

ssize_t sock_rdm_ep_msg_recvmsg(struct fid_ep *ep, const struct fi_msg *msg,
				uint64_t flags)
{
	int i;
	struct sock_ep *sock_ep;
	struct sock_rx_entry *rx_entry;

	if(msg->iov_count > SOCK_EP_MAX_IOV_LIMIT)
		return -FI_EINVAL;
	
	sock_ep = container_of(ep, struct sock_ep, ep);
	if(!sock_ep || !sock_ep->enabled || !sock_ep->rx_ctx)
		return -FI_EINVAL;
	
	rx_entry = calloc(1, sizeof(struct sock_rx_entry));
	if(!rx_entry)
		return -FI_ENOMEM;

	dlist_init(&rx_entry->list);

	rx_entry->rx_op.op = SOCK_OP_RECV;
	rx_entry->rx_op.dest_iov_len = msg->iov_count;

	rx_entry->flags = flags;
	rx_entry->context = (uint64_t)msg->context;
	rx_entry->addr = msg->addr;
	rx_entry->data = msg->data;
	rx_entry->valid_tag = 0;

	for(i=0; i< msg->iov_count; i++){
		rx_entry->iov[i].iov.addr = (uint64_t)msg->msg_iov[i].iov_base;
		rx_entry->iov[i].iov.len = (uint64_t)msg->msg_iov[i].iov_len;
	}

	dlist_insert_tail(&rx_entry->list, &sock_ep->rx_ctx->rx_entry_head.list);
	return 0;
}

ssize_t sock_rdm_ep_msg_recvfrom(struct fid_ep *ep, void *buf, size_t len, void *desc,
				 fi_addr_t src_addr, void *context)
{
	struct fi_msg msg;
	struct iovec msg_iov;

	msg_iov.iov_base = buf;
	msg_iov.iov_len = len;

	msg.msg_iov = &msg_iov;
	msg.desc = desc;
	msg.iov_count = 1;
	msg.addr = src_addr;
	msg.context = context;
	msg.data = 0; /* FIXME: Verify */

	return sock_rdm_ep_msg_recvmsg(ep, &msg, 0);
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

ssize_t sock_rdm_ep_msg_sendmsg(struct fid_ep *ep, const struct fi_msg *msg,
				uint64_t flags)
{
	int ret, i;
	uint64_t tmp=0;
	struct sock_ep *sock_ep;
	struct sock_tx_op tx_op;
	union sock_tx_iov tx_iov;

	if(msg->iov_count > SOCK_EP_MAX_IOV_LIMIT)
		return -FI_EINVAL;
	
	sock_ep = container_of(ep, struct sock_ep, ep);
	if(!sock_ep || !sock_ep->tx_ctx || !sock_ep->enabled)
		return -FI_EINVAL;

	sock_tx_ctx_start(sock_ep->tx_ctx);

	memset(&tx_op, 0, sizeof(struct sock_tx_op));
	tx_op.op = SOCK_OP_SEND;
	tx_op.src_iov_len = msg->iov_count;

	/* tx_op */
	if((ret = sock_tx_ctx_write(sock_ep->tx_ctx, &tx_op, sizeof(struct sock_tx_op))))
		goto err1;

	/* flags */
	if((ret = sock_tx_ctx_write(sock_ep->tx_ctx, &flags, sizeof(uint64_t))))
		goto err1;

	/* context */
	if((ret = sock_tx_ctx_write(sock_ep->tx_ctx, msg->context ? msg->context: &tmp, 
				    sizeof(uint64_t))))
		goto err1;

	/* dest_addr */
	if((ret = sock_tx_ctx_write(sock_ep->tx_ctx, &msg->addr, sizeof(uint64_t))))
		goto err1;

	/* data */
	if(flags & FI_REMOTE_CQ_DATA){
		if((ret = sock_tx_ctx_write(sock_ep->tx_ctx, &msg->data, sizeof(uint64_t))))
			goto err1;
	}

	/* tx iov */
	for(i=0; i< msg->iov_count; i++){
		tx_iov.iov.addr = (uint64_t)msg->msg_iov[i].iov_base;
		tx_iov.iov.len = msg->msg_iov[i].iov_len;

		if((ret = sock_tx_ctx_write(sock_ep->tx_ctx, 
					    &tx_iov, sizeof(union sock_tx_iov))))
			goto err1;
	}
	sock_tx_ctx_commit(sock_ep->tx_ctx);
	return 0;

err1:
	sock_tx_ctx_abort(sock_ep->tx_ctx);
	return ret;
}

ssize_t sock_rdm_ep_msg_sendto(struct fid_ep *ep, const void *buf, size_t len, 
			       void *desc, fi_addr_t dest_addr, void *context)
{
	struct fi_msg msg;
	struct iovec msg_iov;

	msg_iov.iov_base = (void*)buf;
	msg_iov.iov_len = len;

	msg.msg_iov = &msg_iov;
	msg.desc = desc;
	msg.iov_count = 1;
	msg.addr = dest_addr;
	msg.context = context;
	msg.data = 0; /* FIXME: Verify */

	return sock_rdm_ep_msg_sendmsg(ep, &msg, 0);
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
	struct sock_ep *sock_ep;
	struct sock_domain *sock_dom;

	if(info){
		ret = _sock_verify_info(info);
		if(ret){
			sock_debug(SOCK_INFO, "Cannot support requested options!\n");
			return -FI_EINVAL;
		}
	}
	
	sock_dom = container_of(domain, struct sock_domain, dom_fid);
	if(!sock_dom)
		return -FI_EINVAL;

	sock_ep = (struct sock_ep*)calloc(1, sizeof(*sock_ep));
	if(!sock_ep)
		return -FI_ENOMEM;

	atomic_init(&sock_ep->ref);
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

	sock_ep->sock_fd = socket(AF_INET, SOCK_STREAM, 0);
	if(sock_ep->sock_fd <0){
		goto err1;
	}

	flags = fcntl(sock_ep->sock_fd, F_GETFL, 0);
	if(-1 == flags)
		goto err2;
	fcntl(sock_ep->sock_fd, F_SETFL, flags | O_NONBLOCK);
	
	*ep = &sock_ep->ep;	
	if(info){
		sock_ep->info.caps = info->caps;
		sock_ep->info.addr_format = FI_SOCKADDR;
		
		if(info->src_addr){
			memcpy(&sock_ep->src_addr, info->src_addr, 
			       sizeof(struct sockaddr));
			ret = bind(sock_ep->sock_fd, &sock_ep->src_addr, 
				   sizeof(struct sockaddr));
			if(!ret){
				sock_debug(SOCK_ERROR, "Failed to bind to local address\n");
				goto err2;
			}
		}
	}

	sock_ep->rx_ctx = sock_rx_ctx_alloc();
	if(!sock_ep->rx_ctx)
		goto err2;

	sock_ep->rx_ctx->rx_id = 0;
	sock_ep->rx_ctx->addr = 0; /* TODO */
	sock_ep->rx_ctx->ep = sock_ep;
	
	sock_ep->tx_ctx = sock_tx_ctx_alloc(sock_ep->tx_ctx_attr.size);
	if(!sock_ep->tx_ctx)
		goto err3;

	sock_ep->tx_ctx->tx_id = 0;
	sock_ep->tx_ctx->addr = 0; /* TODO */
	sock_ep->tx_ctx->ep = sock_ep;

	sock_ep->domain = sock_dom;
	atomic_inc(&sock_dom->ref);
	return 0;

err3:
	sock_rx_ctx_free(sock_ep->rx_ctx);

err2:
	close(sock_ep->sock_fd);

err1:
	free(sock_ep);
	return -FI_EAVAIL;
}

int sock_rdm_pep(struct fid_fabric *fabric, struct fi_info *info,
			struct fid_pep **pep, void *context)
{
	return -FI_ENOSYS;
}
