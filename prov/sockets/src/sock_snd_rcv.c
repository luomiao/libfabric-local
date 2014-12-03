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

ssize_t sock_ctx_recvmsg(struct fid_ep *ep, const struct fi_msg *msg,
		   uint64_t flags)
{
	int i;
	struct sock_rx_ctx *rx_ctx;
	struct sock_rx_entry *rx_entry;

	rx_ctx = container_of(ep, struct sock_rx_ctx, ctx);
	assert(rx_ctx->enabled && msg->iov_count <= SOCK_EP_MAX_IOV_LIMIT);

	rx_entry = sock_rx_new_entry(rx_ctx);
	if (!rx_entry)
		return -FI_ENOMEM;
	
	dlist_init(&rx_entry->entry);

	rx_entry->rx_op.op = SOCK_OP_RECV;
	rx_entry->rx_op.dest_iov_len = msg->iov_count;

	rx_entry->flags = flags;
	rx_entry->context = (uint64_t)msg->context;
	rx_entry->addr = msg->addr;
	rx_entry->data = msg->data;
	rx_entry->ignore = 0xFFFF;

	for (i=0; i< msg->iov_count; i++) {
		rx_entry->iov[i].iov.addr = (uint64_t)msg->msg_iov[i].iov_base;
		rx_entry->iov[i].iov.len = (uint64_t)msg->msg_iov[i].iov_len;
	}

	fastlock_acquire(&rx_ctx->lock);

	SOCK_LOG_INFO("New rx_entry: %p (ctx: %p)\n", rx_entry, rx_ctx);

	dlist_insert_tail(&rx_entry->entry, &rx_ctx->rx_entry_list);
	fastlock_release(&rx_ctx->lock);
	return 0;
}

ssize_t sock_ctx_recvfrom(struct fid_ep *ep, void *buf, size_t len, void *desc,
		    fi_addr_t src_addr, void *context)
{
	struct fi_msg msg;
	struct iovec msg_iov;

	msg_iov.iov_base = buf;
	msg_iov.iov_len = len;

	msg.msg_iov = &msg_iov;
	msg.desc = &desc;
	msg.iov_count = 1;
	msg.addr = src_addr;
	msg.context = context;

	return sock_ctx_recvmsg(ep, &msg, 0);
}

ssize_t sock_ctx_recv(struct fid_ep *ep, void *buf, size_t len, void *desc,
			  void *context)
{
	return sock_ctx_recvfrom(ep, buf, len, desc, FI_ADDR_UNSPEC, 
				     context);
}

ssize_t sock_ctx_recvv(struct fid_ep *ep, const struct iovec *iov, 
			   void **desc, size_t count, void *context)
{
	struct fi_msg msg;

	msg.msg_iov = iov;
	msg.desc = desc;
	msg.iov_count = count;
	msg.addr = FI_ADDR_UNSPEC;
	msg.context = context;
	return sock_ctx_recvmsg(ep, &msg, 0);
}

ssize_t sock_ctx_sendmsg(struct fid_ep *ep, const struct fi_msg *msg,
		   uint64_t flags)
{
	int ret, i;
	uint64_t total_len;
	struct sock_op tx_op;
	union sock_iov tx_iov;
	struct sock_conn *conn;
	struct sock_tx_ctx *tx_ctx;

	tx_ctx = container_of(ep, struct sock_tx_ctx, ctx);
	assert(tx_ctx->enabled && msg->iov_count <= SOCK_EP_MAX_IOV_LIMIT);

	ret = sock_av_lookup_addr(tx_ctx->av, msg->addr, &conn);
	assert(ret == 0);

	SOCK_LOG_INFO("New sendmsg on TX: %p using conn: %p\n", 
		      tx_ctx, conn);

	total_len = 0;
	if (flags & FI_INJECT) {
		for (i=0; i< msg->iov_count; i++) {
			total_len += msg->msg_iov[i].iov_len;
		}
		assert(total_len <= SOCK_EP_MAX_INJECT_SZ);
	} else {
		total_len = msg->iov_count * sizeof(union sock_iov);
	}

	total_len += sizeof(struct sock_op_send);
	
	if (flags & FI_REMOTE_CQ_DATA)
		total_len += sizeof(uint64_t);

	sock_tx_ctx_start(tx_ctx);
	if (rbfdavail(&tx_ctx->rbfd) < total_len) {
		ret = -FI_EAGAIN;
		goto err;
	}

	memset(&tx_op, 0, sizeof(struct sock_op));
	tx_op.op = (flags & FI_INJECT) ? SOCK_OP_SEND_INJECT : SOCK_OP_SEND;
	tx_op.src_iov_len = msg->iov_count;

	sock_tx_ctx_write(tx_ctx, &tx_op, sizeof(struct sock_op));
	sock_tx_ctx_write(tx_ctx, &flags, sizeof(uint64_t));
	sock_tx_ctx_write(tx_ctx, &msg->context, sizeof(uint64_t));
	sock_tx_ctx_write(tx_ctx, &msg->addr, sizeof(uint64_t));
	sock_tx_ctx_write(tx_ctx, &conn, sizeof(uint64_t));
	sock_tx_ctx_write(tx_ctx, &msg->msg_iov[0].iov_base, sizeof(uint64_t));

	if (flags & FI_REMOTE_CQ_DATA) {
		sock_tx_ctx_write(tx_ctx, &msg->data, sizeof(uint64_t));
	}

	if (flags & FI_INJECT) {
		for (i=0; i< msg->iov_count; i++) {
			sock_tx_ctx_write(tx_ctx, msg->msg_iov[i].iov_base, 
					  msg->msg_iov[i].iov_len);
		}
	} else {
		for (i=0; i< msg->iov_count; i++) {
			tx_iov.iov.addr = (uint64_t)msg->msg_iov[i].iov_base;
			tx_iov.iov.len = msg->msg_iov[i].iov_len;
			sock_tx_ctx_write(tx_ctx, &tx_iov, sizeof(union sock_iov));
		}
	}

	sock_tx_ctx_commit(tx_ctx);
	return 0;

err:
	sock_tx_ctx_abort(tx_ctx);
	return ret;
}

ssize_t sock_ctx_sendto(struct fid_ep *ep, const void *buf, size_t len, 
			    void *desc, fi_addr_t dest_addr, void *context)
{
	struct fi_msg msg;
	struct iovec msg_iov;

	msg_iov.iov_base = (void*)buf;
	msg_iov.iov_len = len;
	msg.msg_iov = &msg_iov;
	msg.desc = &desc;
	msg.iov_count = 1;
	msg.addr = dest_addr;
	msg.context = context;

	return sock_ctx_sendmsg(ep, &msg, 0);
}

ssize_t sock_ctx_send(struct fid_ep *ep, const void *buf, size_t len, 
			  void *desc, void *context)
{
	return sock_ctx_sendto(ep, buf, len, desc, FI_ADDR_UNSPEC, context);
}

ssize_t sock_ctx_sendv(struct fid_ep *ep, const struct iovec *iov, 
			   void **desc, size_t count, void *context)
{
	struct fi_msg msg;
	msg.msg_iov = iov;
	msg.desc = desc;
	msg.iov_count = count;
	msg.addr = FI_ADDR_UNSPEC;
	msg.context = context;
	return sock_ctx_sendmsg(ep, &msg, 0);
}


ssize_t sock_ctx_senddatato(struct fid_ep *ep, const void *buf, 
				size_t len, void *desc, uint64_t data, 
				fi_addr_t dest_addr, void *context)
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
	msg.data = data;

	return sock_ctx_sendmsg(ep, &msg, FI_REMOTE_CQ_DATA);
}

ssize_t sock_ctx_senddata(struct fid_ep *ep, const void *buf, size_t len, 
			      void *desc, uint64_t data, void *context)
{
	return sock_ctx_senddatato(ep, buf, len, desc, data, 
				       FI_ADDR_UNSPEC, context);
}

ssize_t sock_ctx_injectto(struct fid_ep *ep, const void *buf, size_t len,
			      fi_addr_t dest_addr)
{
	struct fi_msg msg;
	struct iovec msg_iov;
	
	msg_iov.iov_base = (void*)buf;
	msg_iov.iov_len = len;
	msg.msg_iov = &msg_iov;
	msg.iov_count = 1;
	msg.addr = dest_addr;

	return sock_ctx_sendmsg(ep, &msg, FI_INJECT);
}

ssize_t sock_ctx_inject(struct fid_ep *ep, const void *buf, size_t len)
{
	return sock_ctx_injectto(ep, buf, len, FI_ADDR_UNSPEC);
}

struct fi_ops_msg sock_ctx_msg_ops = {
	.size = sizeof(struct fi_ops_msg),
	.recv = sock_ctx_recv,
	.recvv = sock_ctx_recvv,
	.recvfrom = sock_ctx_recvfrom,
	.recvmsg = sock_ctx_recvmsg,
	.send = sock_ctx_send,
	.sendv = sock_ctx_sendv,
	.sendto = sock_ctx_sendto,
	.sendmsg = sock_ctx_sendmsg,
	.inject = sock_ctx_inject,
	.injectto = sock_ctx_injectto,
	.senddata = sock_ctx_senddata,
	.senddatato = sock_ctx_senddatato,
};

ssize_t sock_ctx_trecvmsg(struct fid_ep *ep, const struct fi_msg_tagged *msg,
		   uint64_t flags)
{
	int i;
	struct sock_rx_ctx *rx_ctx;
	struct sock_rx_entry *rx_entry;

	rx_ctx = container_of(ep, struct sock_rx_ctx, ctx);
	assert(rx_ctx->enabled && msg->iov_count <= SOCK_EP_MAX_IOV_LIMIT);

	rx_entry = sock_rx_new_entry(rx_ctx);
	if (!rx_entry)
		return -FI_ENOMEM;
	
	dlist_init(&rx_entry->entry);
	rx_entry->rx_op.op = SOCK_OP_TRECV;
	rx_entry->rx_op.dest_iov_len = msg->iov_count;

	rx_entry->flags = flags;
	rx_entry->context = (uint64_t)msg->context;
	rx_entry->addr = msg->addr;
	rx_entry->data = msg->data;
	rx_entry->tag = msg->tag;
	rx_entry->ignore = msg->ignore;

	for (i=0; i< msg->iov_count; i++) {
		rx_entry->iov[i].iov.addr = (uint64_t)msg->msg_iov[i].iov_base;
		rx_entry->iov[i].iov.len = (uint64_t)msg->msg_iov[i].iov_len;
	}

	fastlock_acquire(&rx_ctx->lock);
	dlist_insert_tail(&rx_entry->entry, &rx_ctx->rx_entry_list);
	fastlock_release(&rx_ctx->lock);
	return 0;
}

ssize_t sock_ctx_trecvfrom(struct fid_ep *ep, void *buf, size_t len, 
			       void *desc, fi_addr_t src_addr, uint64_t tag, 
			       uint64_t ignore, void *context)
{
	struct fi_msg_tagged msg;
	struct iovec msg_iov;

	msg_iov.iov_base = buf;
	msg_iov.iov_len = len;

	msg.msg_iov = &msg_iov;
	msg.desc = &desc;
	msg.iov_count = 1;
	msg.addr = src_addr;
	msg.context = context;
	msg.tag = tag;
	msg.ignore = ignore;

	return sock_ctx_trecvmsg(ep, &msg, 0);
}


ssize_t sock_ctx_trecv(struct fid_ep *ep, void *buf, size_t len, void *desc,
			   uint64_t tag, uint64_t ignore, void *context)
{
	return sock_ctx_trecvfrom(ep, buf, len, desc, FI_ADDR_UNSPEC,
				      tag, ignore, context);
}
ssize_t sock_ctx_trecvv(struct fid_ep *ep, const struct iovec *iov, 
			    void **desc, size_t count, uint64_t tag, 
			    uint64_t ignore, void *context)
{
	struct fi_msg_tagged msg;

	msg.msg_iov = iov;
	msg.desc = desc;
	msg.iov_count = count;
	msg.addr = FI_ADDR_UNSPEC;
	msg.context = context;
	msg.tag = tag;
	msg.ignore = ignore;
	return sock_ctx_trecvmsg(ep, &msg, 0);
}

ssize_t sock_ctx_tsendmsg(struct fid_ep *ep, const struct fi_msg_tagged *msg,
		   uint64_t flags)
{
	int ret, i;
	uint64_t total_len;
	struct sock_op tx_op;
	union sock_iov tx_iov;
	struct sock_conn *conn;
	struct sock_tx_ctx *tx_ctx;

	tx_ctx = container_of(ep, struct sock_tx_ctx, ctx);
	assert(tx_ctx->enabled && msg->iov_count <= SOCK_EP_MAX_IOV_LIMIT);

	ret = sock_av_lookup_addr(tx_ctx->av, msg->addr, &conn);
	assert(ret == 0);

	total_len = 0;
	if (flags & FI_INJECT) {
		for (i=0; i< msg->iov_count; i++) {
			total_len += msg->msg_iov[i].iov_len;
		}
		assert(total_len <= SOCK_EP_MAX_INJECT_SZ);
	} else {
		total_len = msg->iov_count * sizeof(union sock_iov);
	}

	total_len += sizeof(struct sock_op_tsend);
	if (flags & FI_REMOTE_CQ_DATA)
		total_len += sizeof(uint64_t);
	
	sock_tx_ctx_start(tx_ctx);
	if (rbfdavail(&tx_ctx->rbfd) < total_len) {
		ret = -FI_EAGAIN;
		goto err;
	}

	memset(&tx_op, 0, sizeof(struct sock_op));
	tx_op.op = (flags & FI_INJECT) ? SOCK_OP_TSEND_INJECT : SOCK_OP_TSEND;
	tx_op.src_iov_len = msg->iov_count;

	sock_tx_ctx_write(tx_ctx, &tx_op, sizeof(struct sock_op));
	sock_tx_ctx_write(tx_ctx, &flags, sizeof(uint64_t));
	sock_tx_ctx_write(tx_ctx, &msg->context, sizeof(uint64_t));
	sock_tx_ctx_write(tx_ctx, &msg->addr, sizeof(uint64_t));
	sock_tx_ctx_write(tx_ctx, &conn, sizeof(uint64_t));
	sock_tx_ctx_write(tx_ctx, &msg->msg_iov[0].iov_base, sizeof(uint64_t));

	if (flags & FI_REMOTE_CQ_DATA) {
		sock_tx_ctx_write(tx_ctx, &msg->data, sizeof(uint64_t));
	}
	sock_tx_ctx_write(tx_ctx, &msg->tag, sizeof(uint64_t));

	if (flags & FI_INJECT) {
		for (i=0; i< msg->iov_count; i++) {
			sock_tx_ctx_write(tx_ctx, msg->msg_iov[i].iov_base,
					  msg->msg_iov[i].iov_len);
		}
	} else {
		for (i=0; i< msg->iov_count; i++) {
			tx_iov.iov.addr = (uint64_t)msg->msg_iov[i].iov_base;
			tx_iov.iov.len = msg->msg_iov[i].iov_len;
			sock_tx_ctx_write(tx_ctx, &tx_iov, sizeof(union sock_iov));
		}
	}
	
	sock_tx_ctx_commit(tx_ctx);
	return 0;

err:
	sock_tx_ctx_abort(tx_ctx);
	return ret;
}

ssize_t sock_ctx_tsendto(struct fid_ep *ep, const void *buf, size_t len, 
			     void *desc, fi_addr_t dest_addr, uint64_t tag, 
			     void *context)
{
	struct fi_msg_tagged msg;
	struct iovec msg_iov;

	msg_iov.iov_base = (void*)buf;
	msg_iov.iov_len = len;
	msg.msg_iov = &msg_iov;
	msg.desc = &desc;
	msg.iov_count = 1;
	msg.addr = dest_addr;
	msg.context = context;
	msg.tag = tag;

	return sock_ctx_tsendmsg(ep, &msg, 0);
}

ssize_t sock_ctx_tsend(struct fid_ep *ep, const void *buf, size_t len, 
			   void *desc, uint64_t tag, void *context)
{
	return sock_ctx_tsendto(ep, buf, len, desc, FI_ADDR_UNSPEC, 
				    tag, context);
}

ssize_t sock_ctx_tsendv(struct fid_ep *ep, const struct iovec *iov, 
			    void **desc, size_t count, uint64_t tag, 
			    void *context)
{
	struct fi_msg_tagged msg;
	msg.msg_iov = iov;
	msg.desc = desc;
	msg.iov_count = count;
	msg.addr = FI_ADDR_UNSPEC;
	msg.context = context;
	msg.tag = tag;
	return sock_ctx_tsendmsg(ep, &msg, 0);
}

ssize_t sock_ctx_tsenddatato(struct fid_ep *ep, const void *buf, size_t len, 
				 void *desc, uint64_t data, fi_addr_t dest_addr, 
				 uint64_t tag, void *context)
{
	struct fi_msg_tagged msg;
	struct iovec msg_iov;

	msg_iov.iov_base = (void*)buf;
	msg_iov.iov_len = len;
	msg.msg_iov = &msg_iov;
	msg.desc = desc;
	msg.iov_count = 1;
	msg.addr = dest_addr;
	msg.context = context;
	msg.data = data;
	msg.tag = tag;

	return sock_ctx_tsendmsg(ep, &msg, FI_REMOTE_CQ_DATA);
}

ssize_t sock_ctx_tsenddata(struct fid_ep *ep, const void *buf, size_t len,
				void *desc, uint64_t data, uint64_t tag, 
			       void *context)
{
	return sock_ctx_tsenddatato(ep, buf, len, desc,
					FI_ADDR_UNSPEC, data, tag, context);
}

ssize_t sock_ctx_tinjectto(struct fid_ep *ep, const void *buf, size_t len,
		    fi_addr_t dest_addr, uint64_t tag)
{
	struct fi_msg_tagged msg;
	struct iovec msg_iov;

	msg_iov.iov_base = (void*)buf;
	msg_iov.iov_len = len;
	msg.msg_iov = &msg_iov;
	msg.iov_count = 1;
	msg.addr = dest_addr;
	msg.tag = tag;
	return sock_ctx_tsendmsg(ep, &msg, FI_INJECT);
}

ssize_t sock_ctx_tinject(struct fid_ep *ep, const void *buf, size_t len,
		  uint64_t tag)
{
	return sock_ctx_tinjectto(ep, buf, len, FI_ADDR_UNSPEC, tag);
}

ssize_t sock_ctx_tsearch(struct fid_ep *ep, uint64_t *tag, uint64_t ignore,
			     uint64_t flags, fi_addr_t *src_addr, size_t *len, 
			     void *context)
{
	return -FI_ENOSYS;
}


struct fi_ops_tagged sock_ctx_tagged = {
	.size = sizeof(struct fi_ops_tagged),
	.recv = sock_ctx_trecv,
	.recvv = sock_ctx_trecvv,
	.recvfrom = sock_ctx_trecvfrom,
	.recvmsg = sock_ctx_trecvmsg,
	.send = sock_ctx_tsend,
	.sendv = sock_ctx_tsendv,
	.sendto = sock_ctx_tsendto,
	.sendmsg = sock_ctx_tsendmsg,
	.inject = sock_ctx_tinject,
	.injectto = sock_ctx_tinjectto,
	.senddata = sock_ctx_tsenddata,
	.senddatato = sock_ctx_tsenddatato,
	.search = sock_ctx_tsearch,
};

ssize_t sock_ep_msg_recvmsg(struct fid_ep *ep, const struct fi_msg *msg,
				uint64_t flags)
{
	struct sock_ep *sock_ep;
	sock_ep = container_of(ep, struct sock_ep, ep);
	return sock_ctx_recvmsg(&sock_ep->rx_ctx->ctx,msg, flags);
}

ssize_t sock_ep_msg_recvfrom(struct fid_ep *ep, void *buf, size_t len, 
				 void *desc, fi_addr_t src_addr, void *context)
{
	struct sock_ep *sock_ep;
	sock_ep = container_of(ep, struct sock_ep, ep);
	return sock_ctx_recvfrom(&sock_ep->rx_ctx->ctx, buf, len, desc,
				     src_addr, context);
}

ssize_t sock_ep_msg_recv(struct fid_ep *ep, void *buf, size_t len, 
			     void *desc, void *context)
{
	struct sock_ep *sock_ep;
	sock_ep = container_of(ep, struct sock_ep, ep);
	return sock_ctx_recv(&sock_ep->rx_ctx->ctx, buf, len, desc, context);
}

ssize_t sock_ep_msg_recvv(struct fid_ep *ep, const struct iovec *iov, void **desc,
			      size_t count, void *context)
{
	struct sock_ep *sock_ep;
	sock_ep = container_of(ep, struct sock_ep, ep);
	return sock_ctx_recvv(&sock_ep->rx_ctx->ctx, iov, desc, 
				  count, context);
}

ssize_t sock_ep_msg_sendmsg(struct fid_ep *ep, const struct fi_msg *msg,
				uint64_t flags)
{
	struct sock_ep *sock_ep;
	sock_ep = container_of(ep, struct sock_ep, ep);
	return sock_ctx_sendmsg(&sock_ep->tx_ctx->ctx, msg, flags);
}

ssize_t sock_ep_msg_sendto(struct fid_ep *ep, const void *buf, size_t len, 
			       void *desc, fi_addr_t dest_addr, void *context)
{
	struct sock_ep *sock_ep;
	sock_ep = container_of(ep, struct sock_ep, ep);
	return sock_ctx_sendto(&sock_ep->tx_ctx->ctx, buf, len, desc,
				   dest_addr, context);
}

ssize_t sock_ep_msg_send(struct fid_ep *ep, const void *buf, size_t len, 
			     void *desc, void *context)
{
	struct sock_ep *sock_ep;
	sock_ep = container_of(ep, struct sock_ep, ep);
	return sock_ctx_send(&sock_ep->tx_ctx->ctx, buf, len, desc, context);
}

ssize_t sock_ep_msg_sendv(struct fid_ep *ep, const struct iovec *iov, 
			      void **desc, size_t count, void *context)
{
	struct sock_ep *sock_ep;
	sock_ep = container_of(ep, struct sock_ep, ep);
	return sock_ctx_sendv(&sock_ep->tx_ctx->ctx, iov, desc,
				  count, context);
}


ssize_t sock_ep_msg_inject(struct fid_ep *ep, const void *buf, size_t len)
{
	struct sock_ep *sock_ep;
	sock_ep = container_of(ep, struct sock_ep, ep);
	return sock_ctx_inject(&sock_ep->tx_ctx->ctx, buf, len);
}

ssize_t sock_ep_msg_injectto(struct fid_ep *ep, const void *buf, size_t len,
				 fi_addr_t dest_addr)
{
	struct sock_ep *sock_ep;
	sock_ep = container_of(ep, struct sock_ep, ep);
	return sock_ctx_injectto(&sock_ep->tx_ctx->ctx, buf, len, dest_addr);
}

ssize_t sock_ep_msg_senddatato(struct fid_ep *ep, const void *buf, size_t len, 
				   void *desc, uint64_t data, fi_addr_t dest_addr, 
				   void *context)
{
	struct sock_ep *sock_ep;
	sock_ep = container_of(ep, struct sock_ep, ep);
	return sock_ctx_senddatato(&sock_ep->tx_ctx->ctx, buf, len, 
				       desc, data, dest_addr, context);
}

ssize_t sock_ep_msg_senddata(struct fid_ep *ep, const void *buf, size_t len, 
				 void *desc, uint64_t data, void *context)
{
	struct sock_ep *sock_ep;
	sock_ep = container_of(ep, struct sock_ep, ep);
	return sock_ctx_senddata(&sock_ep->tx_ctx->ctx, buf, len, desc, 
				     data, context);
}

struct fi_ops_msg sock_ep_msg_ops = {
	.size = sizeof(struct fi_ops_msg),
	.recv = sock_ep_msg_recv,
	.recvv = sock_ep_msg_recvv,
	.recvfrom = sock_ep_msg_recvfrom,
	.recvmsg = sock_ep_msg_recvmsg,
	.send = sock_ep_msg_send,
	.sendv = sock_ep_msg_sendv,
	.sendto = sock_ep_msg_sendto,
	.sendmsg = sock_ep_msg_sendmsg,
	.inject = sock_ep_msg_inject,
	.injectto = sock_ep_msg_injectto,
	.senddata = sock_ep_msg_senddata,
	.senddatato = sock_ep_msg_senddatato,
};


ssize_t sock_ep_trecvmsg(struct fid_ep *ep, const struct fi_msg_tagged *msg,
		   uint64_t flags)
{
	struct sock_ep *sock_ep;
	sock_ep = container_of(ep, struct sock_ep, ep);
	return sock_ctx_trecvmsg(&sock_ep->rx_ctx->ctx, msg, flags);
}

ssize_t sock_ep_trecvfrom(struct fid_ep *ep, void *buf, size_t len, 
			       void *desc, fi_addr_t src_addr, uint64_t tag, 
			       uint64_t ignore, void *context)
{
	struct sock_ep *sock_ep;
	sock_ep = container_of(ep, struct sock_ep, ep);
	return sock_ctx_trecvfrom(&sock_ep->rx_ctx->ctx, buf, len, desc,
				      src_addr, tag, ignore, context);
}


ssize_t sock_ep_trecv(struct fid_ep *ep, void *buf, size_t len, void *desc,
			   uint64_t tag, uint64_t ignore, void *context)
{
	struct sock_ep *sock_ep;
	sock_ep = container_of(ep, struct sock_ep, ep);
	return sock_ctx_trecv(&sock_ep->rx_ctx->ctx, buf, len, desc,
				  tag, ignore, context);
}

ssize_t sock_ep_trecvv(struct fid_ep *ep, const struct iovec *iov, 
			    void **desc, size_t count, uint64_t tag, 
			    uint64_t ignore, void *context)
{
	struct sock_ep *sock_ep;
	sock_ep = container_of(ep, struct sock_ep, ep);
	return sock_ctx_trecvv(&sock_ep->rx_ctx->ctx, iov, desc, count,
				   tag, ignore, context);
}


ssize_t sock_ep_tsendmsg(struct fid_ep *ep, const struct fi_msg_tagged *msg,
		   uint64_t flags)
{
	struct sock_ep *sock_ep;
	sock_ep = container_of(ep, struct sock_ep, ep);
	return sock_ctx_tsendmsg(&sock_ep->tx_ctx->ctx, msg, flags);
}

ssize_t sock_ep_tsendto(struct fid_ep *ep, const void *buf, size_t len, 
			     void *desc, fi_addr_t dest_addr, uint64_t tag, 
			     void *context)
{
	struct sock_ep *sock_ep;
	sock_ep = container_of(ep, struct sock_ep, ep);
	return sock_ctx_tsendto(&sock_ep->tx_ctx->ctx, buf, len, desc,
				    dest_addr, tag, context);
}

ssize_t sock_ep_tsend(struct fid_ep *ep, const void *buf, size_t len, 
			   void *desc, uint64_t tag, void *context)
{
	struct sock_ep *sock_ep;
	sock_ep = container_of(ep, struct sock_ep, ep);
	return sock_ctx_tsend(&sock_ep->tx_ctx->ctx, buf, len, desc,
				  tag, context);
}

ssize_t sock_ep_tsendv(struct fid_ep *ep, const struct iovec *iov, 
			    void **desc, size_t count, uint64_t tag, 
			    void *context)
{
	struct sock_ep *sock_ep;
	sock_ep = container_of(ep, struct sock_ep, ep);
	return sock_ctx_tsendv(&sock_ep->tx_ctx->ctx, iov, desc, count,
				  tag, context);
}

ssize_t sock_ep_tsenddatato(struct fid_ep *ep, const void *buf, size_t len, 
				 void *desc, uint64_t data, fi_addr_t dest_addr, 
				 uint64_t tag, void *context)
{
	struct sock_ep *sock_ep;
	sock_ep = container_of(ep, struct sock_ep, ep);
	return sock_ctx_tsenddatato(&sock_ep->tx_ctx->ctx, buf, len, desc,
					data, dest_addr, tag, context);
}

ssize_t sock_ep_tsenddata(struct fid_ep *ep, const void *buf, size_t len,
				void *desc, uint64_t data, uint64_t tag, 
			       void *context)
{
	struct sock_ep *sock_ep;
	sock_ep = container_of(ep, struct sock_ep, ep);
	return sock_ctx_tsenddata(&sock_ep->tx_ctx->ctx, buf, len, desc,
				      data, tag, context);
}


ssize_t sock_ep_tinjectto(struct fid_ep *ep, const void *buf, size_t len,
		    fi_addr_t dest_addr, uint64_t tag)
{
	struct sock_ep *sock_ep;
	sock_ep = container_of(ep, struct sock_ep, ep);
	return sock_ctx_tinjectto(&sock_ep->tx_ctx->ctx, buf, len,
				      dest_addr, tag);
}

ssize_t sock_ep_tinject(struct fid_ep *ep, const void *buf, size_t len,
		  uint64_t tag)
{
	struct sock_ep *sock_ep;
	sock_ep = container_of(ep, struct sock_ep, ep);
	return sock_ctx_tinject(&sock_ep->tx_ctx->ctx, buf, len, tag);
}

ssize_t sock_ep_tsearch(struct fid_ep *ep, uint64_t *tag, uint64_t ignore,
			     uint64_t flags, fi_addr_t *src_addr, size_t *len, 
			     void *context)
{
	return -FI_ENOSYS;
}


struct fi_ops_tagged sock_ep_tagged = {
	.size = sizeof(struct fi_ops_tagged),
	.recv = sock_ep_trecv,
	.recvv = sock_ep_trecvv,
	.recvfrom = sock_ep_trecvfrom,
	.recvmsg = sock_ep_trecvmsg,
	.send = sock_ep_tsend,
	.sendv = sock_ep_tsendv,
	.sendto = sock_ep_tsendto,
	.sendmsg = sock_ep_tsendmsg,
	.inject = sock_ep_tinject,
	.injectto = sock_ep_tinjectto,
	.senddata = sock_ep_tsenddata,
	.senddatato = sock_ep_tsenddatato,
	.search = sock_ep_tsearch,
};

