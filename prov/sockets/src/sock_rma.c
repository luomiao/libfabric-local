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

static ssize_t sock_ctx_rma_readmsg(struct fid_ep *ep, 
					const struct fi_msg_rma *msg, 
					uint64_t flags)
{
	int ret, i;
	struct sock_op tx_op;
	union sock_iov tx_iov;
	struct sock_conn *conn;
	struct sock_tx_ctx *tx_ctx;
	uint64_t total_len, src_len, dst_len;

	tx_ctx = container_of(ep, struct sock_tx_ctx, ctx);
	assert(tx_ctx->enabled && 
	       msg->iov_count <= SOCK_EP_MAX_IOV_LIMIT &&
	       msg->rma_iov_count <= SOCK_EP_MAX_IOV_LIMIT);

	ret = sock_av_lookup_addr(tx_ctx->av, msg->addr, &conn);
	assert(ret == 0);

	total_len = sizeof(struct sock_op_send);
	total_len += (msg->iov_count * sizeof(union sock_iov));
	total_len += (msg->rma_iov_count * sizeof(union sock_iov));

	sock_tx_ctx_start(tx_ctx);
	if (rbfdavail(&tx_ctx->rbfd) < total_len) {
		ret = -FI_EAGAIN;
		goto err;
	}
	
	memset(&tx_op, 0, sizeof(struct sock_op));
	tx_op.op = SOCK_OP_READ;
	tx_op.src_iov_len = msg->rma_iov_count;
	tx_op.dest_iov_len = msg->iov_count;

	sock_tx_ctx_write(tx_ctx, &tx_op, sizeof(struct sock_op));
	sock_tx_ctx_write(tx_ctx, &flags, sizeof(uint64_t));
	sock_tx_ctx_write(tx_ctx, &msg->context, sizeof(uint64_t));
	sock_tx_ctx_write(tx_ctx, &msg->addr, sizeof(uint64_t));
	sock_tx_ctx_write(tx_ctx, &conn, sizeof(uint64_t));
	if (flags & FI_REMOTE_CQ_DATA) {
		sock_tx_ctx_write(tx_ctx, &msg->data, sizeof(uint64_t));
	}

	src_len = 0;
	for (i = 0; i< msg->rma_iov_count; i++) {
		tx_iov.iov.addr = msg->rma_iov[i].addr;
		tx_iov.iov.key = msg->rma_iov[i].key;
		tx_iov.iov.len = msg->rma_iov[i].len;
		sock_tx_ctx_write(tx_ctx, &tx_iov, sizeof(union sock_iov));
		src_len += tx_iov.iov.len;
	}

	dst_len = 0;
	for (i = 0; i< msg->iov_count; i++) {
		tx_iov.iov.addr = (uint64_t)msg->msg_iov[i].iov_base;
		tx_iov.iov.len = msg->msg_iov[i].iov_len;
		tx_iov.iov.key = (uint64_t)msg->desc[i];
		sock_tx_ctx_write(tx_ctx, &tx_iov, sizeof(union sock_iov));
		dst_len += tx_iov.iov.len;
	}

	if (dst_len != src_len) {
		SOCK_LOG_ERROR("Buffer length mismatch\n");
		ret = -FI_EINVAL;
		goto err;
	}
	
	sock_tx_ctx_commit(tx_ctx);
	return 0;

err:
	sock_tx_ctx_abort(tx_ctx);
	return ret;
}

static ssize_t sock_ctx_rma_readfrom(struct fid_ep *ep, void *buf, size_t len,
					 void *desc, fi_addr_t src_addr, 
					 uint64_t addr, uint64_t key, 
					 void *context)
{
	struct fi_msg_rma msg;
	struct iovec msg_iov;
	struct fi_rma_iov rma_iov;

	msg_iov.iov_base = (void*)buf;
	msg_iov.iov_len = len;
	msg.msg_iov = &msg_iov;
	msg.desc = &desc;
	msg.iov_count = 1;

	rma_iov.addr = addr;
	rma_iov.key = key;
	rma_iov.len = len;
	msg.rma_iov_count = 1;
	msg.rma_iov = &rma_iov;

	msg.addr = src_addr;
	msg.context = context;

	return sock_ctx_rma_readmsg(ep, &msg, 0);
}

static ssize_t sock_ctx_rma_read(struct fid_ep *ep, void *buf, size_t len,
				     void *desc, uint64_t addr, uint64_t key, 
				     void *context)
{
	return sock_ctx_rma_readfrom(ep, buf, len, desc,
					 FI_ADDR_UNSPEC, addr, key, context);
}

static ssize_t sock_ctx_rma_readv(struct fid_ep *ep, const struct iovec *iov,
				      void **desc, size_t count, uint64_t addr,
				      uint64_t key, void *context)
{
	struct fi_msg_rma msg;
	struct fi_rma_iov rma_iov;

	msg.msg_iov = iov;
	msg.desc = desc;
	msg.iov_count = count;

	rma_iov.addr = addr;
	rma_iov.key = key;
	rma_iov.len = 1;

	msg.addr = FI_ADDR_UNSPEC;
	msg.context = context;

	return sock_ctx_rma_readmsg(ep, &msg, 0);
}

static ssize_t sock_ctx_rma_writemsg(struct fid_ep *ep, 
					 const struct fi_msg_rma *msg, 
					 uint64_t flags)
{
	int ret, i;
	struct sock_op tx_op;
	union sock_iov tx_iov;
	struct sock_conn *conn;
	struct sock_tx_ctx *tx_ctx;
	uint64_t total_len, src_len, dst_len;

	tx_ctx = container_of(ep, struct sock_tx_ctx, ctx);
	assert(tx_ctx->enabled && 
	       msg->iov_count <= SOCK_EP_MAX_IOV_LIMIT &&
	       msg->rma_iov_count <= SOCK_EP_MAX_IOV_LIMIT);

	ret = sock_av_lookup_addr(tx_ctx->av, msg->addr, &conn);
	assert(ret == 0);
	
	total_len = 0;
	if (flags & FI_INJECT) {
		for (i=0; i< msg->iov_count; i++) {
			total_len += msg->msg_iov[i].iov_len;
		}
		assert(total_len <= SOCK_EP_MAX_INJECT_SZ);
	} else {
		total_len += msg->iov_count * sizeof(union sock_iov);
	}

	total_len += sizeof(struct sock_op_send);
	total_len += (msg->rma_iov_count * sizeof(union sock_iov));

	sock_tx_ctx_start(tx_ctx);
	if (rbfdavail(&tx_ctx->rbfd) < total_len) {
		ret = -FI_EAGAIN;
		goto err;
	}
	
	memset(&tx_op, 0, sizeof(struct sock_op));
	tx_op.op = SOCK_OP_WRITE;
	tx_op.src_iov_len = msg->iov_count;
	tx_op.dest_iov_len = msg->rma_iov_count;

	sock_tx_ctx_write(tx_ctx, &tx_op, sizeof(struct sock_op));
	sock_tx_ctx_write(tx_ctx, &flags, sizeof(uint64_t));
	sock_tx_ctx_write(tx_ctx, &msg->context, sizeof(uint64_t));
	sock_tx_ctx_write(tx_ctx, &msg->addr, sizeof(uint64_t));
	sock_tx_ctx_write(tx_ctx, &conn, sizeof(uint64_t));
	if (flags & FI_REMOTE_CQ_DATA) {
		sock_tx_ctx_write(tx_ctx, &msg->data, sizeof(uint64_t));
	}

	src_len = 0;
	if (flags & FI_INJECT) {
		for (i=0; i< msg->iov_count; i++) {
			sock_tx_ctx_write(tx_ctx, msg->msg_iov[i].iov_base,
					  msg->msg_iov[i].iov_len);
			src_len += tx_iov.iov.len;
		}
	} else {
		for (i = 0; i< msg->iov_count; i++) {
			tx_iov.iov.addr = (uint64_t)msg->msg_iov[i].iov_base;
			tx_iov.iov.len = msg->msg_iov[i].iov_len;
			tx_iov.iov.key = (uint64_t)msg->desc[i];
			sock_tx_ctx_write(tx_ctx, &tx_iov, sizeof(union sock_iov));
			src_len += tx_iov.iov.len;
		}
	}

	dst_len = 0;
	for (i = 0; i< msg->rma_iov_count; i++) {
		tx_iov.iov.addr = msg->rma_iov[i].addr;
		tx_iov.iov.key = msg->rma_iov[i].key;
		tx_iov.iov.len = msg->rma_iov[i].len;
		sock_tx_ctx_write(tx_ctx, &tx_iov, sizeof(union sock_iov));
		dst_len += tx_iov.iov.len;
	}
	
	if (dst_len != src_len) {
		SOCK_LOG_ERROR("Buffer length mismatch\n");
		ret = -FI_EINVAL;
		goto err;
	}
	
	sock_tx_ctx_commit(tx_ctx);
	return 0;

err:
	sock_tx_ctx_abort(tx_ctx);
	return ret;
}

static ssize_t sock_ctx_rma_writeto(struct fid_ep *ep, const void *buf, 
					size_t len, void *desc, 
					fi_addr_t dest_addr, uint64_t addr, 
					uint64_t key, void *context)
{
	struct fi_msg_rma msg;
	struct iovec msg_iov;
	struct fi_rma_iov rma_iov;

	msg_iov.iov_base = (void*)buf;
	msg_iov.iov_len = len;

	msg.msg_iov = &msg_iov;
	msg.desc = &desc;
	msg.iov_count = 1;

	rma_iov.addr = addr;
	rma_iov.key = key;
	rma_iov.len = len;

	msg.rma_iov_count = 1;
	msg.rma_iov = &rma_iov;

	msg.addr = dest_addr;
	msg.context = context;

	return sock_ctx_rma_writemsg(ep, &msg, 0);
}


static ssize_t sock_ctx_rma_write(struct fid_ep *ep, const void *buf, 
				      size_t len, void *desc, uint64_t addr, 
				      uint64_t key, void *context)
{
	return sock_ctx_rma_writeto(ep, buf, len, desc, 
					FI_ADDR_UNSPEC, addr, key, context);
}

static ssize_t sock_ctx_rma_writev(struct fid_ep *ep, 
				       const struct iovec *iov, void **desc,
				       size_t count, uint64_t addr, uint64_t key, 
				       void *context)
{
	struct fi_msg_rma msg;
	struct fi_rma_iov rma_iov;

	msg.msg_iov = iov;
	msg.desc = desc;
	msg.iov_count = count;

	rma_iov.addr = addr;
	rma_iov.key = key;
	rma_iov.len = 1;
	
	msg.context = context;
	msg.addr = FI_ADDR_UNSPEC;

	return sock_ctx_rma_writemsg(ep, &msg, 0);
}

static ssize_t sock_ctx_rma_writedatato(struct fid_ep *ep, const void *buf, 
					    size_t len, void *desc,uint64_t data,
					    fi_addr_t dest_addr, uint64_t addr, 
					    uint64_t key, void *context)
{
	struct fi_msg_rma msg;
	struct iovec msg_iov;
	struct fi_rma_iov rma_iov;

	msg_iov.iov_base = (void*)buf;
	msg_iov.iov_len = len;
	msg.msg_iov = &msg_iov;
	msg.desc = &desc;
	msg.iov_count = 1;

	rma_iov.addr = addr;
	rma_iov.key = key;
	rma_iov.len = 1;
	msg.addr = dest_addr;
	msg.context = context;
	msg.data = data;

	return sock_ctx_rma_writemsg(ep, &msg, FI_REMOTE_CQ_DATA);
}

static ssize_t sock_ctx_rma_writedata(struct fid_ep *ep, const void *buf, 
					  size_t len, void *desc,
					  uint64_t data, uint64_t addr, 
					  uint64_t key, void *context)
{
	return sock_ctx_rma_writedatato(ep, buf, len, desc, data,
					    FI_ADDR_UNSPEC, addr, 
					    key, context);
}

static ssize_t sock_ctx_rma_injectto(struct fid_ep *ep, const void *buf, 
					 size_t len, fi_addr_t dest_addr, 
					 uint64_t addr, uint64_t key)
{
	struct fi_msg_rma msg;
	struct iovec msg_iov;
	struct fi_rma_iov rma_iov;

	msg_iov.iov_base = (void*)buf;
	msg_iov.iov_len = len;
	msg.msg_iov = &msg_iov;
	msg.iov_count = 1;

	rma_iov.addr = addr;
	rma_iov.key = key;
	rma_iov.len = 1;
	msg.addr = dest_addr;

	return sock_ctx_rma_writemsg(ep, &msg, FI_INJECT);
}


static ssize_t sock_ctx_rma_inject(struct fid_ep *ep, const void *buf, 
				       size_t len, uint64_t addr, uint64_t key)
{
	return sock_ctx_rma_injectto(ep, buf, len, FI_ADDR_UNSPEC, 
					 addr, key);
}

struct fi_ops_rma sock_ctx_rma = {
	.size  = sizeof(struct fi_ops_rma),
	.read = sock_ctx_rma_read,
	.readv = sock_ctx_rma_readv,
	.readfrom = sock_ctx_rma_readfrom,
	.readmsg = sock_ctx_rma_readmsg,
	.write = sock_ctx_rma_write,
	.writev = sock_ctx_rma_writev,
	.writeto = sock_ctx_rma_writeto,
	.writemsg = sock_ctx_rma_writemsg,
	.inject = sock_ctx_rma_inject,
	.injectto = sock_ctx_rma_injectto,
	.writedata = sock_ctx_rma_writedata,
	.writedatato = sock_ctx_rma_writedatato,
};

static ssize_t sock_ep_rma_readmsg(struct fid_ep *ep, 
					const struct fi_msg_rma *msg, 
					uint64_t flags)
{
	struct sock_ep *sock_ep;
	sock_ep = container_of(ep, struct sock_ep, ep);
	return sock_ctx_rma_readmsg(&sock_ep->tx_ctx->ctx, msg, flags);
}

static ssize_t sock_ep_rma_readfrom(struct fid_ep *ep, void *buf, size_t len,
					 void *desc, fi_addr_t src_addr, 
					 uint64_t addr, uint64_t key, 
					 void *context)
{
	struct sock_ep *sock_ep;
	sock_ep = container_of(ep, struct sock_ep, ep);
	return sock_ctx_rma_readfrom(&sock_ep->tx_ctx->ctx, buf, len,
					 desc, src_addr, addr, key, context);
}

static ssize_t sock_ep_rma_read(struct fid_ep *ep, void *buf, size_t len,
				     void *desc, uint64_t addr, uint64_t key, 
				     void *context)
{
	struct sock_ep *sock_ep;
	sock_ep = container_of(ep, struct sock_ep, ep);
	return sock_ctx_rma_read(&sock_ep->tx_ctx->ctx, buf, len,
				     desc, addr, key, context);
}

static ssize_t sock_ep_rma_readv(struct fid_ep *ep, const struct iovec *iov,
				      void **desc, size_t count, uint64_t addr,
				      uint64_t key, void *context)
{
	struct sock_ep *sock_ep;
	sock_ep = container_of(ep, struct sock_ep, ep);
	return sock_ctx_rma_readv(&sock_ep->tx_ctx->ctx, iov, desc, count,
				      addr, key, context);
}

static ssize_t sock_ep_rma_writemsg(struct fid_ep *ep, 
					 const struct fi_msg_rma *msg, 
					 uint64_t flags)
{
	struct sock_ep *sock_ep;
	sock_ep = container_of(ep, struct sock_ep, ep);
	return sock_ctx_rma_writemsg(&sock_ep->tx_ctx->ctx, msg, flags);
}

static ssize_t sock_ep_rma_writeto(struct fid_ep *ep, const void *buf, 
					size_t len, void *desc, 
					fi_addr_t dest_addr, uint64_t addr, 
					uint64_t key, void *context)
{
	struct sock_ep *sock_ep;
	sock_ep = container_of(ep, struct sock_ep, ep);
	return sock_ctx_rma_writeto(&sock_ep->tx_ctx->ctx, buf, len, desc,
					dest_addr, addr, key, context);
}


static ssize_t sock_ep_rma_write(struct fid_ep *ep, const void *buf, 
				      size_t len, void *desc, uint64_t addr, 
				      uint64_t key, void *context)
{
	struct sock_ep *sock_ep;
	sock_ep = container_of(ep, struct sock_ep, ep);
	return sock_ctx_rma_write(&sock_ep->tx_ctx->ctx, buf, len, desc,
				      addr, key, context);
}

static ssize_t sock_ep_rma_writev(struct fid_ep *ep, 
				       const struct iovec *iov, void **desc,
				       size_t count, uint64_t addr, uint64_t key, 
				       void *context)
{
	struct sock_ep *sock_ep;
	sock_ep = container_of(ep, struct sock_ep, ep);
	return sock_ctx_rma_writev(&sock_ep->tx_ctx->ctx, iov, desc, count,
				       addr, key, context);
}

static ssize_t sock_ep_rma_writedatato(struct fid_ep *ep, const void *buf, 
					    size_t len, void *desc,uint64_t data,
					    fi_addr_t dest_addr, uint64_t addr, 
					    uint64_t key, void *context)
{
	struct sock_ep *sock_ep;
	sock_ep = container_of(ep, struct sock_ep, ep);
	return sock_ctx_rma_writedatato(&sock_ep->tx_ctx->ctx, buf, len,
					    desc, data, dest_addr,
					    addr, key, context);
}

static ssize_t sock_ep_rma_writedata(struct fid_ep *ep, const void *buf, 
					  size_t len, void *desc,
					  uint64_t data, uint64_t addr, 
					  uint64_t key, void *context)
{
	struct sock_ep *sock_ep;
	sock_ep = container_of(ep, struct sock_ep, ep);
	return sock_ctx_rma_writedata(&sock_ep->tx_ctx->ctx, buf, len,
					    desc, data,addr, key, context);
}

static ssize_t sock_ep_rma_injectto(struct fid_ep *ep, const void *buf, 
					 size_t len, fi_addr_t dest_addr, 
					 uint64_t addr, uint64_t key)
{
	struct sock_ep *sock_ep;
	sock_ep = container_of(ep, struct sock_ep, ep);
	return sock_ctx_rma_injectto(&sock_ep->tx_ctx->ctx, buf, len,
					 dest_addr, addr, key);
}


static ssize_t sock_ep_rma_inject(struct fid_ep *ep, const void *buf, 
				       size_t len, uint64_t addr, uint64_t key)
{
	struct sock_ep *sock_ep;
	sock_ep = container_of(ep, struct sock_ep, ep);
	return sock_ctx_rma_inject(&sock_ep->tx_ctx->ctx, buf, len,
					 addr, key);
}

struct fi_ops_rma sock_ep_rma = {
	.size  = sizeof(struct fi_ops_rma),
	.read = sock_ep_rma_read,
	.readv = sock_ep_rma_readv,
	.readfrom = sock_ep_rma_readfrom,
	.readmsg = sock_ep_rma_readmsg,
	.write = sock_ep_rma_write,
	.writev = sock_ep_rma_writev,
	.writeto = sock_ep_rma_writeto,
	.writemsg = sock_ep_rma_writemsg,
	.inject = sock_ep_rma_inject,
	.injectto = sock_ep_rma_injectto,
	.writedata = sock_ep_rma_writedata,
	.writedatato = sock_ep_rma_writedatato,
};


