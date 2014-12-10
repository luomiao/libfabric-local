/*
 * Copyright (c) 2013-2014 Intel Corporation. All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * OpenFabrics.org BSD license below:
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

#include <stdlib.h>
#include <string.h>

#include "sock.h"
#include "sock_util.h"

extern struct fi_ops_rma sock_ctx_rma;
extern struct fi_ops_msg sock_ctx_msg_ops;
extern struct fi_ops_tagged sock_ctx_tagged;
extern struct fi_ops_atomic sock_ctx_atomic;

static int sock_ctx_close(struct fid *fid)
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

static int sock_ctx_bind_cq(struct fid *fid, struct fid *bfid, uint64_t flags)
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

static int sock_ctx_bind_cntr(struct fid *fid, struct fid *bfid, uint64_t flags)
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

static int sock_ctx_bind(struct fid *fid, struct fid *bfid, uint64_t flags)
{
	switch (bfid->fclass) {
	case FI_CLASS_CQ:
		return sock_ctx_bind_cq(fid, bfid, flags);

	case FI_CLASS_CNTR:
		return sock_ctx_bind_cntr(fid, bfid, flags);

	default:
		SOCK_LOG_ERROR("Invalid bind()\n");
		return -FI_EINVAL;
	}

}

struct fi_ops sock_ctx_ops = {
	.size = sizeof(struct fi_ops),
	.close = sock_ctx_close,
	.bind = sock_ctx_bind,
	.control = fi_no_control,
};

static int sock_ctx_enable(struct fid_ep *ep)
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

static int sock_ctx_getopt(fid_t fid, int level, int optname,
		       void *optval, size_t *optlen)
{
	struct sock_rx_ctx *rx_ctx;
	rx_ctx = container_of(fid, struct sock_rx_ctx, ctx.fid);

	if (level != FI_OPT_ENDPOINT)
		return -ENOPROTOOPT;

	switch (optname) {
	case FI_OPT_MIN_MULTI_RECV:
		*(size_t *)optval = rx_ctx->min_multi_recv;
		*optlen = sizeof(size_t);
		break;

	default:
		return -FI_ENOPROTOOPT;
	}
	return 0;
}

static int sock_ctx_setopt(fid_t fid, int level, int optname,
		       const void *optval, size_t optlen)
{
	struct sock_rx_ctx *rx_ctx;
	rx_ctx = container_of(fid, struct sock_rx_ctx, ctx.fid);

	if (level != FI_OPT_ENDPOINT)
		return -ENOPROTOOPT;

	switch (optname) {
	case FI_OPT_MIN_MULTI_RECV:
		rx_ctx->min_multi_recv = *(size_t *)optval;
		break;
		
	default:
		return -ENOPROTOOPT;
	}
	return 0;
}

struct fi_ops_ep sock_ctx_ep_ops = {
	.size = sizeof(struct fi_ops_ep),
	.enable = sock_ctx_enable,
	.cancel = fi_no_cancel,
	.getopt = sock_ctx_getopt,
	.setopt = sock_ctx_setopt,
	.tx_ctx = fi_no_tx_ctx,
	.rx_ctx = fi_no_rx_ctx,
};

static int sock_ep_fi_close(struct fid *fid)
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

static int sock_ep_fi_bind(struct fid *fid, struct fid *bfid, uint64_t flags)
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

			if ((ret = sock_ctx_bind_cq(&tx_ctx->ctx.fid, 
							bfid, flags)))
				return ret;
		}

		for (i=0; i<=ep->ep_attr.rx_ctx_cnt; i++) {
			rx_ctx = ep->rx_array[i];

			if (!rx_ctx)
				continue;

			if ((ret = sock_ctx_bind_cq(&rx_ctx->ctx.fid, 
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

			if ((ret = sock_ctx_bind_cntr(&tx_ctx->ctx.fid, 
							  bfid, flags)))
				return ret;
		}

		for (i=0; i<=ep->ep_attr.rx_ctx_cnt; i++) {
			rx_ctx = ep->rx_array[i];

			if (!rx_ctx)
				continue;

			if ((ret = sock_ctx_bind_cntr(&rx_ctx->ctx.fid, 
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

struct fi_ops sock_ep_fi_ops = {
	.size = sizeof(struct fi_ops),
	.close = sock_ep_fi_close,
	.bind = sock_ep_fi_bind,
	.control = fi_no_control,
	.ops_open = fi_no_ops_open,
};

static int sock_ep_enable(struct fid_ep *ep)
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

static int sock_ep_getopt(fid_t fid, int level, int optname,
		       void *optval, size_t *optlen)
{
	struct sock_ep *sock_ep;
	sock_ep = container_of(fid, struct sock_ep, ep.fid);

	if (level != FI_OPT_ENDPOINT)
		return -ENOPROTOOPT;

	switch (optname) {
	case FI_OPT_MIN_MULTI_RECV:
		*(size_t *)optval = sock_ep->min_multi_recv;
		*optlen = sizeof(size_t);
		break;

	default:
		return -FI_ENOPROTOOPT;
	}
	return 0;
}

static int sock_ep_setopt(fid_t fid, int level, int optname,
		       const void *optval, size_t optlen)
{
	int i;
	struct sock_ep *sock_ep;
	sock_ep = container_of(fid, struct sock_ep, ep.fid);

	if (level != FI_OPT_ENDPOINT)
		return -ENOPROTOOPT;

	switch (optname) {
	case FI_OPT_MIN_MULTI_RECV:

		sock_ep->min_multi_recv = *(size_t *)optval;
		for (i = 0; i < sock_ep->ep_attr.rx_ctx_cnt + 1; i ++) {
			if (sock_ep->rx_array[i] != NULL) {
				sock_ep->rx_array[i]->min_multi_recv = 
					sock_ep->min_multi_recv;
			}
		}
		break;
		
	default:
		return -ENOPROTOOPT;
	}
	return 0;
}

static int sock_ep_tx_ctx(struct fid_sep *ep, int index, struct fi_tx_attr *attr, 
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

	tx_ctx->ctx.ops = &sock_ctx_ep_ops;
	tx_ctx->ctx.msg = &sock_ctx_msg_ops;
	tx_ctx->ctx.tagged = &sock_ctx_tagged;
	tx_ctx->ctx.rma = &sock_ctx_rma;
	tx_ctx->ctx.atomic = &sock_ctx_atomic;

	*tx_ep = &tx_ctx->ctx;
	sock_ep->tx_array[index] = tx_ctx;
	atomic_inc(&sock_ep->num_tx_ctx);
	return 0;
}

static int sock_ep_rx_ctx(struct fid_sep *ep, int index, struct fi_rx_attr *attr,
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

	rx_ctx->ctx.ops = &sock_ctx_ep_ops;
	rx_ctx->ctx.msg = &sock_ctx_msg_ops;
	rx_ctx->ctx.tagged = &sock_ctx_tagged;

	/* default config */
	rx_ctx->min_multi_recv = SOCK_EP_MIN_MULTI_RECV;

	*rx_ep = &rx_ctx->ctx;
	sock_ep->rx_array[index] = rx_ctx;
	atomic_inc(&sock_ep->num_rx_ctx);
	return 0;
}

struct fi_ops_ep sock_ep_ops ={
	.size = sizeof(struct fi_ops_ep),
	.enable = sock_ep_enable,
	.cancel = fi_no_cancel,
	.getopt = sock_ep_getopt,
	.setopt = sock_ep_setopt,
	.tx_ctx = sock_ep_tx_ctx,
	.rx_ctx = sock_ep_rx_ctx,
};

static int sock_ep_cm_getname(fid_t fid, void *addr, size_t *addrlen)
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

struct fi_ops_cm sock_ep_cm_ops = {
	.size = sizeof(struct fi_ops_cm),
	.getname = sock_ep_cm_getname,
	.getpeer = fi_no_getpeer,
	.connect = fi_no_connect,
	.listen = fi_no_listen,
	.accept = fi_no_accept,
	.reject = fi_no_reject,
	.shutdown = fi_no_shutdown,
	.join = fi_no_join,
	.leave = fi_no_leave,
};
