/*
 * Copyright (c) 2014 Intel Corporation. All rights reserved.
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


struct sock_rx_ctx *sock_rx_ctx_alloc(struct fi_rx_ctx_attr *attr, void *context)
{
	struct sock_rx_ctx *rx_ctx;
	rx_ctx = calloc(1, sizeof(*rx_ctx));
	if(!rx_ctx)
		return NULL;

	dlist_init(&rx_ctx->ep_entry);
	dlist_init(&rx_ctx->cq_entry);
	dlist_init(&rx_ctx->pe_entry);

	dlist_init(&rx_ctx->pe_entry_list);
	dlist_init(&rx_ctx->rx_entry_list);
	dlist_init(&rx_ctx->ep_list);

	fastlock_init(&rx_ctx->lock);

	rx_ctx->ctx.fid.fclass = FI_CLASS_RX_CTX;
	rx_ctx->ctx.fid.context = context;
	rx_ctx->attr = *attr;
	return rx_ctx;
}

void sock_rx_ctx_add_ep(struct sock_rx_ctx *rx_ctx, struct sock_ep *ep)
{
	fastlock_acquire(&rx_ctx->lock);
	dlist_insert_tail(&ep->rx_ctx_entry, &rx_ctx->ep_list);
	atomic_inc(&ep->num_rx_ctx); 
	fastlock_release(&rx_ctx->lock);
}

void sock_rx_ctx_free(struct sock_rx_ctx *rx_ctx)
{
	fastlock_destroy(&rx_ctx->lock);
	free(rx_ctx);
}

struct sock_tx_ctx *sock_tx_ctx_alloc(struct fi_tx_ctx_attr *attr, void *context)
{
	struct sock_tx_ctx *tx_ctx;

	tx_ctx = calloc(sizeof(*tx_ctx), 1);
	if (!tx_ctx)
		return NULL;

	if (rbfdinit(&tx_ctx->rbfd, attr->size))
		goto err;

	dlist_init(&tx_ctx->ep_entry);
	dlist_init(&tx_ctx->cq_entry);
	dlist_init(&tx_ctx->pe_entry);

	dlist_init(&tx_ctx->pe_entry_list);
	dlist_init(&tx_ctx->ep_list);

	fastlock_init(&tx_ctx->rlock);
	fastlock_init(&tx_ctx->wlock);

	tx_ctx->ctx.fid.fclass = FI_CLASS_TX_CTX;
	tx_ctx->ctx.fid.context = context;
	tx_ctx->attr = *attr;

	return tx_ctx;
err:
	free(tx_ctx);
	return NULL;
}

void sock_tx_ctx_add_ep(struct sock_tx_ctx *tx_ctx, struct sock_ep *ep)
{
	fastlock_acquire(&tx_ctx->lock);
	dlist_insert_tail(&ep->tx_ctx_entry, &tx_ctx->ep_list);
	atomic_inc(&ep->num_tx_ctx); 
	fastlock_release(&tx_ctx->lock);
}

void sock_tx_ctx_free(struct sock_tx_ctx *tx_ctx)
{
	fastlock_destroy(&tx_ctx->rlock);
	fastlock_destroy(&tx_ctx->wlock);
	rbfdfree(&tx_ctx->rbfd);
	free(tx_ctx);
}

void sock_tx_ctx_start(struct sock_tx_ctx *tx_ctx)
{
	fastlock_acquire(&tx_ctx->wlock);
}

int sock_tx_ctx_write(struct sock_tx_ctx *tx_ctx, const void *buf, size_t len)
{
	if (rbfdavail(&tx_ctx->rbfd) < len)
		return -FI_EAGAIN;

	rbfdwrite(&tx_ctx->rbfd, buf, len);
	return 0;
}

void sock_tx_ctx_commit(struct sock_tx_ctx *tx_ctx)
{
	rbfdcommit(&tx_ctx->rbfd);
	fastlock_release(&tx_ctx->rlock);
}

void sock_tx_ctx_abort(struct sock_tx_ctx *tx_ctx)
{
	rbfdabort(&tx_ctx->rbfd);
	fastlock_release(&tx_ctx->rlock);
}

int sock_tx_ctx_read(struct sock_tx_ctx *tx_ctx, void *buf, size_t len)
{
	int ret;

	fastlock_acquire(&tx_ctx->rlock);
	if (rbfdused(&tx_ctx->rbfd) >= len) {
		rbfdread(&tx_ctx->rbfd, buf, len);
		ret = 0;
	} else {
		ret = -FI_EAGAIN;
	}
	fastlock_release(&tx_ctx->rlock);

	return ret;
}

struct sock_rx_entry *sock_ep_get_rx_entry(struct sock_ep *ep, fi_addr_t addr,
					uint16_t rx_id, uint64_t tag, uint64_t mask)
{
	struct dlist_entry *entry;
	struct sock_rx_ctx *rx_ctx;
	struct sock_rx_entry *rx_entry;

	for(entry = ep->rx_ctx_list.next;
	    entry != &ep->rx_ctx_list; entry = entry->next) {
		rx_ctx = container_of(entry, struct sock_rx_ctx, ep_entry);
		if(rx_ctx->rx_id == rx_id)
			break;
	}

	if(entry == &ep->rx_ctx_list)
		return NULL;
	
	fastlock_acquire(&rx_ctx->lock);

	for(entry = rx_ctx->rx_entry_list.next;
	    entry != &rx_ctx->rx_entry_list; entry = entry->next) {
		rx_entry = container_of(entry, struct sock_rx_entry, entry);
		if(rx_entry->addr == addr && 
		   ((tag & mask) == (rx_entry->tag & rx_entry->mask))) {
			dlist_remove(&rx_entry->entry);
			goto out;
		}
	}

	if(entry == &rx_ctx->rx_entry_list)
		rx_entry = NULL;
	
out:
	fastlock_release(&rx_ctx->lock);
	return rx_entry;
}
