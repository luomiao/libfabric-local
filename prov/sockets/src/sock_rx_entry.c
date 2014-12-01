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
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#include "sock.h"
#include "sock_util.h"


struct sock_rx_entry *sock_new_rx_entry(struct sock_rx_ctx *rx_ctx)
{
	/* FIXME: pool of rx_entry */
	struct sock_rx_entry *rx_entry;
	rx_entry = calloc(1, sizeof(struct sock_rx_entry));
	SOCK_LOG_INFO("New rx_entry: %p, ctx: %p\n", rx_entry, rx_ctx);

	dlist_init(&rx_entry->entry);
	return rx_entry;
}

void sock_release_rx_entry(struct sock_rx_entry *rx_entry)
{
	free(rx_entry);
}


struct sock_rx_entry *sock_new_buffered_rx_entry(struct sock_rx_ctx *rx_ctx,
						 size_t len)
{
	struct sock_rx_entry *rx_entry;

	fastlock_acquire(&rx_ctx->lock);

	if (rx_ctx->buffered_len + len >= rx_ctx->attr.total_buffered_recv) {
		SOCK_LOG_ERROR("Reached max buffered recv limit\n");
		rx_entry = NULL;
		goto out;
	}

	/* FIXME: pool of rx_entry */
	rx_entry = calloc(1, sizeof(struct sock_rx_entry) + len);
	SOCK_LOG_INFO("New buffered entry:%p len: %lu, ctx: %p\n", 
		       rx_entry, len, rx_ctx);

	dlist_init(&rx_entry->entry);

	if (rx_entry) {
		rx_entry->is_buffered = 1;
		rx_entry->rx_op.dest_iov_len = 1;
		rx_entry->iov[0].iov.len = len;
		rx_entry->iov[0].iov.addr = (uint64_t)((char*)rx_entry + 
						       sizeof(struct sock_rx_entry));

		rx_ctx->buffered_len += len;
		dlist_insert_tail(&rx_entry->entry, &rx_ctx->rx_buffered_list);
	}

out:
	fastlock_release(&rx_ctx->lock);
	return rx_entry;
}

struct sock_rx_entry *sock_rdm_check_buffered_list(struct sock_rx_ctx *rx_ctx,
						   const struct fi_msg *msg, uint64_t flags)
{
	struct sock_rx_entry *rx_entry;
	struct dlist_entry *entry;

	fastlock_acquire(&rx_ctx->lock);
	for (entry = rx_ctx->rx_buffered_list.next; 
	     entry != &rx_ctx->rx_buffered_list; entry = entry->next) {
		rx_entry = container_of(entry, struct sock_rx_entry, entry);
		if (msg->addr == FI_ADDR_UNSPEC ||
		    rx_entry->addr == msg->addr) {
			dlist_remove(&rx_entry->entry);
			fastlock_release(&rx_ctx->lock);
			return rx_entry;
		}
	}
	fastlock_release(&rx_ctx->lock);
	return NULL;
}

struct sock_rx_entry *sock_rdm_check_buffered_tlist(struct sock_rx_ctx *rx_ctx,
						    const struct fi_msg_tagged *msg, 
						    uint64_t flags)
{
	struct sock_rx_entry *rx_entry;
	struct dlist_entry *entry;

	fastlock_acquire(&rx_ctx->lock);
	for (entry = rx_ctx->rx_buffered_list.next; 
	     entry != &rx_ctx->rx_buffered_list; entry = entry->next) {
		rx_entry = container_of(entry, struct sock_rx_entry, entry);

		if (((rx_entry->tag & ~msg->ignore) == (msg->tag & ~msg->ignore)) &&
		    (msg->addr == FI_ADDR_UNSPEC || rx_entry->addr == msg->addr)) {
			dlist_remove(&rx_entry->entry);
			fastlock_release(&rx_ctx->lock);
			return rx_entry;
		}
	}
	fastlock_release(&rx_ctx->lock);
	return NULL;
}

struct sock_rx_entry *sock_get_rx_entry(struct sock_rx_ctx *rx_ctx, 
					uint64_t addr, uint64_t tag)
{
	struct dlist_entry *entry;
	struct sock_rx_entry *rx_entry;

	fastlock_acquire(&rx_ctx->lock);

	for (entry = rx_ctx->rx_entry_list.next;
	    entry != &rx_ctx->rx_entry_list; entry = entry->next) {

		rx_entry = container_of(entry, struct sock_rx_entry, entry);
		if (((rx_entry->tag & ~rx_entry->ignore) == 
		     (tag & ~rx_entry->ignore)) &&
		    (rx_entry->addr == FI_ADDR_UNSPEC ||
		     rx_entry->addr == addr)) {
			dlist_remove(&rx_entry->entry);
			goto out;
		}
	}

	if (entry == &rx_ctx->rx_entry_list)
		rx_entry = NULL;
	
out:
	fastlock_release(&rx_ctx->lock);
	return rx_entry;
}
