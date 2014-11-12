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
#include <pthread.h>

#include "sock.h"
#include "sock_util.h"


#define PE_INDEX(_pe, _e) ((_e - &_pe->pe_table[0])/sizeof(struct sock_pe_entry))


static int sock_pe_process_rx_send(struct sock_pe *pe, struct sock_rx_ctx *rx_ctx,
				   struct sock_pe_entry *pe_entry)
{
	uint64_t len;
	int i, truncated, ret;
	struct sock_rx_entry *rx_entry;

	rx_entry = sock_ep_get_rx_entry(pe_entry->ep, pe_entry->addr, 
					pe_entry->msg_hdr.rx_id, 0, 0);
	if(!rx_entry) {
		sock_debug(SOCK_ERROR, "PE: No matching recv!\n");
		sock_cq_report_error(rx_ctx->cq, pe_entry, 0,
				     -FI_ENOENT, -FI_ENOENT, NULL);
		ret = -FI_ENOENT;
		goto out;
	}
	
	if(pe_entry->msg_hdr.flags & FI_REMOTE_COMPLETE) {
		sock_debug(SOCK_ERROR, "PE: FI_REMOTE_COMPLETE not implemented\n");
		/* TODO */
	}

	truncated = 0;
	if(pe_entry->msg_hdr.src_iov_len > rx_entry->rx_op.src_iov_len) {
		truncated = pe_entry->msg_hdr.src_iov_len - 
			rx_entry->rx_op.src_iov_len;
	}

	for(i=0; !truncated && i<MIN(pe_entry->msg_hdr.src_iov_len, 
				     rx_entry->rx_op.src_iov_len); i++) {
		
		if(pe_entry->rx.rx_iov[i].iov.len > rx_entry->iov[i].iov.len) {
			truncated = pe_entry->rx.rx_iov[i].iov.len - 
				rx_entry->iov[i].iov.len;
		}

		len = MIN(pe_entry->rx.rx_iov[i].iov.len, rx_entry->iov[i].iov.len);
		memcpy((void *)pe_entry->rx.rx_iov[i].iov.addr, 
		       (void *)rx_entry->iov[i].iov.addr, len);
	}

	/* report error, if any */
	if(truncated) {
		ret = sock_cq_report_error(rx_ctx->cq, pe_entry, truncated,
					   -FI_ENOSPC, -FI_ENOSPC, NULL);
		if(ret) goto out;
	}
	
	/* post completion */
	if(rx_ctx->cq) {
		if(rx_ctx->cq_event_flag) {
			if(pe_entry->msg_hdr.flags & FI_EVENT) {
				ret = rx_ctx->cq->report_completion(
					rx_ctx->cq, pe_entry->msg_hdr.src_addr,
					pe_entry);
			}
		}else{
			ret = rx_ctx->cq->report_completion(
				rx_ctx->cq, pe_entry->msg_hdr.src_addr, pe_entry);
		}
	}

out:
	free(rx_entry);
	return ret;
}

static int sock_pe_process_recv(struct sock_pe *pe, struct sock_rx_ctx *rx_ctx,
				struct sock_pe_entry *pe_entry)
{
	int ret;
	struct sock_msg_hdr *msg_hdr;

	msg_hdr = &pe_entry->msg_hdr;
	msg_hdr->version = ntohs(msg_hdr->version);
	if(msg_hdr->version != SOCK_WIRE_PROTO_VERSION) {
		sock_debug(SOCK_ERROR, "PE: Invalid wire protocol\n");
		ret = -FI_EINVAL;
		goto out;
	}
		
	msg_hdr->op_type = ntohs(msg_hdr->op_type);
	msg_hdr->src_iov_len = ntohs(msg_hdr->src_iov_len);
	msg_hdr->rx_id = ntohs(msg_hdr->rx_id);
	msg_hdr->flags = ntohs(msg_hdr->flags);
	msg_hdr->msg_len = ntohl(msg_hdr->msg_len);

	/* process rx entry */
	switch(pe_entry->msg_hdr.op_type) {

	case SOCK_OP_SEND:
		ret = sock_pe_process_rx_send(pe, rx_ctx, pe_entry);
		break;

	case SOCK_OP_WRITE:
	case SOCK_OP_READ:
	case SOCK_OP_TSEND:
	case SOCK_OP_ATOMIC:
	default:
		ret = -FI_ENOSYS;
		sock_debug(SOCK_ERROR, "PE: Operation not supported\n");
		break;
	}

out:
	free(pe_entry->rx.raw_data);
	return ret;
}

static int sock_pe_progress_rx_entry(struct sock_pe *pe,
				      struct sock_pe_entry *pe_entry)
{
	int ret; 
	struct sock_conn *conn;

	ret = sock_av_lookup_addr(pe_entry->ep->av, pe_entry->addr, &conn);
	if(ret != 0) {
		sock_debug(SOCK_ERROR, "PE: Failed to lookup addr\n");
		return ret;
	}

	if(conn->pe_entry != NULL && conn->pe_entry != pe_entry)
		return 0;

	if(conn->pe_entry == NULL) {
		conn->pe_entry = pe_entry;
	}

	sock_debug(SOCK_INFO, "PE: [%d] Progressing RX pe_entry\n", 
		   PE_INDEX(pe, pe_entry));
	
	if(pe_entry->done_len < sizeof(struct sock_msg_hdr)) {
		ret = recv(conn->sock_fd, 
			   (char*)&pe_entry->msg_hdr + pe_entry->done_len, 
			   sizeof(struct sock_msg_hdr) - pe_entry->done_len, 0);
		if(ret < 0) {
			if(ret == EWOULDBLOCK || ret == EAGAIN)
				return 0;
		}else{
			sock_debug(SOCK_ERROR, "PE: Failed to progress recv\n");
			return ret;
		}
		
		pe_entry->done_len += ret;
		if(pe_entry->done_len == sizeof(struct sock_msg_hdr)) {
			pe_entry->msg_hdr.msg_len = 
				ntohl(pe_entry->msg_hdr.msg_len);
			
			pe_entry->rx.raw_data = 
				malloc(pe_entry->msg_hdr.msg_len - 
				       sizeof(struct sock_msg_hdr));
			if(!pe_entry->rx.raw_data) {
				sock_debug(SOCK_ERROR, "PE: Not enough memory\n");
				return -FI_ENOMEM;
			}
		}else {
			return 0;
		}
	}

	ret = recv(conn->sock_fd, 
		   (char*)&pe_entry->rx.raw_data + 
		   pe_entry->done_len - sizeof(struct sock_msg_hdr), 
		   pe_entry->msg_hdr.msg_len - pe_entry->done_len, 0);

	if(ret < 0) {
		if(ret == EWOULDBLOCK || ret == EAGAIN)
			return 0;
	}else{
		sock_debug(SOCK_ERROR, "PE: Failed to progress recv\n");
		return ret;
	}

	pe_entry->done_len += ret;
	if(pe_entry->done_len == pe_entry->msg_hdr.msg_len)
		pe_entry->is_complete = 1;
	return 0;
}

static int sock_pe_progress_tx_send(struct sock_pe *pe, 
				    struct sock_pe_entry *pe_entry, 
				    struct sock_conn *conn)
{
	int ret;
	ssize_t len, i, done_data, rem, offset, curr_offset;
	struct sock_msg_hdr *msg_hdr = &pe_entry->msg_hdr;

	/* src iov(s) */
	len = sizeof(struct sock_msg_hdr) + 
		(msg_hdr->src_iov_len * sizeof(union sock_iov));
	if(pe_entry->done_len < len) {
		rem = len - pe_entry->done_len;
		offset = pe_entry->done_len - sizeof(struct sock_msg_hdr);
		
		ret = send(conn->sock_fd, 
			   (char*)&pe_entry->tx.tx_iov + offset, rem, 0);
		
		if(ret < 0) {
			if(ret == EWOULDBLOCK || ret == EAGAIN)
				return 0;
		}else{
			sock_debug(SOCK_ERROR, "PE: Failed to send\n");
			return ret;
		}
		
		pe_entry->done_len += ret;
		if(ret < rem) {
			return 0;
		}
	}

	/* msg buf */
	for(i=0; i<msg_hdr->src_iov_len; i++) {
		len += pe_entry->tx.tx_iov[i].src.iov.len;
	}
	if(pe_entry->done_len < len) {
		done_data = pe_entry->done_len -
			(sizeof(struct sock_msg_hdr)+
			 msg_hdr->src_iov_len * sizeof(union sock_iov));
		offset = 0;

		for(i = 0; i<msg_hdr->src_iov_len; i++) {
			if(done_data > pe_entry->tx.tx_iov[i].src.iov.len + offset) {
				offset += pe_entry->tx.tx_iov[i].src.iov.len;
				continue;
			}

			curr_offset = done_data - offset;
			ret = send(conn->sock_fd, 
				   (char*)pe_entry->tx.tx_iov[i].src.iov.addr + curr_offset, 
				   pe_entry->tx.tx_iov[i].src.iov.len - curr_offset, 0);

			if(ret < 0) {
				if(ret == EWOULDBLOCK || ret == EAGAIN)
					return 0;
			}else{
				sock_debug(SOCK_ERROR, "PE: Failed to send\n");
				return ret;
			}
			
			pe_entry->done_len += ret;
			offset += ret;
		}
	}

	/* user data */
	len = len + sizeof(uint64_t);
	if(msg_hdr->msg_len == len) {
		rem = msg_hdr->msg_len - pe_entry->done_len;
		ret = send(conn->sock_fd, 
			   (char*)&pe_entry->data + sizeof(uint64_t) - rem, rem, 0);
		if(ret < 0) {
			if(ret == EWOULDBLOCK || ret == EAGAIN)
				return 0;
		}else{
			sock_debug(SOCK_ERROR, "PE: Failed to send\n");
			return ret;
		}
		
		pe_entry->done_len += ret;
	}
	return 0;
}

static int sock_pe_progress_tx_entry(struct sock_pe *pe,
				      struct sock_pe_entry *pe_entry)
{
	int ret; 
	struct sock_conn *conn;

	/* FIXME - conn ID should be embedded in TX entry */
	ret = sock_av_lookup_addr(pe_entry->ep->av, pe_entry->addr, &conn);
	if(ret != 0) {
		sock_debug(SOCK_ERROR, "PE: Failed to lookup address\n");
		return ret;
	}
	
	if(conn->pe_entry != NULL && conn->pe_entry != pe_entry)
		return 0;

	if(conn->pe_entry == NULL) {
		conn->pe_entry = pe_entry;
	}

	sock_debug(SOCK_INFO, "PE: [%d] Progressing TX entry\n", 
		   PE_INDEX(pe, pe_entry));

	if(!pe_entry->tx.header_sent) {
		ret = send(conn->sock_fd, 
			   (char*)&pe_entry->msg_hdr + pe_entry->done_len,
			   sizeof(struct sock_msg_hdr) - pe_entry->done_len, 0);
		if(ret < 0) {
			if(ret == EWOULDBLOCK || ret == EAGAIN)
				return 0;
		}else {
			sock_debug(SOCK_ERROR, "PE: Failed to send\n");
			return ret;
		}

		pe_entry->done_len += ret;
		if(pe_entry->done_len == sizeof(struct sock_msg_hdr)) {
			pe_entry->tx.header_sent = 1;
			sock_debug(SOCK_INFO, "PE: [%d] Header sent\n", 
				   PE_INDEX(pe, pe_entry));
		}else {
			return 0;
		}
	}

	switch(pe_entry->msg_hdr.op_type) {

	case SOCK_OP_SEND:
		ret = sock_pe_progress_tx_send(pe, pe_entry, conn);
		break;
		
	case SOCK_OP_WRITE:
	case SOCK_OP_READ:
	case SOCK_OP_TSEND:
	case SOCK_OP_ATOMIC:
	case SOCK_OP_SEND_INJECT:
	default:
		ret = -FI_ENOSYS;
		sock_debug(SOCK_ERROR, "PE: Operation not supported\n");
		break;
	}

	return ret;
}

static void sock_pe_release_entry(struct sock_pe *pe, 
			struct sock_pe_entry *pe_entry)
{
	dlist_remove(&pe_entry->entry);
	dlist_insert_tail(&pe_entry->entry, &pe->free_list);
}

static struct sock_pe_entry *sock_pe_acquire_entry(struct sock_pe *pe)
{
	struct dlist_entry *entry;
	struct sock_pe_entry *pe_entry;

	entry = pe->free_list.next;
	pe_entry = container_of(entry, struct sock_pe_entry, entry);
	dlist_remove(&pe_entry->entry);
	dlist_insert_tail(&pe_entry->entry, &pe->busy_list);
	return pe_entry;
}

static int sock_pe_new_rx_entry(struct sock_pe *pe, struct sock_rx_ctx *rx_ctx,
				struct sock_ep *ep)
{
	struct sock_pe_entry *pe_entry;	
	pe_entry = sock_pe_acquire_entry(pe);
	if(!pe_entry) {
		sock_debug(SOCK_ERROR, "Error in getting PE entry \n");
		return -FI_EINVAL;
	}

	pe_entry->type = SOCK_PE_RX;
	pe_entry->ep = ep;
	pe_entry->is_complete = 0;
	pe_entry->done_len = 0;

	/* link to tracking list in rx_ctx */
	dlist_init(&pe_entry->ctx_entry);
	dlist_insert_tail(&pe_entry->ctx_entry, &rx_ctx->pe_entry_list);
	return 0;
}

static int sock_pe_new_tx_entry(struct sock_pe *pe, struct sock_tx_ctx *tx_ctx)
{
	int i;
	struct sock_msg_hdr *msg_hdr;
	struct sock_pe_entry *pe_entry;

	pe_entry = sock_pe_acquire_entry(pe);
	if(!pe_entry) {
		sock_debug(SOCK_ERROR, "PE: Failed to get free PE entry \n");
		return -FI_EINVAL;
	}

	pe_entry->type = SOCK_PE_TX;
	pe_entry->is_complete = 0;
	pe_entry->done_len = 0;

	dlist_insert_tail(&pe_entry->ctx_entry, &tx_ctx->pe_entry_list);

	/* fill in PE tx entry */
	memset(&pe_entry->msg_hdr, 0, sizeof(struct sock_msg_hdr));
	msg_hdr = &pe_entry->msg_hdr;
	msg_hdr->msg_len = sizeof(struct sock_msg_hdr);

	rbfdread(&tx_ctx->rbfd, &pe_entry->tx.tx_op, sizeof(struct sock_op));
	rbfdread(&tx_ctx->rbfd, &pe_entry->flags, sizeof(uint64_t));
	rbfdread(&tx_ctx->rbfd, &pe_entry->context, sizeof(uint64_t));
	rbfdread(&tx_ctx->rbfd, &pe_entry->addr, sizeof(uint64_t));

	if(pe_entry->flags & FI_REMOTE_CQ_DATA) {
		rbfdread(&tx_ctx->rbfd, &pe_entry->data, sizeof(uint64_t));
	}

	if(pe_entry->tx.tx_op.op == SOCK_OP_TSEND) {
		rbfdread(&tx_ctx->rbfd, &pe_entry->tag, sizeof(uint64_t));
	}

	if(pe_entry->tx.tx_op.op == SOCK_OP_SEND_INJECT) {
		rbfdread(&tx_ctx->rbfd, &pe_entry->tx.inject_data[0],
			 pe_entry->tx.tx_op.src_iov_len);
		msg_hdr->msg_len += pe_entry->tx.tx_op.src_iov_len;
	}else {
		msg_hdr->msg_len += (pe_entry->tx.tx_op.src_iov_len + 
			    pe_entry->tx.tx_op.dest_iov_len) *
			sizeof(union sock_iov);

		/* copy src iov(s)*/
		for(i = 0; i<pe_entry->tx.tx_op.src_iov_len; i++) {
			rbfdread(&tx_ctx->rbfd, &pe_entry->tx.tx_iov[i].src, 
				 sizeof(union sock_iov));
			msg_hdr->msg_len += pe_entry->tx.tx_iov[i].src.iov.len;
		}

		/* copy dst iov(s)*/
		for(i = 0; i<pe_entry->tx.tx_op.dest_iov_len; i++) {
			rbfdread(&tx_ctx->rbfd, &pe_entry->tx.tx_iov[i].dst, 
			       sizeof(union sock_iov));
			msg_hdr->msg_len += pe_entry->tx.tx_iov[i].dst.iov.len;
		}
	}

	/* prepare message header */
	msg_hdr->version = htons(SOCK_WIRE_PROTO_VERSION);
	msg_hdr->op_type = htons(pe_entry->tx.tx_op.op);
	msg_hdr->src_iov_len = htons(pe_entry->tx.tx_op.src_iov_len);

	/* FIXME: rx_ctx bits- why */
	msg_hdr->rx_id = htons(SOCK_GET_RX_ID(pe_entry->addr, 
				pe_entry->ep->av->rx_ctx_bits));
	msg_hdr->flags = htonl(pe_entry->flags);
	msg_hdr->msg_len = htonl(msg_hdr->msg_len);
	return 0;
}

int sock_pe_add_tx_ctx(struct sock_pe *pe, struct sock_tx_ctx *ctx)
{
	fastlock_acquire(&pe->lock);
	dlistfd_insert_tail(&ctx->pe_entry, &pe->tx_list);
	fastlock_release(&pe->lock);
	sock_debug(SOCK_INFO, "PE: TX ctx added to PE\n");
	return 0;
}

int sock_pe_add_rx_ctx(struct sock_pe *pe, struct sock_rx_ctx *ctx)
{
	fastlock_acquire(&pe->lock);
	dlistfd_insert_tail(&ctx->pe_entry, &pe->rx_list);
	fastlock_release(&pe->lock);
	sock_debug(SOCK_INFO, "PE: RX ctx added to PE\n");
	return 0;
}

int sock_pe_progress_rx_ctx(struct sock_pe *pe, struct sock_rx_ctx *rx_ctx)
{
	int i, ret = 0;
	struct sock_ep *ep;
	struct pollfd poll_fd;
	struct sock_conn *conn;
	struct dlist_entry *entry;
	struct sock_pe_entry *pe_entry;

	poll_fd.events = POLLIN;
	fastlock_acquire(&pe->lock);

	/* check for incoming data */
	for(entry = rx_ctx->ep_list.next;
	    entry != &rx_ctx->ep_list; entry = entry->next) {

		ep = container_of(entry, struct sock_ep, rx_ctx_entry);
		if(!ep->av)
			continue;

		for (i=0; i < ep->av->count && 
			     !dlist_empty(&pe->free_list); i++) {
			sock_conn_map_lookup_key(ep->av->cmap, 
						 ep->av->key_table[i], &conn);
			poll_fd.fd = conn->sock_fd;
			ret = poll(&poll_fd, 1, 0);
			if(ret<0) goto out;
			if(ret == 1) {
				/* new RX PE entry */
				ret = sock_pe_new_rx_entry(pe, rx_ctx, ep);
				if(ret) goto out;
			}
		}
	}

	/* progress tx_ctx in PE table */
	for(entry = rx_ctx->pe_entry_list.next;
	    entry != &rx_ctx->pe_entry_list; entry = entry->next) {
		
		pe_entry = container_of(entry, struct sock_pe_entry, ctx_entry);
		ret = sock_pe_progress_rx_entry(pe, pe_entry);
		if(ret < 0) goto out;

		if(pe_entry->is_complete) {
			ret = sock_pe_process_recv(pe, rx_ctx, pe_entry);
			if(ret < 0) goto out;
			sock_pe_release_entry(pe, pe_entry);
			sock_debug(SOCK_INFO, "PE: [%d] RX done\n", 
				   PE_INDEX(pe, pe_entry));
		}
	}
		
out:	
	if(ret) 
		sock_debug(SOCK_ERROR, "PE: failed to progress RX ctx\n");
	fastlock_release(&pe->lock);
	return ret;
}

int sock_pe_progress_tx_ctx(struct sock_pe *pe, struct sock_tx_ctx *tx_ctx)
{
	int ret = 0;
	struct dlist_entry *entry;
	struct sock_pe_entry *pe_entry;

	fastlock_acquire(&pe->lock);

	/* check tx_ctx rbuf */
	fastlock_acquire(&tx_ctx->rlock);
	while(!rbfdempty(&tx_ctx->rbfd) && 
	      !dlist_empty(&pe->free_list)) {
		/* new TX PE entry */
		ret = sock_pe_new_tx_entry(pe, tx_ctx);
		if(ret) {
			fastlock_release(&tx_ctx->rlock);
			goto out;
		}
	}
	fastlock_release(&tx_ctx->rlock);

	/* progress tx_ctx in PE table */
	for(entry = tx_ctx->pe_entry_list.next;
	    entry != &tx_ctx->pe_entry_list; entry = entry->next) {
		
		pe_entry = container_of(entry, struct sock_pe_entry, ctx_entry);
		ret = sock_pe_progress_tx_entry(pe, pe_entry);
		if(ret < 0) goto out;
			
		if(!pe_entry->is_complete)
			continue;

		if(tx_ctx->cq) {
			if(tx_ctx->cq_event_flag) {
				if(pe_entry->msg_hdr.flags & FI_EVENT) {
					ret = tx_ctx->cq->report_completion(
						tx_ctx->cq, pe_entry->addr, pe_entry);
					if(ret) goto out;
				}
			}else {
				ret = tx_ctx->cq->report_completion(
					tx_ctx->cq, pe_entry->addr, pe_entry);
			}
		}
		
		sock_pe_release_entry(pe, pe_entry);
		sock_debug(SOCK_INFO, "PE: [%d] TX done\n", 
			   PE_INDEX(pe, pe_entry));
	}
		
out:	
	if(ret) 
		sock_debug(SOCK_ERROR, "PE: failed to progress TX ctx\n");
	fastlock_release(&pe->lock);
	return ret;
}

static void *sock_pe_progress_thread(void *data)
{
	int ret;
	struct pollfd fds[2];
	struct dlist_entry *entry;
	struct sock_tx_ctx *tx_ctx;
	struct sock_rx_ctx *rx_ctx;
	struct sock_pe *pe = (struct sock_pe *)data;

	sock_debug(SOCK_INFO, "PE: Progress thread started\n");

	fds[0].events = POLLIN;
	fds[0].fd = pe->tx_list.fd[LIST_READ_FD];

	fds[1].events = POLLIN;	
	fds[1].fd = pe->rx_list.fd[LIST_READ_FD];
	
	while(pe->do_progress) {

		if(dlistfd_empty(&pe->tx_list) &&
		   dlistfd_empty(&pe->rx_list)) {
			ret = poll(fds, 2, SOCK_PE_POLL_TIMEOUT);
			if(ret == 0)
				continue;
		}

		/* progress tx */
		if(!dlistfd_empty(&pe->tx_list)) {
			for(entry = pe->tx_list.list.next;
			    entry != &pe->tx_list.list; entry = entry->next) {
				tx_ctx = container_of(entry, struct sock_tx_ctx, pe_entry);
				ret = sock_pe_progress_tx_ctx(pe, tx_ctx);
				if(ret) {
					sock_debug(SOCK_ERROR, "PE: failed to progress TX\n");
					return NULL;
				}
			}
		}

		/* progress rx */
		if(!dlistfd_empty(&pe->rx_list)) {
			for(entry = pe->rx_list.list.next;
			    entry != &pe->rx_list.list; entry = entry->next) {
				rx_ctx = container_of(entry, struct sock_rx_ctx, pe_entry);
				ret = sock_pe_progress_rx_ctx(pe, rx_ctx);
				if(ret) {
					sock_debug(SOCK_ERROR, "PE: failed to progress RX\n");
					return NULL;
				}
			}
		}
	}
	
	sock_debug(SOCK_INFO, "PE: Progress thread terminated\n");
	return NULL;
}

static void sock_pe_init_table(
	struct sock_pe *pe)
{
	int i;
	
	memset(&pe->pe_table, 0, 
	       sizeof(struct sock_pe_entry) * SOCK_PE_MAX_ENTRIES);

	dlist_init(&pe->free_list);
	dlist_init(&pe->busy_list);

	for(i=0; i<SOCK_PE_MAX_ENTRIES; i++) {
		dlist_insert_tail(&pe->pe_table[i].entry, &pe->free_list);
	}

	sock_debug(SOCK_INFO, "PE table init: OK\n");
}

struct sock_pe *sock_pe_init(struct sock_domain *domain)
{
	struct sock_pe *pe = calloc(1, sizeof(struct sock_pe));
	if(!pe)
		return NULL;

	sock_pe_init_table(pe);

	dlistfd_head_init(&pe->tx_list);
	dlistfd_head_init(&pe->rx_list);
	fastlock_init(&pe->lock);

	pe->do_progress = 1;
	if(pthread_create(&pe->progress_thread, NULL, sock_pe_progress_thread,
			  (void *)pe)) {
		sock_debug(SOCK_ERROR, "PE: Couldn't create progress thread\n");
		goto err;
	}
	sock_debug(SOCK_INFO, "PE init: OK\n");
	return pe;

err:
	dlistfd_head_free(&pe->tx_list);
	dlistfd_head_free(&pe->rx_list);

	free(pe);
	return NULL;
}

void sock_pe_finalize(struct sock_pe *pe)
{
	pe->do_progress = 0;
	pthread_join(pe->progress_thread, NULL);
	
	fastlock_destroy(&pe->lock);
	atomic_dec(&pe->domain->ref);

	dlistfd_head_free(&pe->tx_list);
	dlistfd_head_free(&pe->rx_list);

	free(pe);
	sock_debug(SOCK_INFO, "PE: Progress engine finalize: OK\n");
}

