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

#define IGNORE_TAG (1)
#define MATCH_TAG (0)

int sock_pe_process_rx_send(struct sock_pe *pe, struct sock_pe_entry *pe_entry)
{
	uint64_t len;
	int i, truncated, ret;
	struct sock_rx_entry *rx_entry;

	rx_entry = sock_cq_get_rx_entry(pe_entry->cq, pe_entry->addr, 
					pe_entry->msg_hdr.rx_id, 0, 0);
	if(!rx_entry){
		sock_debug(SOCK_ERROR, "PE: No matching recv!\n");
		sock_cq_report_error(pe_entry->cq, pe_entry, 0,
				     -FI_ENOENT, -FI_ENOENT, NULL);
		return -FI_ENOENT;
	}

	if(pe_entry->msg_hdr.flags & FI_REMOTE_COMPLETE){
		sock_debug(SOCK_ERROR, "PE: FI_REMOTE_COMPLETE not implemented\n");
		/* TODO: send ack to sender */
	}

	truncated = 0;
	if(pe_entry->msg_hdr.src_iov_len > rx_entry->rx_op.src_iov_len){
		truncated = pe_entry->msg_hdr.src_iov_len - 
			rx_entry->rx_op.src_iov_len;
	}

	for(i=0; !truncated && i<MIN(pe_entry->msg_hdr.src_iov_len, 
				     rx_entry->rx_op.src_iov_len); i++){
		
		if(pe_entry->rx.rx_iov[i].iov.len > rx_entry->iov[i].iov.len){
			truncated = pe_entry->rx.rx_iov[i].iov.len - 
				rx_entry->iov[i].iov.len;
		}

		len = MIN(pe_entry->rx.rx_iov[i].iov.len, rx_entry->iov[i].iov.len);
		memcpy((void *)pe_entry->rx.rx_iov[i].iov.addr, 
		       (void *)rx_entry->iov[i].iov.addr, len);
	}

	/* report error, if any */
	if(truncated){
		ret = sock_cq_report_error(pe_entry->cq, pe_entry, truncated,
					   -FI_ENOSPC, -FI_ENOSPC, NULL);
		if(ret) goto out;
	}
	
	/* post completion */
	if(pe_entry->ep->recv_cq_event_flag){
		if(pe_entry->msg_hdr.flags & FI_EVENT){
			ret = pe_entry->cq->report_completion(
				pe_entry->cq, FI_ADDR_UNSPEC, pe_entry);
		}
	}else{
		ret = pe_entry->cq->report_completion(
			pe_entry->cq, FI_ADDR_UNSPEC, pe_entry);
	}

out:
	free(rx_entry);
	return ret;
}

int sock_pe_process_recv(struct sock_pe *pe, struct sock_pe_entry *pe_entry)
{
	int ret;
	struct sock_msg_hdr *msg_hdr;

	msg_hdr = &pe_entry->msg_hdr;
	msg_hdr->version = ntohs(msg_hdr->version);
	if(msg_hdr->version != SOCK_WIRE_PROTO_VERSION){
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
	switch(pe_entry->msg_hdr.op_type){

	case SOCK_OP_SEND:
		ret = sock_pe_process_rx_send(pe, pe_entry);
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

#define PE_INDEX(_pe, _e) ((_e - &_pe->pe_table[0])/sizeof(struct sock_pe_entry))

inline int sock_pe_progress_rx_entry(struct sock_pe *pe,
				      struct sock_pe_entry *pe_entry)
{
	int ret; 
	struct sock_conn *conn;

	ret = sock_av_lookup_addr(pe_entry->ep->av, pe_entry->addr, &conn);
	if(ret != 0){
		sock_debug(SOCK_ERROR, "PE: Failed to lookup addr\n");
		return ret;
	}

	if(conn->pe_entry != NULL && conn->pe_entry != pe_entry)
		return 0;

	if(conn->pe_entry == NULL){
		conn->pe_entry = pe_entry;
	}

	sock_debug(SOCK_INFO, "PE: [%d] Progressing RX pe_entry\n", 
		   PE_INDEX(pe, pe_entry));
	
	if(pe_entry->done_len < sizeof(struct sock_msg_hdr)){
		ret = recv(conn->sock_fd, 
			   (char*)&pe_entry->msg_hdr + pe_entry->done_len, 
			   sizeof(struct sock_msg_hdr) - pe_entry->done_len, 0);
		if(ret < 0){
			if(ret == EWOULDBLOCK || ret == EAGAIN)
				return 0;
		}else{
			sock_debug(SOCK_ERROR, "PE: Failed to progress recv\n");
			return ret;
		}
		
		pe_entry->done_len += ret;
		if(pe_entry->done_len == sizeof(struct sock_msg_hdr)){
			pe_entry->msg_hdr.msg_len = 
				ntohl(pe_entry->msg_hdr.msg_len);
			
			pe_entry->rx.raw_data = 
				malloc(pe_entry->msg_hdr.msg_len);
			if(!pe_entry->rx.raw_data){
				sock_debug(SOCK_ERROR, "PE: Not enough memory (%lu)\n",
					   pe_entry->msg_hdr.msg_len);
				return -FI_ENOMEM;
			}
		}
	}

	ret = recv(conn->sock_fd, 
		   (char*)&pe_entry->rx.raw_data + 
		   pe_entry->done_len - sizeof(struct sock_msg_hdr), 
		   pe_entry->msg_hdr.msg_len - pe_entry->done_len, 0);

	if(ret < 0){
		if(ret == EWOULDBLOCK || ret == EAGAIN)
			return 0;
	}else{
		sock_debug(SOCK_ERROR, "PE: Failed to progress recv\n");
		return ret;
	}

	pe_entry->done_len += ret;
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
	if(pe_entry->done_len < len){
		
		rem = len - pe_entry->done_len;
		offset = pe_entry->done_len - sizeof(struct sock_msg_hdr);
		
		ret = send(conn->sock_fd, 
			   (char*)&pe_entry->tx.src_iov + offset, rem, 0);
		
		if(ret < 0){
			if(ret == EWOULDBLOCK || ret == EAGAIN)
				return 0;
		}else{
			sock_debug(SOCK_ERROR, "PE: Failed to send\n");
			return ret;
		}
		
		pe_entry->done_len += ret;
		if(ret < rem){
			return 0;
		}
	}

	/* msg buf */
	for(i=0; i<msg_hdr->src_iov_len; i++){
		len += pe_entry->tx.src_iov[i].iov.len;
	}
	if(pe_entry->done_len < len){

		done_data = pe_entry->done_len -
			(sizeof(struct sock_msg_hdr)+
			 msg_hdr->src_iov_len * sizeof(union sock_iov));
		offset = 0;

		for(i = 0; i<msg_hdr->src_iov_len; i++){
			if(done_data > pe_entry->tx.src_iov[i].iov.len + offset){
				offset += pe_entry->tx.src_iov[i].iov.len;
				continue;
			}

			curr_offset = done_data - offset;
			ret = send(conn->sock_fd, 
				   (char*)pe_entry->tx.src_iov[i].iov.addr + curr_offset, 
				   pe_entry->tx.src_iov[i].iov.len - curr_offset, 0);

			if(ret < 0){
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
	if(msg_hdr->msg_len == len){
		rem = msg_hdr->msg_len - pe_entry->done_len;
		ret = send(conn->sock_fd, 
			   (char*)&pe_entry->data + sizeof(uint64_t) - rem, rem, 0);
		if(ret < 0){
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

inline int sock_pe_progress_tx_entry(struct sock_pe *pe,
				      struct sock_pe_entry *pe_entry)
{
	int ret; 
	struct sock_conn *conn;

	ret = sock_av_lookup_addr(pe_entry->ep->av, pe_entry->addr, &conn);
	if(ret != 0){
		sock_debug(SOCK_ERROR, "PE: Failed to lookup address\n");
		return ret;
	}
	
	if(conn->pe_entry != NULL && conn->pe_entry != pe_entry)
		return 0;

	if(conn->pe_entry == NULL){
		conn->pe_entry = pe_entry;
	}

	sock_debug(SOCK_INFO, "PE: [%d] Progressing TX entry\n", 
		   PE_INDEX(pe, pe_entry));

	if(!pe_entry->tx.header_sent){
		ret = send(conn->sock_fd, 
			   (char*)&pe_entry->msg_hdr + pe_entry->done_len,
			   sizeof(struct sock_msg_hdr) - pe_entry->done_len, 0);
		if(ret < 0){
			if(ret == EWOULDBLOCK || ret == EAGAIN)
				return 0;
		}else{
			sock_debug(SOCK_ERROR, "PE: Failed to send\n");
			return ret;
		}

		pe_entry->done_len += ret;
		if(pe_entry->done_len == sizeof(struct sock_msg_hdr)){
			pe_entry->tx.header_sent = 1;
			sock_debug(SOCK_INFO, "PE: [%d] Header sent\n", 
				   PE_INDEX(pe, pe_entry));
		}else{
			return 0;
		}
	}

	switch(pe_entry->msg_hdr.op_type){

	case SOCK_OP_SEND:
		ret = sock_pe_progress_tx_send(pe, pe_entry, conn);
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

	return ret;
}

void sock_pe_release_entry(struct sock_pe *pe, 
			struct sock_pe_entry *entry)
{
	dlist_remove(&entry->list);
	dlist_insert_tail(&entry->list, &pe->free_list_head.list);
}

struct sock_pe_entry *sock_pe_acquire_entry(struct sock_pe *pe)
{
	struct dlist_entry *list_entry;
	struct sock_pe_entry *pe_entry;

	list_entry = pe->free_list_head.list.next;
	pe_entry = container_of(list_entry, struct sock_pe_entry, list);
	dlist_remove(list_entry);
	dlist_insert_tail(&pe_entry->list, &pe->busy_list_head.list);
	return pe_entry;
}

static int sock_pe_progress_table(struct sock_pe *pe,
				  struct sock_cq *cq)
{
	int ret;
	struct dlist_entry *head, *curr, *next;
	struct sock_pe_entry *pe_entry;
	
	head = &cq->pe_entry_head.list;
	curr = head->next;
	
	while(curr != head){
		next = curr->next;
		pe_entry = container_of(curr, struct sock_pe_entry, list);
		
		if(pe_entry->type == SOCK_RX){
			ret = sock_pe_progress_rx_entry(pe, pe_entry);
			if(ret < 0)
				return ret;

			if(pe_entry->msg_hdr.msg_len == pe_entry->done_len){
				sock_debug(SOCK_INFO, "PE: [%d] RX done\n", 
					   PE_INDEX(pe, pe_entry));
				ret = sock_pe_process_recv(pe, pe_entry);
				if(ret < 0)
					return ret;
				sock_pe_release_entry(pe, pe_entry);
			}
		}else{
			ret = sock_pe_progress_tx_entry(pe, pe_entry);
			if(ret < 0)
				return ret;
			
			if(pe_entry->msg_hdr.msg_len == pe_entry->done_len){
				sock_debug(SOCK_INFO, "PE: [%d] TX done\n", 
					   PE_INDEX(pe, pe_entry));
				ret = pe_entry->cq->report_completion(
					pe_entry->cq, FI_ADDR_UNSPEC, pe_entry);
				if(ret < 0)
					return ret;
				sock_pe_release_entry(pe, pe_entry);
			}
		}
		curr = next;
	}
	return 0;
}

static int sock_pe_new_rx_entry(struct sock_pe *pe, struct sock_cq *cq,
				struct sock_ep *ep)
{
	struct sock_pe_entry *pe_entry;	
	pe_entry = sock_pe_acquire_entry(pe);
	if(!pe_entry){
		sock_debug(SOCK_ERROR, "Error in getting PE entry \n");
		return -FI_EINVAL;
	}

	pe_entry->type = SOCK_RX;
	pe_entry->done_len = 0;

	pe_entry->ep = ep;
	pe_entry->cq = cq;

	/* link to tracking list in CQ */
	dlist_init(&pe_entry->list);
	dlist_insert_tail(&pe_entry->list, &cq->pe_entry_head.list);

	return 0;
}

static int sock_pe_new_tx_entry(struct sock_pe *pe, struct sock_cq *cq, 
				struct sock_tx_ctx *tx_ctx)
{
	int i, is_inject;
	uint64_t msg_len, payload_len;
	struct sock_msg_hdr *msg_hdr;
	struct sock_pe_entry *pe_entry;

	is_inject = 0;
	payload_len = 0;
	
	pe_entry = sock_pe_acquire_entry(pe);
	if(!pe_entry){
		sock_debug(SOCK_ERROR, "Error in acquiring free PE entry \n");
		return -FI_EINVAL;
	}

	pe_entry->type = SOCK_TX;
	pe_entry->done_len = 0;

	pe_entry->ep = tx_ctx->ep;
	pe_entry->cq = cq;

	/* link to tracking list in CQ */
	dlist_init(&pe_entry->list);
	dlist_insert_tail(&pe_entry->list, &cq->pe_entry_head.list);

	/* fill in PE tx entry */
	memset(&pe_entry->msg_hdr, 0, sizeof(struct sock_msg_hdr));
	rbfdread(&tx_ctx->rbfd, &pe_entry->tx.tx_op, 
		 sizeof(struct sock_tx_op));

	rbfdread(&tx_ctx->rbfd, &pe_entry->flags, sizeof(uint64_t));
	rbfdread(&tx_ctx->rbfd, &pe_entry->context, sizeof(uint64_t));
	rbfdread(&tx_ctx->rbfd, &pe_entry->addr, sizeof(uint64_t));

	if(pe_entry->flags & FI_REMOTE_CQ_DATA){
		rbfdread(&tx_ctx->rbfd, &pe_entry->data, sizeof(uint64_t));
	}

	if(pe_entry->flags & FI_INJECT){
		is_inject = 1;
		payload_len = pe_entry->tx.tx_op.src_iov_len;
	}

	if(pe_entry->tx.tx_op.op == SOCK_OP_TSEND){
		rbfdread(&tx_ctx->rbfd, &pe_entry->tag, sizeof(uint64_t));
	}

	if(!is_inject){
		/* copy src iov(s)*/
		for(i = 0; i<pe_entry->tx.tx_op.src_iov_len; i++){
			rbfdread(&tx_ctx->rbfd, &pe_entry->tx.src_iov[i], 
			       sizeof(union sock_iov));
			payload_len += pe_entry->tx.src_iov[i].iov.len;
		}

		/* copy dst iov(s)*/
		for(i = 0; i<pe_entry->tx.tx_op.dest_iov_len; i++){
			rbfdread(&tx_ctx->rbfd, &pe_entry->tx.dst_iov[i], 
			       sizeof(union sock_iov));
			payload_len += pe_entry->tx.dst_iov[i].iov.len;
		}
	}

	/* prepare message header */
	msg_hdr = &pe_entry->msg_hdr;
	msg_hdr->version = htons(SOCK_WIRE_PROTO_VERSION);
	msg_hdr->op_type = htons(pe_entry->tx.tx_op.op);
	msg_hdr->src_iov_len = htons(pe_entry->tx.tx_op.src_iov_len);
	msg_hdr->rx_id = htons(SOCK_GET_RX_ID(pe_entry->addr));
	msg_hdr->flags = htonl(pe_entry->flags);
	pe_entry->tx.header_sent = 0;

	/* calculate & set message len */
	msg_len = sizeof(struct sock_msg_hdr);
	if(!is_inject){
		msg_len += (pe_entry->tx.tx_op.src_iov_len + 
			    pe_entry->tx.tx_op.dest_iov_len) *
			sizeof(union sock_iov);
	}
	msg_len += payload_len;
	msg_hdr->msg_len = htonl(msg_len);
	return 0;
}

int sock_pe_progress_cq(struct sock_pe *pe, struct sock_cq *cq)
{
	int ret = 0, i;
	struct sock_ep *ep;
	struct pollfd poll_fd;
	struct sock_tx_ctx *tx_ctx;
	struct sock_conn *conn;
	struct dlist_entry *curr_ctx, *curr;

	fastlock_acquire(&pe->pe_lock);

	if(!dlist_empty(&cq->pe_entry_head.list)){
		ret = sock_pe_progress_table(pe, cq);
		if(ret) goto out;
	}

	/* iterate over tx_ctx list */
	for(curr_ctx = cq->tx_ctx_head.list.next; 
	    curr_ctx != &cq->tx_ctx_head.list && 
		    !dlist_empty(&pe->free_list_head.list); 
	    curr_ctx = curr_ctx->next){
		
		tx_ctx = container_of(curr_ctx, struct sock_tx_ctx, list);
			
		/* iterate over rbuf of tx_ctx */
		while(!rbfdempty(&tx_ctx->rbfd) && 
		      !dlist_empty(&pe->free_list_head.list)){
			/* new TX PE entry */
			ret = sock_pe_new_tx_entry(pe, cq, tx_ctx);
			if(ret) goto out;
		}
	}

	/* check for rx */
	for(curr = cq->ep_list_head.list.next;
	    !dlist_empty(&pe->free_list_head.list) && curr != &cq->ep_list_head.list;
	    curr = curr->next){
		
		ep = container_of(curr, struct sock_ep, list);
		if(ep->recv_cq != cq)
			continue;

		/* check for incoming data */
		for (i=0; i<ep->av->count; i++) {
			sock_conn_map_lookup_key(ep->av->cmap, 
						 ep->av->key_table[i], &conn);
			poll_fd.fd = conn->sock_fd;
			poll_fd.events = POLLIN;	
			ret = poll(&poll_fd, 1, 0);
			
			if(ret == 1){
				/* new RX PE entry */
				ret = sock_pe_new_rx_entry(pe, cq, ep);
				if(ret) goto out;
			}else if(ret < 0){
				sock_debug(SOCK_ERROR, "PE: poll() failed!\n");
				goto out;
			}else{
				/* try next */
				break;
			}
		}
	}

out:
	fastlock_release(&pe->pe_lock);
	return ret;
}

int sock_pe_add_cq(struct sock_pe *pe, struct sock_cq *cq)
{
	if(rbfdavail(&pe->cq_rb) < sizeof(struct sock_cq*))
		return -FI_ENOMEM;

	fastlock_acquire(&pe->cq_lock);
	rbfdwrite(&pe->cq_rb, cq, sizeof(struct sock_cq*));
	rbfdcommit(&pe->cq_rb);
	fastlock_release(&pe->cq_lock);
	sock_debug(SOCK_INFO, "cq: %p added to PE\n", cq);
	return 0;
}

static void *sock_pe_progress_thread(void *data)
{
	size_t ret;
	struct sock_cq *cq;
	struct sock_pe *pe = 
		(struct sock_pe *)data;

	sock_debug(SOCK_INFO, "PE: Progress thread started\n");

	while(pe->do_progress){

		cq = NULL;
		if(rbfdempty(&pe->cq_rb) && 
		   dlist_empty(&pe->busy_list_head.list)){
			ret = rbfdsread(&pe->cq_rb,
					(void*)&cq, sizeof(struct sock_cq*), 10000);
			if(ret < 0)
				continue;
		}
				
		if(cq != NULL){
			ret = sock_pe_progress_cq(pe, cq);
			if(ret){
				sock_debug(SOCK_ERROR, "PE: failed to progress CQ\n");
				return NULL;
			}
			sock_pe_add_cq(pe, cq);
		}
	}
	sock_debug(SOCK_INFO, "Stopping progress thread\n");
	return NULL;
}

static void sock_pe_init_table(
	struct sock_pe *pe)
{
	int64_t i;
	
	memset(&pe->pe_table, 0, 
	       sizeof(struct sock_pe_entry) * MAX_PROGRESS_ENTRIES);

	dlist_init(&pe->free_list_head.list);
	dlist_init(&pe->busy_list_head.list);

	for(i=0; i<MAX_PROGRESS_ENTRIES; i++){
		dlist_insert_tail(&pe->pe_table[i].list, &pe->free_list_head.list);
	}
	fastlock_init(&pe->pe_lock);
	sock_debug(SOCK_INFO, "PE table init: OK\n");
}

struct sock_pe *sock_pe_init(struct sock_domain *domain)
{
	struct sock_pe *pe = calloc(1, sizeof(struct sock_pe));
	if(!pe)
		return NULL;

	sock_pe_init_table(pe);

	if(rbfdinit(&pe->cq_rb, 
		    SOCK_NUM_PROGRESS_CQS * sizeof(struct sock_cq*))){
		sock_debug(SOCK_ERROR, "PE: Couldn't create CQ rb\n");
		goto err;
	}
	fastlock_init(&pe->cq_lock);

	pe->do_progress = 1;
	if(pthread_create(&pe->progress_thread, NULL, sock_pe_progress_thread,
			  (void *)pe)){
		sock_debug(SOCK_ERROR, "PE: Couldn't create progress thread\n");
		goto err;
	}
	sock_debug(SOCK_INFO, "PE init: OK\n");

err:
	free(pe);
	return NULL;
}

void sock_pe_finalize(struct sock_pe *pe)
{
	/* FIXME: wait until PE table is empty? 
	   what about posted recv buffers */
	
	pe->do_progress = 0;
	pthread_join(pe->progress_thread, NULL);
	
	rbfdfree(&pe->cq_rb);
	fastlock_destroy(&pe->cq_lock);
	fastlock_destroy(&pe->pe_lock);
	atomic_dec(&pe->domain->ref);
	free(pe);
	sock_debug(SOCK_INFO, "Progress engine finalize: OK\n");
}

