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

void sock_pe_process_rx_send(struct sock_pe *pe, struct sock_pe_entry *pe_entry)
{
	int i, truncated;
	uint64_t ignore, len;
	struct sock_rx_entry *rx_entry;

	rx_entry = sock_cq_get_rx_buffer(pe_entry->cq, addr, rx_id, 
					 IGNORE_TAG, ignore);
	if(!rx_entry){
		sock_debug(SOCK_ERROR, "No matching requests!\n");
		exit(-1);
		/* FIXME: Or just report as an error ? */
	}

	if(pe_entry->flags & FI_REMOTE_CQ_DATA){
		rx_entry->data = pe_entry->data;
	}

	if(pe_entry->flags & FI_REMOTE_COMPLETE){
		sock_debug(SOCK_ERROR, "FI_REMOTE_COMPLETE not implemented\n");
		/* TODO: send ack to sender */
	}

	truncated = 0;
	if(pe_entry->tx_op.src_iov_len != rx_entry->src_iov_len){
		truncated = 1;
	}

	for(i=0; i<min(pe_entry->tx_op.src_iov_len, rx_entry->src_iov_len); i++){
		
		if(pe_entry->tx_iov[i].len > rx_entry->iov[i].iov.len){
			truncated = 1;
		}

		len = min(pe_entry->tx_iov[i].len, rx_entry->iov[i].iov.len);
		memcpy(pe_entry->tx_iov[i].iov.addr, rx_entry->iov[i].iov.addr, len);
		rx_entry->iov[i].iov.len = len;
	}

	/* report error, if any */
	if(truncated){
		sock_cq_report_error(pe_entry->cq);
	}
	
	/* post completion */
	if(pe_entry->ep->recv_cq_event_flag){
		if(pe_entry->flags & FI_EVENT)
			sock_cq_report_rx_completion(pe_entry->cq, rx_entry);
	}else{
		sock_cq_report_rx_completion(pe_entry->cq, rx_entry);
	}
}

void sock_pe_process_recv(struct sock_pe *pe, struct sock_pe_entry *entry)
{
	/* endian check */

	/* process rx entry */
	switch(curr_entry->msg_hdr.op_type){

	case SOCK_OP_SEND:
		sock_pe_process_rx_send(pe, entry);
		break;

	case SOCK_OP_SEND_INJECT:
	case SOCK_OP_WRITE:
	case SOCK_OP_WRITE_INJECT:
	case SOCK_OP_READ:
	case SOCK_OP_TSEND:
	case SOCK_OP_ATOMIC:
	default:
		sock_debug(SOCK_ERROR, "PE: Operation not supported\n");
		break;
	}

	free(curr_entry->rx.raw_data);
}

inline void sock_pe_progress_rx_entry(struct sock_pe *pe,
				      struct sock_pe_entry *entry)
{
	int ret; 
	struct sock_conn_map_entry *conn_entry;

	ret = sock_conn_map_lookup_key(pe->conn_map,
				       curr_entry->conn_key, &conn_entry);

	if(ret != 0 || (conn_entry->pe_index != -1 && 
			conn_entry->pe_index != curr_entry->index))
		return;

	if(conn_entry->pe_index == -1){
		ret = sock_conn_map_set_pe_entry(pe->conn_map, 
						 curr_entry->index);
		if(ret)
			return;
	}

	sock_debug(SOCK_INFO, "PE: [%d] Progressing RX entry\n", 
		   curr_entry->pe_index);
	
	if(curr_entry->done_len < sizeof(struct sock_msg_hdr)){
		ret = recv(conn_entry->fd, 
			   (char*)&curr_entry->msg_hdr + curr_entry->done_len, 
			   sizeof(struct sock_msg_hdr) - curr_entry->done_len);
		if(ret < 0)
			return;

		curr_entry->done_len += ret;
		if(curr_entry->done_len == sizeof(struct sock_msg_hdr)){
			curr_entry->msg_hdr.msg_len = 
				ntohl(curr_entry->msg_hdr.msg_len);
			
			curr_entry->rx.raw_data = 
				malloc(curr_entry->msg_hdr.msg_len);
			if(!curr_entry->rx.raw_data){
				sock_debug(SOCK_ERROR, "PE: Not enough memory (%lu)\n",
					   curr_entry->msg_hdr.msg_len);
				exit(-1);
			}
		}
	}

	ret = recv(conn_entry->fd, 
		   (char*)&curr_entry->rx.raw_data + 
		   curr_entry->done_len - sizeof(struct sock_msg_hdr), 
		   curr_entry->msg_hdr.msg_len - curr_entry->done_len);

	if(ret < 0)
		return;

	curr_entry->done_len += ret;
}

static void sock_pe_progress_tx_send(struct sock_pe *pe, 
				  struct sock_pe_entry *curr_entry, 
				  struct sock_conn_map_entry *conn_entry)
{
	int ret, rem, offset, data_sent, i;
	struct sock_msg_hdr *msg_hdr = curr_entry->msg_hdr;

	/* src iov(s) */
	if(curr_entry->done_len > (sizeof(struct sock_msg_hdr) +
				   msg_hdr->src_iov_len * sizeof(union sock_tx_iov))){

		rem = msg_hdr->src_iov_len * sizeof(union sock_tx_iov) - 
			(curr_entry->done_len + sizeof(struct sock_msg_hdr));
		offset = (msg_hdr->src_iov_len * sizeof(union sock_tx_iov)) - rem;

		ret = send(conn_entry->fd, 
			   (char*)&curr_entry->tx.tx_iov + offset, rem);

		if(ret < 0)
			return;
		
		curr_entry->done_len += ret;
		if(ret < rem){
			return;
		}
	}

	/* data */
	if(curr_entry->done_len < msg_hdr->msg_len){

		done_data = curr_entry->done_len -
			(sizeof(struct sock_msg_hdr)+
			 msg_hdr->src_iov_len * sizeof(union sock_tx_iov));
		offset = 0;

		for(i = 0; i<msg_hdr->src_iov_len; i++){
			if(done_data > curr_entry->tx.tx_iov[i].iov.len + offset){
				offset += curr_entry->tx.tx_iov[i].iov.len;
				continue;
			}

			curr_offset = done_data - offset;
			ret = send(conn_entry->fd, 
				   (char*)curr_entry->tx.tx_iov[i].iov.addr + curr_offset, 
				   curr_entry->tx.tx_iov[i].iov.len - curr_offset);

			if(ret<0)
				return;

			curr_entry->done_len += ret;
			offset += ret;
		}
	}

	/* user data */
	rem = msg_hdr->msg_len - curr_entry->done_len;
	ret = send(conn_entry->fd, 
		   (char*)&curr_entry->data + sizeof(uint64_t) - rem, rem);
	if(ret<0)
		return;
	curr_entry->done_len += ret;
}

inline void sock_pe_progress_tx_entry(struct sock_pe *pe,
				      struct sock_pe_entry *curr_entry)
{
	int ret; 
	struct sock_conn_map_entry *conn_entry;

	ret = sock_conn_map_lookup_key(pe->conn_map,
				       curr_entry->conn_key, &conn_entry);

	if(ret != 0 || (conn_entry->pe_index != -1 && 
			conn_entry->pe_index != curr_entry->index))
		return;

	if(conn_entry->pe_index == -1){
		ret = sock_conn_map_set_pe_entry(pe->conn_map, 
						 curr_entry->index);
		if(ret)
			return;
	}

	sock_debug(SOCK_INFO, "PE: [%d] Progressing TX entry\n", 
		   curr_entry->pe_index);

	if(!curr_entry->tx.header_sent){
		ret = send(conn_entry->fd, 
			   (char*)curr_entry->msg_hdr + curr_entry->done_len,
			   sizeof(struct sock_msg_hdr) - curr_entry->done_len);
		if(ret < 0)
			return;
		curr_entry->done_len += ret;
		if(curr_entry->done_len == sizeof(struct sock_msg_hdr)){
			curr_entry->tx.header_sent = 1;
			sock_debug(SOCK_INFO, "PE: [%d] Header sent\n", 
				   curr_entry->pe_index);
		}else{
			return;
		}
	}

	switch(curr_entry->msg_hdr.op_type){

	case SOCK_OP_SEND:
		sock_pe_progress_tx_send(pe, curr_entry, conn_entry);
		break;

	case SOCK_OP_SEND_INJECT:
	case SOCK_OP_WRITE:
	case SOCK_OP_WRITE_INJECT:
	case SOCK_OP_READ:
	case SOCK_OP_TSEND:
	case SOCK_OP_ATOMIC:
	default:
		sock_debug(SOCK_ERROR, "PE: Operation not supported\n");
		break;
	}

	return;
}

void sock_pe_release_entry(struct sock_pe *pe, 
			struct sock_pe_entry *entry)
{
	dlist_remove(&entry->list);
	dlist_insert_tail(&entry->list, &pe->free_list_head.list);
}

struct sock_pe_entry *sock_pe_acquire_entry(struct sock_pe *pe)
{
	struct sock_pe_entry *pe_entry;

	pe_entry = pe->free_list_head.list.next;
	dlist_remove(&pe_entry->list);
	dlist_insert_tail(&pe_entry->list, &pe->busy_list_head.list);
	return entry;
}

static void sock_pe_progress_table(struct sock_pe *engine,
				  struct sock_cq *cq)
{
	struct dlist_entry *head, *curr, *next;
	struct sock_pe_entry *pe_entry;
	
	head = &cq->pe_list_head.list;
	curr = head->next;
	
	while(curr != head){
		next = curr->next;
		pe_entry = container_of(curr, struct sock_pe_entry, list);
		if(curr->type == SOCK_RX){
			sock_pe_progress_rx_entry(engine, curr);
			if(curr->msg_hdr.msg_len == curr->done_len){
				sock_debug(SOCK_INFO, "PE: [%d] RX done\n", curr->pe_index);
				sock_pe_process_recv(pe, curr);
				sock_pe_free_entry(pe, curr);
			}
		}else{
			sock_pe_progress_tx_entry(engine, curr);
			if(curr->msg_hdr.msg_len == curr->done_len){
				sock_debug(SOCK_INFO, "PE: [%d] TX done\n", curr->pe_index);
				sock_cq_report_tx_completion(curr->cq, curr);
				sock_pe_free_entry(pe, curr);
			}
		}
		curr = next;
	}
}

static int sock_pe_new_rx_entry(struct sock_pe *engine, struct sock_cq *cq, 
				struct sock_rx_ctx *rx_ctx, 
				struct sock_rx_entry *rx_entry)
{
	int i;
	struct sock_pe_entry *pe_entry;
	
	pe_entry = sock_pe_acquire_entry(engine);
	if(!pe_entry){
		sock_debug(SOCK_ERROR, "Error in getting PE entry \n");
		return -FI_EINVAL;
	}

	pe_entry->type = SOCK_RX;
	pe_entry->done_len = 0;
	pe_entry->conn_key = -1;

	pe_entry->ep = rx_ctx->ep;
	pe_entry->cq = cq;

	/* link to tracking list in CQ */
	dlist_init(&pe_entry->list);
	dlist_insert_tail(&pe_entry->list, &cq->pe_list_head);

	/* fill in PE rx entry */
	pe_entry->rx.rx_op = rx_entry->rx_op;
	pe_entry->rx.flags = rx_entry->flags;
	pe_entry->rx.context = rx_entry->context;
	pe_entry->rx.src_addr = rx_entry->addr;
	pe_entry->rx.tag = rx_entry->tag;

	/* copy iov(s)*/
	for(i = 0; i<rx_entry->rx_op.dest_iov_len; i++){
		pe_entry->rx.rx_iov[i] = rx_entry->iov[i];
	}

	return 0;
}

static int sock_pe_new_tx_entry(struct sock_pe *engine, struct sock_cq *cq, 
				struct sock_tx_ctx *tx_ctx)
{
	int i, is_inject = 0;
	uint64_t msg_len, payload_len = 0;
	struct sock_msg_hdr *msg_hdr;
	struct sock_pe_entry *pe_entry;
	
	pe_entry = sock_pe_acquire_entry(engine);
	if(!pe_entry){
		sock_debug(SOCK_ERROR, "Error in getting PE entry \n");
		return -FI_EINVAL;
	}

	pe_entry->type = SOCK_TX;
	pe_entry->done_len = 0;
	pe_entry->conn_key = -1;

	pe_entry->ep = tx_ctx->ep;
	pe_entry->cq = cq;

	/* link to tracking list in CQ */
	dlist_init(&pe_entry->list);
	dlist_insert_tail(&pe_entry->list, &cq->pe_list_head);

	/* fill in PE tx entry */
	memset(pe_entry->msg_hdr, 0, sizeof(struct sock_msg_hdr));
	rbfdread(&tx_ctx->rbfd, &pe_entry->tx.tx_op, 
		 sizeof(struct sock_tx_op));

	rbread(&tx_ctx->rbfd, &pe_entry->tx.flags, sizeof(uint64_t));
	rbread(&tx_ctx->rbfd, &pe_entry->tx.context, sizeof(uint64_t));
	rbread(&tx_ctx->rbfd, &pe_entry->tx.dest_addr, sizeof(uint64_t));

	if(pe_entry->tx.flags & FI_REMOTE_CQ_DATA){
		rbread(&tx_ctx->rbfd, &pe_entry->tx.data, sizeof(uint64_t));
	}

	if(pe_entry->tx.flags & FI_INJECT){
		is_inject = 1;
		payload_len = pe_entry->tx.tx_op.src_iov_len;
	}

	if(pe_entry->tx.tx_op.op == SOCK_OP_TSEND){
		rbread(&tx_ctx->rbfd, &pe_entry->tx.tag, sizeof(uint64_t));
	}

	if(!is_inject){
		/* copy src iov(s)*/
		for(i = 0; i<pe_entry->tx.tx_op.src_iov_len; i++){
			rbread(&tx_ctx->rbfd, &pe_entry->tx.src_iov[i], 
			       sizeof(union struct sock_tx_iov));
			payload_len += pe_entry->tx.src_iov[i].iov.len;
		}

		/* copy dst iov(s)*/
		for(i = 0; i<pe_entry->tx.tx_op.dst_iov_len; i++){
			rbread(&tx_ctx->rbfd, &pe_entry->tx.tx_op.dst_iov[i], 
			       sizeof(union struct sock_tx_iov));
			payload_len += pe_entry->tx.dst_iov[i].iov.len;
		}
	}

	/* prepare message header */
	msg_hdr = &pe_entry->msg_hdr;
	msg_hdr->version = htons(SOCK_WIRE_PROTO_VERSION);
	msg_hdr->op_type = htons(pe_entry->tx.tx_op.op);
	msg_hdr->src_iov_len = htons(pe_entry->tx.tx_op.src_iov_len);
	msg_hdr->rx_id = htons(SOCK_GET_RX_ID(pe_entry->tx.dest_addr));
	msg_hdr->flags = htonl(pe_entry->tx.flags);
	pe_entry->tx.header_sent = 0;

	/* calculate & set message len */
	msg_len = sizeof(struct sock_msg_hdr);
	if(!is_inject){
		msg_len += (pe_entry->tx.tx_op.src_iov_len + 
			    pe_entry->tx.tx_op.dst_iov_len) *
			sizeof(union sock_tx_iov);
	}
	msg_len += payload_len;
	return 0;
}

static void sock_pe_progress(struct sock_pe *engine,
			    struct sock_cq *cq)
{
	int ret, sock_fd;
	struct pollfd poll_fd;
	struct sock_tx_ctx *tx_ctx;
	struct sock_rx_ctx *rx_ctx;
	struct sock_rx_entry *rx_entry;
	struct sock_conn_map_entry *conn_entry;
	struct dlist_entry *curr_ctx, *curr_entry, *next_entry;

	fastlock_acquire(&engine->engine_lock);

	if(!dlist_empty(&cq->pe_list_head.list))
		sock_pe_progress_table(engine, cq);

	if(dlist_empty(&cq->tx_list) && dlist_empty(&cq->rx_list))
		break;

	/* check for tx_ctx list */
	if(!dlist_empty(&cq->tx_list)){
		
		/* iterate over tx_ctx list */
		for(curr_ctx = cq->tx_list_head.next; curr_ctx != &cq->tx_list_head &&
			    !dlist_empty(&pe->free_list_head); curr_ctx = curr_ctx->next){
			tx_ctx = container_of(curr_ctx, struct sock_tx_ctx, list);
			
			/* iterate over rbuf of tx_ctx */
			while(!rbfdempty(&tx_ctx->rbfd) && !dlist_empty(&pe->free_list_head)){
				/* new TX PE entry */
				sock_pe_new_tx_entry(engine, cq, tx_ctx);
			}
		}
	}

	/* check for RX */
	if(!dlist_empty(&cq->rx_list)){
		poll_fd.events = POLLIN;	

		/* iterate over rx_ctx list */
		for(curr_ctx = cq->rx_list_head.next; 
		    curr_ctx != &cq->rx_list_head && !dlist_empty(&pe->free_list_head); 
		    curr_ctx = curr_ctx->next){
			rx_ctx = container_of(curr_ctx, struct sock_rx_ctx, list);

			/* iterate over rx_entry list */
			curr_entry = curr_ctx->rx_list_head.next;
			while(!dlist_empty(&curr_ctx->rx_list_head)){
				next_entry = curr_entry->next;
				
				rx_entry = container_of(curr_entry, struct sock_rx_entry, list);
				ret = sock_conn_map_lookup_addr(pe->domain->conn_map,
								rx_entry->addr,  &conn_entry);
				
				/* check for incoming data */
				poll_fd.fd = sock_fd;
				ret = poll(&poll_fd, 1, 0);
				if(ret == 1){
					/* new RX PE entry */
					sock_pe_new_rx_entry(engine, cq, rx_ctx, rx_entry);
					dlist_remove(&rx_entry->list);
				}else if(ret < 0){
					sock_debug(SOCK_ERROR, "PE: poll() failed!\n");
					break;
				}else{
					break;
				}
				curr_entry = next_entry;
			}
		}

	}
	fastlock_release(&engine->engine_lock);
}

static void *sock_pe_progress_thread(void *data)
{
	size_t ret;
	struct sock_cq *cq;
	struct sock_pe *engine = 
		(struct sock_pe *)data;

	sock_debug(SOCK_INFO, "PE: Progress thread started\n");

	while(engine->do_progress){

		cq = NULL;
		if(rbfdempty(&engine->cq_rb) && engine->busy_head == -1){
			ret = rbfdsread(engine->cq_rb,
					(void*)&cq, sizeof(struct sock_cq*), 1000);
			if(ret < 0)
				continue;
		}
				
		if(cq != NULL){
			sock_progress_cq(engine, cq);
			sock_progress_engine_add_cq(engine, cq);
		}

		if(engine->busy_head != -1){
			sock_progress_table(engine);
		}
	}
	return NULL;
}

static void sock_pe_init_table(
	struct sock_pe *engine)
{
	int64_t i;
	
	memset(&engine->pe_table, 0, 
	       sizeof(struct sock_progress_entry) * MAX_PROGRESS_ENTRIES);

	dlist_init(&engine->free_list_head.list);
	dlist_init(&engine->busy_list_head.list);

	for(i=0; i<MAX_PROGRESS_ENTRIES; i++){
		dlist_insert_tail(&engine->progress_entry[i].list, 
				  &engine->free_list_head.list);
	}
	fastlock_init(&engine->engine_lock);
}

struct sock_pe *sock_pe_init(struct sock_domain *domain)
{
	struct sock_pe *engine = 
		calloc(1, struct sock_pe);
	if(!engine)
		return NULL;

	sock_pe_init_table(engine);

	if(rbfdinit(&engine->cq_rb, 
		    SOCK_NUM_PROGRESS_CQS * sizeof(struct sock_cq*))){
		sock_debug(SOCK_ERROR, "PE: Couldn't create CQ rb\n");
		goto err;
	}
	fastlock_init(&engine->cq_lock);

	engine->do_progress = 1;
	if(pthread_create(&engine->progress_thread, NULL, sock_pe_progress_thread,
			  (void *)engine)){
		sock_debug(SOCK_ERROR, "PE: Couldn't create progress thread\n");
		goto err;
	}

err:
	free(engine);
	return NULL;
}

int sock_pe_add_cq(struct sock_pe *engine,
				struct sock_cq *cq)
{
	if(rbfdavail(&engine->cq_rb) < sizeof(struct sock_cq*))
		return -FI_ENOMEM;

	fastlock_acquire(&engine->cq_lock);
	rbfdwrite(&engine->cq_rb, cq, sizeof(struct sock_cq*));
	rbfdcommit(&engine->cq_rb);
	fastlock_release(&engine->cq_lock);
	return 0;
}
