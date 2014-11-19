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

int sock_pe_report_tx_completion(struct sock_pe_entry *pe_entry,
				 struct sock_tx_ctx *tx_ctx)
{
	int ret;

	if (tx_ctx->send_cq_event) {
		if (pe_entry->msg_hdr.flags & FI_EVENT) {
			if (tx_ctx->send_cq) {
				ret = tx_ctx->send_cq->report_completion(
					tx_ctx->send_cq, pe_entry->addr, pe_entry);
			}
		}
	}else {
		if (tx_ctx->send_cq)
			ret = tx_ctx->send_cq->report_completion(
				tx_ctx->send_cq, pe_entry->addr, pe_entry);
	}
	
	if (ret < 0) {
		SOCK_LOG_ERROR("Failed to report completion %p\n", pe_entry);
		if (tx_ctx->eq) {
			sock_eq_report_error(tx_ctx->eq, 
					     &tx_ctx->send_cq->cq_fid.fid, 
					     tx_ctx->send_cq->cq_fid.fid.context, 
					     -FI_ENOSPC, -FI_ENOSPC, NULL);
		}
	}
	
	if (tx_ctx->send_cntr) {
		ret = sock_cntr_inc(tx_ctx->send_cntr);
		if (ret < 0) {
			SOCK_LOG_ERROR("Failed to report completion %p\n",
				       pe_entry);
			if (tx_ctx->eq) {
				sock_eq_report_error(tx_ctx->eq, 
						     &tx_ctx->send_cntr->cntr_fid.fid, 
						     tx_ctx->send_cntr->cntr_fid.fid.context, 
						     -FI_ENOSPC, -FI_ENOSPC, NULL);
			}				
		}
	}
	return 0;
}

int sock_pe_report_rx_completion(struct sock_pe_entry *pe_entry,
				 struct sock_rx_ctx *rx_ctx)
{
	int ret;

	if (rx_ctx->recv_cq_event) {
		if (pe_entry->msg_hdr.flags & FI_EVENT) {
			if (rx_ctx->recv_cq) {
				ret = rx_ctx->recv_cq->report_completion(
					rx_ctx->recv_cq, pe_entry->msg_hdr.src_addr,
					pe_entry);
			}
		}
	}else {
		if (rx_ctx->recv_cq) {
			ret = rx_ctx->recv_cq->report_completion(
				rx_ctx->recv_cq, pe_entry->msg_hdr.src_addr, 
				pe_entry);
		}
	}

	if (ret < 0) {
		SOCK_LOG_ERROR("Failed to report completion %p\n", pe_entry);
		if (rx_ctx->eq) {
			sock_eq_report_error(rx_ctx->eq, 
					     &rx_ctx->recv_cq->cq_fid.fid, 
					     rx_ctx->recv_cq->cq_fid.fid.context, 
					     -FI_ENOSPC, -FI_ENOSPC, NULL);
		}
	}

	if (rx_ctx->recv_cntr) {
		ret = sock_cntr_inc(rx_ctx->recv_cntr);
		if (ret < 0) {
			SOCK_LOG_ERROR("Failed to report completion %p\n", pe_entry);
			if (rx_ctx->eq) {
				sock_eq_report_error(rx_ctx->eq, 
						     &rx_ctx->recv_cntr->cntr_fid.fid, 
						     rx_ctx->recv_cntr->cntr_fid.fid.context, 
						     -FI_ENOSPC, -FI_ENOSPC, NULL);
			}
		}
	}
	return 0;
}

static int sock_pe_process_rx_send(struct sock_pe *pe, struct sock_rx_ctx *rx_ctx,
				   struct sock_pe_entry *pe_entry)
{
	int i, ret;
	struct sock_rx_entry *rx_entry;
	uint64_t len, rem, offset;

	rx_entry = sock_ep_get_rx_entry(pe_entry->ep, pe_entry);

	if (!rx_entry) {
		SOCK_LOG_ERROR("No matching recv!\n");
		if (rx_ctx->recv_cntr)
			sock_cntr_err_inc(rx_ctx->recv_cntr);
		if (rx_ctx->recv_cq)
			sock_cq_report_error(rx_ctx->recv_cq, pe_entry, 0,
					     -FI_ENOENT, -FI_ENOENT, NULL);
		ret = -FI_ENOENT;
		goto out;
	}
	
	offset = 0;
	if (pe_entry->msg_hdr.op_type == SOCK_OP_TSEND) {
		memcpy(&pe_entry->tag, (char*)pe_entry->rx.raw_data + offset,
		       sizeof(uint64_t));
		offset += sizeof(uint64_t);
	}

	if (pe_entry->msg_hdr.flags & FI_REMOTE_CQ_DATA) {
		memcpy(&pe_entry->data, (char*)pe_entry->rx.raw_data + offset,
		       sizeof(uint64_t));
		offset += sizeof(uint64_t);
	}

	rem = pe_entry->msg_hdr.msg_len - sizeof(struct sock_msg_hdr) - offset;
	for (i=0; rem > 0 && i < rx_entry->rx_op.src_iov_len; i++) {
		len = MIN(rx_entry->iov[i].iov.len, rem);
		memcpy((void *)pe_entry->rx.rx_iov[i].iov.addr, 
		       (char*)pe_entry->rx.raw_data + offset, len);
		rem -= len;
		offset += len;
	}

	/* report error, if any */
	if (rem) {
		if (rx_ctx->recv_cntr)
			sock_cntr_err_inc(rx_ctx->recv_cntr);
		if (rx_ctx->recv_cq)
			ret = sock_cq_report_error(rx_ctx->recv_cq, pe_entry, rem,
						   -FI_ENOSPC, -FI_ENOSPC, NULL);
		goto out;
	} else {
		sock_pe_report_rx_completion(pe_entry, rx_ctx);
	}
	
out:
	free(rx_entry);
	return ret;
}

int sock_pe_send_rx_ack(struct sock_pe_entry *pe_entry)
{
	/* FIXME */
	SOCK_LOG_ERROR("FI_REMOTE_COMPLETE not implemented\n");
	return -FI_ENOSYS;
}

static int sock_pe_process_recv(struct sock_pe *pe, struct sock_rx_ctx *rx_ctx,
				struct sock_pe_entry *pe_entry)
{
	int ret;
	struct sock_msg_hdr *msg_hdr;

	msg_hdr = &pe_entry->msg_hdr;
	msg_hdr->version = ntohs(msg_hdr->version);
	if (msg_hdr->version != SOCK_WIRE_PROTO_VERSION) {
		SOCK_LOG_ERROR("Invalid wire protocol\n");
		ret = -FI_EINVAL;
		goto out;
	}
		
	msg_hdr->op_type = ntohs(msg_hdr->op_type);
	msg_hdr->rx_id = ntohs(msg_hdr->rx_id);
	msg_hdr->flags = ntohs(msg_hdr->flags);
	msg_hdr->msg_len = ntohl(msg_hdr->msg_len);

	SOCK_LOG_INFO("PE RX: MsgLen: %lu\n", msg_hdr->msg_len);

	/* process rx entry */
	switch (pe_entry->msg_hdr.op_type) {

	case SOCK_OP_SEND:
	case SOCK_OP_TSEND:
		ret = sock_pe_process_rx_send(pe, rx_ctx, pe_entry);
		break;

	case SOCK_OP_WRITE:
	case SOCK_OP_READ:
	case SOCK_OP_ATOMIC:
	default:
		ret = -FI_ENOSYS;
		SOCK_LOG_ERROR("Operation not supported\n");
		break;
	}

	if (pe_entry->msg_hdr.flags & FI_REMOTE_COMPLETE) {
		sock_pe_send_rx_ack(pe_entry);
	}
	pe_entry->is_complete = 1;

out:
	free(pe_entry->rx.raw_data);
	return ret;
}

static int sock_pe_progress_rx_entry(struct sock_pe *pe, 
				     struct sock_pe_entry *pe_entry)
{
	int ret, rem, read_data; 
	struct sock_conn *conn = pe_entry->conn;

	SOCK_LOG_INFO("[%p] Progressing RX pe_entry\n", pe_entry);
	if (conn->pe_entry != NULL && conn->pe_entry != pe_entry)
		return 0;

	if (conn->pe_entry == NULL) {
		conn->pe_entry = pe_entry;
	}

	if (pe_entry->done_len < sizeof(struct sock_msg_hdr)) {
		ret = recv(conn->sock_fd, 
			   (char*)&pe_entry->msg_hdr + pe_entry->done_len, 
			   sizeof(struct sock_msg_hdr) - pe_entry->done_len, 0);
		if (ret < 0) {
			if (ret == EWOULDBLOCK || ret == EAGAIN)
				return 0;
			else{
				SOCK_LOG_ERROR("Failed to progress recv\n");
				return ret;
			}
		}
		
		pe_entry->done_len += ret;
		if (pe_entry->done_len == sizeof(struct sock_msg_hdr)) {
			pe_entry->msg_hdr.msg_len = 
				ntohl(pe_entry->msg_hdr.msg_len);
			
			pe_entry->rx.raw_data = 
				calloc(1, pe_entry->msg_hdr.msg_len - 
				       sizeof(struct sock_msg_hdr));
			if (!pe_entry->rx.raw_data) {
				SOCK_LOG_ERROR("Not enough memory\n");
				return -FI_ENOMEM;
			}
		}else {
			return 0;
		}
	}

	read_data = pe_entry->done_len - sizeof(struct sock_msg_hdr);
	rem = pe_entry->msg_hdr.msg_len - sizeof(struct sock_msg_hdr) 
		- read_data;
	
	ret = recv(conn->sock_fd, 
		   (char*)&pe_entry->rx.raw_data + read_data, rem, 0);

	if (ret < 0) {
		if (ret == EWOULDBLOCK || ret == EAGAIN)
			return 0;
		else{
			SOCK_LOG_ERROR("Failed to progress recv\n");
			return ret;
		}
	}

	pe_entry->done_len += ret;
	if (pe_entry->done_len == pe_entry->msg_hdr.msg_len)
		pe_entry->rx.recv_done = 1;

	return 0;
}


static int sock_pe_progress_tx_send(struct sock_pe *pe, 
				    struct sock_pe_entry *pe_entry, 
				    struct sock_conn *conn)
{
	int ret;
	ssize_t len, i, offset, done_data, data_len;

	len = sizeof(struct sock_msg_hdr);
	if (pe_entry->tx.tx_op.op == SOCK_OP_TSEND ||
		pe_entry->tx.tx_op.op == SOCK_OP_TSEND_INJECT) {

		offset = pe_entry->done_len - len;

		len += sizeof(uint64_t);
		if (pe_entry->done_len < len) {
			ret = send(conn->sock_fd, 
				   (char*)pe_entry->tag + offset,
				   sizeof(uint64_t) - offset, 0);
			if (ret < 0) {
				if (ret == EWOULDBLOCK || ret == EAGAIN)
					return 0;
				else{
					SOCK_LOG_ERROR("Failed to send: %d\n", ret);
					return ret;
				}		
			}	
			pe_entry->done_len += ret;
			if (pe_entry->done_len != len)
				return 0;
		}
	}

	if (pe_entry->flags & FI_REMOTE_CQ_DATA) {

		offset = pe_entry->done_len - len;
		len += sizeof(uint64_t);
		if (pe_entry->done_len < len) {
			ret = send(conn->sock_fd, 
				   (char*)pe_entry->data + offset,
				   sizeof(uint64_t) - offset, 0);
			if (ret < 0) {
				if (ret == EWOULDBLOCK || ret == EAGAIN)
					return 0;
				else{
					SOCK_LOG_ERROR("Failed to send\n");
					return ret;
				}		
			}	
			pe_entry->done_len += ret;
			if (pe_entry->done_len != len)
				return 0;
		}
	}


	if (pe_entry->tx.tx_op.op == SOCK_OP_SEND_INJECT ||
	    pe_entry->tx.tx_op.op == SOCK_OP_TSEND_INJECT) {
		offset = pe_entry->done_len - len;
		len += pe_entry->tx.tx_op.src_iov_len;
		
		if (pe_entry->done_len < len) {
			ret = send(conn->sock_fd, 
				   (char*)pe_entry->tx.inject_data + offset,
				   pe_entry->tx.tx_op.src_iov_len - offset, 0);
			
			if (ret < 0) {
				if (ret == EWOULDBLOCK || ret == EAGAIN)
					return 0;
				else{
					SOCK_LOG_ERROR("Failed to send\n");
					return ret;
				}
			}
			
			pe_entry->done_len += ret;
			if (pe_entry->done_len <= len)
				return 0;
		}
	} else {
		data_len = 0;
		done_data = pe_entry->done_len - len;

		for (i=0; i < pe_entry->tx.tx_op.src_iov_len; i++) {
			data_len += pe_entry->tx.tx_iov[i].src.iov.len;
			if (done_data >= pe_entry->tx.tx_iov[i].src.iov.len + data_len) {
				done_data -= data_len;
				continue;
			}

			offset = done_data;
			ret = send(conn->sock_fd, 
				   (char*)pe_entry->tx.tx_iov[i].src.iov.addr + 
				   offset, pe_entry->tx.tx_iov[i].src.iov.len -
				   offset, 0);

			if (ret < 0) {
				if (ret == EWOULDBLOCK || ret == EAGAIN)
					return 0;
				else{
					SOCK_LOG_ERROR("Failed to send\n");
					return ret;
				}
			}
			
			pe_entry->done_len += ret;
			if ( ret != pe_entry->tx.tx_iov[i].src.iov.len - offset)
				return 0;

		}
	}

	if (pe_entry->done_len == pe_entry->total_len) {
		pe_entry->tx.send_done = 1;
		SOCK_LOG_INFO("Send complete\n");

		if (!(pe_entry->flags & FI_REMOTE_COMPLETE)) 
			pe_entry->tx.ack_done = 1;
	}
	return 0;
}

int sock_pe_handle_ack(struct sock_pe *pe, struct sock_pe_entry *pe_entry)
{
	struct sock_pe_entry *waiting_entry;

	assert(pe_entry->msg_hdr.pe_entry_id <= SOCK_PE_MAX_ENTRIES);
	waiting_entry = &pe->pe_table[pe_entry->msg_hdr.pe_entry_id];
	assert(waiting_entry->type == SOCK_PE_TX);
	waiting_entry->is_complete = 1;
	return 0;
}

static int sock_pe_progress_tx_entry(struct sock_pe *pe,
				     struct sock_tx_ctx *tx_ctx,
				     struct sock_pe_entry *pe_entry)
{
	int ret; 
	struct sock_conn *conn = pe_entry->conn;
	if (conn->pe_entry != NULL && conn->pe_entry != pe_entry)
		return 0;

	if (conn->pe_entry == NULL) {
		conn->pe_entry = pe_entry;
	}

	SOCK_LOG_INFO("[%p] Progressing TX entry\n", pe_entry);
	if (!pe_entry->tx.header_sent) {
		ret = send(conn->sock_fd, 
			   (char*)&pe_entry->msg_hdr + pe_entry->done_len,
			   sizeof(struct sock_msg_hdr) - pe_entry->done_len, 0);
		if (ret < 0) {
			if (ret == EWOULDBLOCK || ret == EAGAIN)
				return 0;
			else {
				SOCK_LOG_ERROR("Failed to send\n");
				return ret;
			}
		}

		pe_entry->done_len += ret;
		if (pe_entry->done_len == sizeof(struct sock_msg_hdr)) {
			pe_entry->tx.header_sent = 1;
			SOCK_LOG_INFO("[%p] Header sent\n", pe_entry);
		}else {
			return 0;
		}
	}

	switch (pe_entry->msg_hdr.op_type) {
		
	case SOCK_OP_SEND:
		ret = sock_pe_progress_tx_send(pe, pe_entry, conn);

		if (pe_entry->tx.ack_done) {
			sock_pe_report_tx_completion(pe_entry, tx_ctx);
			pe_entry->is_complete = 1;
		}
		break;

	case SOCK_OP_SEND_COMPLETE:
	case SOCK_OP_WRITE_COMPLETE:
	case SOCK_OP_READ_COMPLETE:
		ret = sock_pe_handle_ack(pe, pe_entry);
		pe_entry->is_complete = 1;
		break;
		
	case SOCK_OP_WRITE:
	case SOCK_OP_READ:
	case SOCK_OP_TSEND:
	case SOCK_OP_ATOMIC:
	case SOCK_OP_SEND_INJECT:
	default:
		ret = -FI_ENOSYS;
		SOCK_LOG_ERROR("Operation not supported\n");
		break;
	}
	
	return ret;
}

static void sock_pe_release_entry(struct sock_pe *pe, 
			struct sock_pe_entry *pe_entry)
{
	dlist_remove(&pe_entry->ctx_entry);
	pe_entry->conn->pe_entry = NULL;
	pe_entry->conn = NULL;

	dlist_remove(&pe_entry->entry);
	dlist_insert_tail(&pe_entry->entry, &pe->free_list);
	SOCK_LOG_INFO("progress entry %p released\n", pe_entry);
}

static struct sock_pe_entry *sock_pe_acquire_entry(struct sock_pe *pe)
{
	struct dlist_entry *entry;
	struct sock_pe_entry *pe_entry;

	entry = pe->free_list.next;
	pe_entry = container_of(entry, struct sock_pe_entry, entry);
	dlist_remove(&pe_entry->entry);
	dlist_insert_tail(&pe_entry->entry, &pe->busy_list);
	SOCK_LOG_INFO("progress entry %p acquired \n", pe_entry);
	return pe_entry;
}

static int sock_pe_new_rx_entry(struct sock_pe *pe, struct sock_rx_ctx *rx_ctx,
				struct sock_ep *ep, struct sock_conn *conn)
{
	struct sock_pe_entry *pe_entry;	
	pe_entry = sock_pe_acquire_entry(pe);
	if (!pe_entry) {
		SOCK_LOG_ERROR("Error in getting PE entry\n");
		return -FI_EINVAL;
	}

	memset(&pe_entry->rx, 0, sizeof(struct sock_rx_pe_entry));

	pe_entry->conn = conn;
	pe_entry->type = SOCK_PE_RX;
	pe_entry->ep = ep;
	pe_entry->is_complete = 0;
	pe_entry->done_len = 0;

	SOCK_LOG_INFO("Inserting rx_entry to PE entry %p, conn: %p\n",
		      pe_entry, pe_entry->conn);

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
	if (!pe_entry) {
		SOCK_LOG_ERROR("Failed to get free PE entry \n");
		return -FI_EINVAL;
	}

	memset(&pe_entry->tx, 0, sizeof(struct sock_tx_pe_entry));

	pe_entry->type = SOCK_PE_TX;
	pe_entry->is_complete = 0;
	pe_entry->done_len = 0;
	pe_entry->conn = NULL;
	pe_entry->ep = tx_ctx->ep;

	dlist_insert_tail(&pe_entry->ctx_entry, &tx_ctx->pe_entry_list);

	/* fill in PE tx entry */
	memset(&pe_entry->msg_hdr, 0, sizeof(struct sock_msg_hdr));
	msg_hdr = &pe_entry->msg_hdr;
	msg_hdr->msg_len = sizeof(struct sock_msg_hdr);

	rbfdread(&tx_ctx->rbfd, &pe_entry->tx.tx_op, sizeof(struct sock_op));
	rbfdread(&tx_ctx->rbfd, &pe_entry->flags, sizeof(uint64_t));
	rbfdread(&tx_ctx->rbfd, &pe_entry->context, sizeof(uint64_t));
	rbfdread(&tx_ctx->rbfd, &pe_entry->addr, sizeof(uint64_t));
	rbfdread(&tx_ctx->rbfd, &pe_entry->conn, sizeof(uint64_t));

	if (pe_entry->flags & FI_REMOTE_CQ_DATA) {
		rbfdread(&tx_ctx->rbfd, &pe_entry->data, sizeof(uint64_t));
		msg_hdr->msg_len += sizeof(uint64_t);
	}

	if (pe_entry->tx.tx_op.op == SOCK_OP_TSEND ||
		pe_entry->tx.tx_op.op == SOCK_OP_TSEND_INJECT) {
		rbfdread(&tx_ctx->rbfd, &pe_entry->tag, sizeof(uint64_t));
		msg_hdr->msg_len += sizeof(uint64_t);
	}

	if (pe_entry->tx.tx_op.op == SOCK_OP_SEND_INJECT ||
		pe_entry->tx.tx_op.op == SOCK_OP_TSEND_INJECT) {
		rbfdread(&tx_ctx->rbfd, &pe_entry->tx.inject_data[0],
			 pe_entry->tx.tx_op.src_iov_len);
		msg_hdr->msg_len += pe_entry->tx.tx_op.src_iov_len;
	}else {
		/* read src iov(s)*/
		for (i = 0; i<pe_entry->tx.tx_op.src_iov_len; i++) {
			rbfdread(&tx_ctx->rbfd, &pe_entry->tx.tx_iov[i].src, 
				 sizeof(union sock_iov));
			msg_hdr->msg_len += pe_entry->tx.tx_iov[i].src.iov.len;
		}

		/* read dst iov(s)*/
		for (i = 0; i<pe_entry->tx.tx_op.dest_iov_len; i++) {
			rbfdread(&tx_ctx->rbfd, &pe_entry->tx.tx_iov[i].dst, 
			       sizeof(union sock_iov));
			msg_hdr->msg_len += pe_entry->tx.tx_iov[i].dst.iov.len;
		}
	}

	SOCK_LOG_INFO("Inserting TX-entry to PE entry %p, conn: %p\n",
		      pe_entry, pe_entry->conn);

	/* prepare message header */
	msg_hdr->version = htons(SOCK_WIRE_PROTO_VERSION);

	switch (pe_entry->tx.tx_op.op) {
	case SOCK_OP_SEND:
	case SOCK_OP_SEND_INJECT:
		msg_hdr->op_type = htons(SOCK_OP_TSEND);
		break;

	case SOCK_OP_TSEND:
	case SOCK_OP_TSEND_INJECT:
		msg_hdr->op_type = htons(SOCK_OP_SEND);
		break;

	default:
		SOCK_LOG_ERROR("Invalid op type\n");
		return -FI_EINVAL;
	}

	/* FIXME: double check */
	msg_hdr->rx_id = htonl(SOCK_GET_RX_ID(pe_entry->addr, 
					      tx_ctx->av->rx_ctx_bits));
	msg_hdr->flags = htonl(pe_entry->flags);
	pe_entry->total_len = msg_hdr->msg_len;
	msg_hdr->msg_len = htonl(msg_hdr->msg_len);
	return 0;
}

int sock_pe_add_tx_ctx(struct sock_pe *pe, struct sock_tx_ctx *ctx)
{
	fastlock_acquire(&pe->lock);
	dlistfd_insert_tail(&ctx->pe_entry, &pe->tx_list);
	fastlock_release(&pe->lock);
	SOCK_LOG_INFO("TX ctx added to PE\n");
	return 0;
}

int sock_pe_add_rx_ctx(struct sock_pe *pe, struct sock_rx_ctx *ctx)
{
	fastlock_acquire(&pe->lock);
	dlistfd_insert_tail(&ctx->pe_entry, &pe->rx_list);
	fastlock_release(&pe->lock);
	SOCK_LOG_INFO("RX ctx added to PE\n");
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
	struct sock_conn_map *map;

	poll_fd.events = POLLIN;
	fastlock_acquire(&pe->lock);

	/* check for incoming data */
	for (entry = rx_ctx->ep_list.next;
	    entry != &rx_ctx->ep_list; entry = entry->next) {

		ep = container_of(entry, struct sock_ep, rx_ctx_entry);

		map = &ep->domain->r_cmap;

/*
		if (!ep->av)
			continue;
*/

		for (i=0; i<map->used; i++) {
			conn = &map->table[i];

/*
			if (!ep->av->key_table[i]) continue;
			sock_conn_map_lookup_key(ep->av->cmap, 
						 ep->av->key_table[i], &conn);
*/

			poll_fd.fd = conn->sock_fd;
			ret = poll(&poll_fd, 1, 0);
			if (ret < 0) {
				SOCK_LOG_INFO("Error polling fd: %d\n", conn->sock_fd);
				goto out;
			}

			if (ret == 1) {
				/* new RX PE entry */
				ret = sock_pe_new_rx_entry(pe, rx_ctx, ep, conn);
				if (ret < 0) 
					goto out;
			}
		}
	}

	/* progress tx_ctx in PE table */
	for (entry = rx_ctx->pe_entry_list.next;
	    entry != &rx_ctx->pe_entry_list;) {
		
		pe_entry = container_of(entry, struct sock_pe_entry, ctx_entry);
		entry = entry->next;
		ret = sock_pe_progress_rx_entry(pe, pe_entry);
		if (ret < 0) 
			goto out;

		if (pe_entry->rx.recv_done) {
			ret = sock_pe_process_recv(pe, rx_ctx, pe_entry);
			if (ret < 0) 
				goto out;
		}

		if (pe_entry->is_complete) {
			sock_pe_release_entry(pe, pe_entry);
			SOCK_LOG_INFO("[%p] RX done\n", pe_entry);
		}
	}
		
out:	
	if (ret < 0) 
		SOCK_LOG_ERROR("failed to progress RX ctx\n");
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
	while (!rbfdempty(&tx_ctx->rbfd) && 
	      !dlist_empty(&pe->free_list)) {
		/* new TX PE entry */
		ret = sock_pe_new_tx_entry(pe, tx_ctx);
		if (ret < 0) {
			fastlock_release(&tx_ctx->rlock);
			goto out;
		}
	}
	fastlock_release(&tx_ctx->rlock);

	/* progress tx_ctx in PE table */
	for (entry = tx_ctx->pe_entry_list.next;
	    entry != &tx_ctx->pe_entry_list;) {
		
		pe_entry = container_of(entry, struct sock_pe_entry, ctx_entry);
		entry = entry->next;

		ret = sock_pe_progress_tx_entry(pe, tx_ctx, pe_entry);
		if (ret < 0) {
			SOCK_LOG_ERROR("Error in progressing %p\n", pe_entry);
			goto out;
		}
			
		if (pe_entry->is_complete) {
			sock_pe_release_entry(pe, pe_entry);
			SOCK_LOG_INFO("[%p] TX done\n", pe_entry);
		}
	}
		
out:	
	if (ret < 0) 
		SOCK_LOG_ERROR("failed to progress TX ctx\n");
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

	SOCK_LOG_INFO("Progress thread started\n");

	fds[0].events = POLLIN;
	fds[0].fd = pe->tx_list.fd[LIST_READ_FD];

	fds[1].events = POLLIN;	
	fds[1].fd = pe->rx_list.fd[LIST_READ_FD];
	
	while (pe->do_progress) {

		if (dlistfd_empty(&pe->tx_list) &&
		   dlistfd_empty(&pe->rx_list)) {
			ret = poll(fds, 2, SOCK_PE_POLL_TIMEOUT);
			if (ret == 0)
				continue;
		}

		/* progress tx */
		if (!dlistfd_empty(&pe->tx_list)) {
			for (entry = pe->tx_list.list.next;
			    entry != &pe->tx_list.list; entry = entry->next) {
				tx_ctx = container_of(entry, struct sock_tx_ctx,
						      pe_entry);
				ret = sock_pe_progress_tx_ctx(pe, tx_ctx);
				if (ret < 0) {
					SOCK_LOG_ERROR(
						   "failed to progress TX\n");
					return NULL;
				}
			}
		}

		/* progress rx */
		if (!dlistfd_empty(&pe->rx_list)) {
			for (entry = pe->rx_list.list.next;
			    entry != &pe->rx_list.list; entry = entry->next) {
				rx_ctx = container_of(entry, struct sock_rx_ctx,
						      pe_entry);
				ret = sock_pe_progress_rx_ctx(pe, rx_ctx);
				if (ret < 0) {
					SOCK_LOG_ERROR(
						   "failed to progress RX\n");
					return NULL;
				}
			}
		}
	}
	
	SOCK_LOG_INFO("Progress thread terminated\n");
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

	for (i=0; i<SOCK_PE_MAX_ENTRIES; i++) {
		dlist_insert_tail(&pe->pe_table[i].entry, &pe->free_list);
	}

	SOCK_LOG_INFO("PE table init: OK\n");
}

struct sock_pe *sock_pe_init(struct sock_domain *domain)
{
	struct sock_pe *pe = calloc(1, sizeof(struct sock_pe));
	if (!pe)
		return NULL;

	sock_pe_init_table(pe);

	dlistfd_head_init(&pe->tx_list);
	dlistfd_head_init(&pe->rx_list);
	fastlock_init(&pe->lock);

	pe->do_progress = 1;
	if (pthread_create(&pe->progress_thread, NULL, sock_pe_progress_thread,
			  (void *)pe)) {
		SOCK_LOG_ERROR("Couldn't create progress thread\n");
		goto err;
	}
	SOCK_LOG_INFO("PE init: OK\n");
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
	SOCK_LOG_INFO("Progress engine finalize: OK\n");
}

