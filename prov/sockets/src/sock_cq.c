/*
 * Copyright (c) 2014 Intel Corporation, Inc.  All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * OpenIB.org BSD license below:
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/time.h>

#include <sys/socket.h>
#include <sys/types.h>

#include <fi_list.h>

#include "sock.h"
#include "sock_util.h"


static ssize_t sock_cq_entry_size(struct sock_cq *sock_cq)
{
	ssize_t size;

	switch(sock_cq->attr.format){
	case FI_CQ_FORMAT_CONTEXT:
		size = sizeof(struct fi_cq_entry);
		break;

	case FI_CQ_FORMAT_MSG:
		size = sizeof(struct fi_cq_msg_entry);
		break;

	case FI_CQ_FORMAT_DATA:
		size = sizeof(struct fi_cq_data_entry);
		break;

	case FI_CQ_FORMAT_TAGGED:
		size = sizeof(struct fi_cq_tagged_entry);
		break;

	case FI_CQ_FORMAT_UNSPEC:
	default:
		size = -1;
		sock_debug(SOCK_ERROR, "Invalid CQ format\n");
		break;
	}
	return size;
}

ssize_t sock_cq_sreadfrom(struct fid_cq *cq, void *buf, size_t count,
			fi_addr_t *src_addr, const void *cond, int timeout)
{
	fi_addr_t addr;
	int64_t threshold;
	ssize_t i, bytes_read, num_read, cq_entry_len;
	struct sock_cq *sock_cq;
	
	sock_cq = container_of(cq, struct sock_cq, cq_fid);
	if(!sock_cq)
		return -FI_EINVAL;

	if (sock_cq->attr.wait_cond == FI_CQ_COND_THRESHOLD){
		threshold = min((int64_t)cond, count);
	}else{
		threshold = count;
	}

	cq_entry_len = sock_cq_entry_size(sock_cq);
	bytes_read = rbfdsread(&sock_cq->cq_rbfd, buf, 
			       cq_entry_len*threshold, timeout);
	num_read = bytes_read/cq_entry_len;

	for(i=0; i<num_read; i++){
		rbread(&sock_cq->addr_rb, &addr, sizeof(fi_addr_t));
		if(src_addr)
			src_addr[i] = addr;
	}	
	return num_read;
}

ssize_t sock_cq_readfrom(struct fid_cq *cq, void *buf, size_t count,
			fi_addr_t *src_addr)
{
	return sock_cq_sreadfrom(cq, buf, count, src_addr, NULL, 0);
}

static ssize_t sock_cq_read(struct fid_cq *cq, void *buf, size_t count)
{
	return sock_cq_readfrom(cq, buf, count, NULL);
}

static ssize_t sock_cq_readerr(struct fid_cq *cq, struct fi_cq_err_entry *buf,
			       size_t len, uint64_t flags)
{
	ssize_t num_read;
	struct sock_cq *sock_cq;
	
	sock_cq = container_of(cq, struct sock_cq, cq_fid);
	if(!sock_cq)
		return -FI_ENOENT;
	
	if(len < sizeof(struct fi_cq_err_entry))
		return -FI_ETOOSMALL;

	num_read = 0;
	while(rbused(&sock_cq->cqerr_rb) >= sizeof(struct fi_cq_err_entry)){
		rbread(&sock_cq->cqerr_rb, 
		       (char*)buf +sizeof(struct fi_cq_err_entry) * num_read, 
		       sizeof(struct fi_cq_err_entry));
		num_read++;
	}
	return num_read;
}

static ssize_t sock_cq_write(struct fid_cq *cq, const void *buf, size_t len)
{
	ssize_t ret;
	struct sock_cq *sock_cq;
	
	sock_cq = container_of(cq, struct sock_cq, cq_fid);
	if(!sock_cq)
		return -FI_ENOENT;

	if(!(sock_cq->attr.flags & FI_WRITE))
		return -FI_EINVAL;
	
	ret = min(rbfdavail(&sock_cq->cq_rbfd), len);
	rbfdwrite(&sock_cq->cq_rbfd, buf, ret);
	return ret;
}

static ssize_t sock_cq_sread(struct fid_cq *cq, void *buf, size_t len,
			     const void *cond, int timeout)
{
	return sock_cq_sreadfrom(cq, buf, len, NULL, cond, timeout);
}

static const char * sock_cq_strerror(struct fid_cq *cq, int prov_errno,
				     const void *err_data, void *buf, size_t len)
{
	if (buf && len)
		strncpy(buf, strerror(prov_errno), len);
	return strerror(prov_errno);
}

static int sock_cq_close(struct fid *fid)
{
	struct sock_cq *cq;

	cq = container_of(fid, struct sock_cq, cq_fid.fid);
	if(!cq)
		return -FI_EINVAL;

	if (atomic_get(&cq->ref))
		return -FI_EBUSY;

	rbfree(&cq->addr_rb);
	rbfree(&cq->cqerr_rb);
	rbfdfree(&cq->cq_rbfd);

	fastlock_destroy(&cq->cq_lock);
	fastlock_destroy(&cq->cqerr_lock);
	atomic_dec(&cq->domain->ref);

	free(cq);
	return 0;
}

ssize_t sock_cq_writeerr(struct fid_cq *cq, struct fi_cq_err_entry *buf,
			size_t len, uint64_t flags)
{
	ssize_t ret;
	struct sock_cq *sock_cq;
	
	sock_cq = container_of(cq, struct sock_cq, cq_fid);
	if(!sock_cq)
		return -FI_ENOENT;
	
	if(!(sock_cq->attr.flags & FI_WRITE))
		return -FI_EINVAL;
	
	ret = min(rbavail(&sock_cq->cqerr_rb), len);
	rbfdwrite(&sock_cq->cq_rbfd, buf, ret);
	return ret;
}

static struct fi_ops_cq sock_cq_ops = {
	.read = sock_cq_read,
	.readfrom = sock_cq_readfrom,
	.readerr = sock_cq_readerr,
	.write = sock_cq_write,
	.writeerr = sock_cq_writeerr,
	.sread = sock_cq_sread,
	.sreadfrom = sock_cq_sreadfrom,
	.strerror = sock_cq_strerror,
};

static struct fi_ops sock_cq_fi_ops = {
	.size = sizeof(struct fi_ops),
	.close = sock_cq_close,
};

static int sock_cq_verify_attr(struct fi_cq_attr *attr)
{
	if(!attr)
		return 0;

	switch (attr->format) {
	case FI_CQ_FORMAT_CONTEXT:
	case FI_CQ_FORMAT_MSG:
	case FI_CQ_FORMAT_DATA:
	case FI_CQ_FORMAT_TAGGED:
		break;
	default:
		return -FI_ENOSYS;
	}

	switch (attr->wait_obj) {
	case FI_WAIT_NONE:
	case FI_WAIT_FD:
		break;
	case FI_WAIT_UNSPEC:
		attr->wait_obj = FI_WAIT_FD;
		break;
	default:
		return -FI_ENOSYS;
	}

	return 0;
}

static struct fi_cq_attr _sock_cq_def_attr = {
	.size = SOCK_CQ_DEF_LEN,
	.flags = 0,
	.format = FI_CQ_FORMAT_CONTEXT,
	.wait_obj = FI_WAIT_FD,
	.signaling_vector = 0,
	.wait_cond = FI_CQ_COND_NONE,
	.wait_set = NULL,
};

int sock_cq_open(struct fid_domain *domain, struct fi_cq_attr *attr,
		 struct fid_cq **cq, void *context)
{
	struct sock_domain *sock_dom;
	struct sock_cq *sock_cq;
	int ret;

	sock_dom = container_of(domain, struct sock_domain, dom_fid);
	if(!sock_dom)
		return -FI_EINVAL;
	
	ret = sock_cq_verify_attr(attr);
	if (ret)
		return ret;

	sock_cq = calloc(1, sizeof(*sock_cq));
	if (!sock_cq)
		return -FI_ENOMEM;
	
	atomic_init(&sock_cq->ref);
	sock_cq->cq_fid.fid.fclass = FI_CLASS_CQ;
	sock_cq->cq_fid.fid.context = context;
	sock_cq->cq_fid.fid.ops = &sock_cq_fi_ops;
	sock_cq->cq_fid.ops = &sock_cq_ops;
	atomic_inc(&sock_dom->ref);

	if(attr == NULL)
		memcpy(&sock_cq->attr, &_sock_cq_def_attr, 
		       sizeof(struct fi_cq_attr));
	else
		memcpy(&sock_cq->attr, attr, sizeof(struct fi_cq_attr));
	
	sock_cq->domain = sock_dom;
	sock_cq->cq_entry_size = sock_cq_entry_size(sock_cq);

	dlist_init(&sock_cq->tx_ctx_head.list);
	dlist_init(&sock_cq->rx_ctx_head.list);
	dlist_init(&sock_cq->pe_entry_head.list);

	if((ret = rbfdinit(&sock_cq->cq_rbfd, sock_cq->attr.size)))
		goto err1;

	if((ret = rbinit(&sock_cq->addr_rb, sock_cq->attr.size)))
		goto err2;

	if((ret = rbinit(&sock_cq->cqerr_rb, sock_cq->attr.size)))
		goto err3;

	fastlock_init(&sock_cq->cq_lock);
	fastlock_init(&sock_cq->cqerr_lock);

	*cq = &sock_cq->cq_fid;
	atomic_inc(&sock_dom->ref);
	return 0;

err3:
	rbfree(&sock_cq->addr_rb);

err2:
	rbfdfree(&sock_cq->cq_rbfd);

err1:
	   free(sock_cq);
	   return ret;
}

int _sock_cq_report_completion(struct sock_cq *sock_cq, 
			      struct sock_req_item *item)
{
	char byte;
	write(sock_cq->fd[SOCK_WR_FD], &byte, 1);
	return enqueue_item(sock_cq->completed_list, item);
}

int _sock_cq_report_error(struct sock_cq *sock_cq, 
			  struct fi_cq_err_entry *error)
{
	char byte;
	write(sock_cq->fd[SOCK_WR_FD], &byte, 1);
	return enqueue_item(sock_cq->error_list, error);
}

int sock_cq_report_completion(struct sock_cq *cq, 
				 struct sock_pe_entry *pe_entry)
{
	size_t i, msg_len, iov_len;
	size_t cq_entry_size = sock_cq_entry_size(cq);
	if(rbfdavail(&cq->cq_rbfd) < cq_entry_size)
		return -FI_ENOSPC;

	switch (cq->attr.format){
	case FI_CQ_FORMAT_CONTEXT:
	{
		struct fi_cq_entry cq_entry;
		cq_entry.op_context = (void*)pe_entry->context;

		rbfdwrite(&cq->cq_rbfd, (void*)&cq_entry, cq_entry_size);
		break;
	}
		
	case FI_CQ_FORMAT_MSG:
	{
		struct fi_cq_msg_entry cq_entry;
		cq_entry.op_context = (void*)pe_entry->context;
		cq_entry.flags = pe_entry->flags;

		msg_len = 0;
		iov_len = (pe_entry->type == SOCK_RX) ? 
			pe_entry->rx.rx_op.src_iov_len :
			pe_entry->tx.tx_op.src_iov_len;
		for(i=0;i<iov_len; i++)
			msg_len += pe_entry->rx.rx_iov[i].iov.len;
		cq_entry.len = msg_len;

		rbfdwrite(&cq->cq_rbfd, (void*)&cq_entry, cq_entry_size);
		break;
	}

	case FI_CQ_FORMAT_DATA:
	{
		struct fi_cq_data_entry cq_entry;
		cq_entry.op_context = (void*)pe_entry->context;
		cq_entry.flags = pe_entry->flags;

		msg_len = 0;
		iov_len = (pe_entry->type == SOCK_RX) ? 
			pe_entry->rx.rx_op.src_iov_len :
			pe_entry->tx.tx_op.src_iov_len;
		for(i=0;i<iov_len; i++)
			msg_len += pe_entry->rx.rx_iov[i].iov.len;
		cq_entry.len = msg_len;

		cq_entry.buf = (void*)pe_entry->rx.rx_iov[0].iov.addr;
		cq_entry.data = pe_entry->data;

		rbfdwrite(&cq->cq_rbfd, (void*)&cq_entry, cq_entry_size);
		break;
	}

	case FI_CQ_FORMAT_TAGGED:
	{
		struct fi_cq_tagged_entry cq_entry;
		cq_entry.op_context = (void*)pe_entry->context;
		cq_entry.flags = pe_entry->flags;

		msg_len = 0;
		iov_len = (pe_entry->type == SOCK_RX) ? 
			pe_entry->rx.rx_op.src_iov_len :
			pe_entry->tx.tx_op.src_iov_len;
		for(i=0;i<iov_len; i++)
			msg_len += pe_entry->rx.rx_iov[i].iov.len;
		cq_entry.len = msg_len;

		cq_entry.buf = (void*)pe_entry->rx.rx_iov[0].iov.addr;
		cq_entry.data = pe_entry->data;
		cq_entry.tag = pe_entry->tag;

		rbfdwrite(&cq->cq_rbfd, (void*)&cq_entry, cq_entry_size);
		break;
	}

	default:
		sock_debug(SOCK_ERROR, "CQ: Invalid format\n");
		return -FI_EINVAL;
	}

	rbfdcommit(&cq->cq_rbfd);
	return 0;
}

int sock_cq_report_error(struct sock_cq *cq, struct sock_pe_entry *entry,
			 size_t olen, int err, int prov_errno, void *err_data)
{
	struct fi_cq_err_entry err_entry;

	if(rbavail(&cq->cqerr_rb) < sizeof(struct fi_cq_err_entry))
		return -1;

	err_entry.err = err;
	err_entry.olen = olen;
	err_entry.err_data = err_data;
	err_entry.len = entry->done_len;
	err_entry.prov_errno = prov_errno;

	switch(entry->type){
	case SOCK_RX:
		err_entry.flags = entry->flags;
		err_entry.buf = (void*)entry->rx.rx_iov[0].iov.addr;
		err_entry.data = entry->data;
		err_entry.tag = entry->tag;
		err_entry.op_context = (void*)entry->context;
		break;

	case SOCK_TX:
		err_entry.flags = entry->flags;
		err_entry.buf = (void*)entry->tx.src_iov[0].iov.addr;
		err_entry.data = entry->data;
		err_entry.tag = entry->tag;
		err_entry.op_context = (void*)entry->context;
		break;
	default:
		sock_debug(SOCK_ERROR, "CQ: Invalid error type\n");
		return -FI_EINVAL;
	}

	rbwrite(&cq->cqerr_rb, &err_entry, sizeof(struct fi_cq_err_entry));
	rbcommit(&cq->cqerr_rb);
	return 0;
}


struct sock_rx_entry *sock_cq_get_rx_buffer(struct sock_cq *cq, uint64_t addr, 
					    uint16_t rx_id, int ignore_tag, uint64_t tag)
{
	struct dlist_entry *head_ctx, *curr_ctx;
	struct dlist_entry *head_entry, *curr_entry;
	struct sock_rx_ctx *rx_ctx;
	struct sock_rx_entry *rx_entry;

	head_ctx = &cq->rx_ctx_head.list;
	for(curr_ctx = head_ctx->next; !dlist_empty(head_ctx) &&
		    curr_ctx != head_ctx; curr_ctx = curr_ctx->next){

		rx_ctx = container_of(curr_ctx, struct sock_rx_ctx, list);
		if(rx_ctx->rx_id != rx_id)
			continue;
		
		head_entry = &rx_ctx->rx_entry_head.list;
		for(curr_entry = head_entry->next; !dlist_empty(head_entry) &&
			    curr_entry != head_entry; curr_entry = curr_entry->next){
			
			rx_entry = container_of(curr_entry, struct sock_rx_entry, list);
			if(rx_entry->addr == addr){

				if(!ignore_tag){
					if(rx_entry->valid_tag && rx_entry->tag == tag){
						rx_entry->list.prev->next = rx_entry->list.next;
						return rx_entry;
					}
				}else{
					rx_entry->list.prev->next = rx_entry->list.next;
					return rx_entry;
				}
			}
		}
	}
	return NULL;
}
