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

#include <stdlib.h>
#include <string.h>

#include <sys/socket.h>
#include <sys/types.h>

#include "sock.h"

static ssize_t sock_cq_read(struct fid_cq *cq, void *buf, size_t len)
{
	return -FI_ENOSYS;
}

static ssize_t sock_cq_readfrom(struct fid_cq *cq, void *buf, size_t len,
				fi_addr_t *src_addr)
{
	return -FI_ENOSYS;
}

static ssize_t sock_cq_readerr(struct fid_cq *cq, struct fi_cq_err_entry *buf,
			       size_t len, uint64_t flags)
{
	return -FI_ENOSYS;
}

static ssize_t sock_cq_write(struct fid_cq *cq, const void *buf, size_t len)
{
	return -FI_ENOSYS;
}

static ssize_t sock_cq_sread(struct fid_cq *cq, void *buf, size_t len,
				const void *cond, int timeout)
{
	return -FI_ENOSYS;
}

static ssize_t sock_cq_sreadfrom(struct fid_cq *cq, void *buf, size_t len,
				    fi_addr_t *src_addr, const void *cond, int timeout)
{
	return -FI_ENOSYS;
}

static const char * sock_cq_strerror(struct fid_cq *cq, int prov_errno,
				     const void *err_data, void *buf, size_t len)
{
	return NULL;
}

static int sock_cq_close(struct fid *fid)
{
	sock_cq_t *cq;

	cq = container_of(fid, sock_cq_t, cq_fid.fid);
	if (atomic_get(&cq->ref))
		return -FI_EBUSY;

	close(cq->fd[SOCK_WR_FD]);
	close(cq->fd[SOCK_RD_FD]);
	free(cq);
	return 0;
}

static struct fi_ops_cq sock_cq_ops = {
	.read = sock_cq_read,
	.readfrom = sock_cq_readfrom,
	.readerr = sock_cq_readerr,
	.write = sock_cq_write,
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
	case FI_WAIT_UNSPECIFIED:
		attr->wait_obj = FI_WAIT_FD;
		break;
	default:
		return -FI_ENOSYS;
	}

	return 0;
}

int sock_cq_open(struct fid_domain *domain, struct fi_cq_attr *attr,
		 struct fid_cq **cq, void *context)
{
	sock_domain_t *dom;
	sock_cq_t *_cq;
	int ret;

	ret = sock_cq_verify_attr(attr);
	if (ret)
		return ret;

	_cq = calloc(1, sizeof(*_cq));
	if (!_cq)
		return -FI_ENOMEM;

	ret = socketpair(AF_UNIX, 0, 0, _cq->fd);
	if (ret){
		ret = -ret;
		goto err1;
	}

	ret = socketpair(AF_UNIX, 0, 0, _cq->error_fd);
	if (ret){
		ret = -ret;
		goto err2;
	}

	atomic_init(&_cq->ref);
	_cq->cq_fid.fid.fclass = FI_CLASS_CQ;
	_cq->cq_fid.fid.context = context;
	_cq->cq_fid.fid.ops = &sock_cq_fi_ops;
	_cq->cq_fid.ops = &sock_cq_ops;

	dom = container_of(domain, sock_domain_t, dom_fid);
	atomic_inc(&dom->ref);

	_cq->ep_list = new_list(64);
	if(!_cq->ep_list){
		ret = -FI_ENOMEM;
		goto err2;
	}

	_cq->domain = dom;
	_cq->format = attr->format;
	*cq = &_cq->cq_fid;
	return 0;

err2:
	close(_cq->fd[0]);
	close(_cq->fd[1]);

err1:
	free(_cq);
	return ret;
}

static uint64_t sock_cntr_read(struct fid_cntr *cntr)
{
	sock_cntr_t *_cntr;
	_cntr = container_of(cntr, sock_cntr_t, cntr_fid);
	return _cntr->value;
}

static int sock_cntr_add(struct fid_cntr *cntr, uint64_t value)
{
	sock_cntr_t *_cntr;

	_cntr = container_of(cntr, sock_cntr_t, cntr_fid);
	pthread_mutex_lock(&_cntr->mut);
	_cntr->value += value;
	if (_cntr->value >= _cntr->threshold)
		pthread_cond_signal(&_cntr->cond);
	pthread_mutex_unlock(&_cntr->mut);
	return 0;
}

static int sock_cntr_set(struct fid_cntr *cntr, uint64_t value)
{
	sock_cntr_t *_cntr;

	_cntr = container_of(cntr, sock_cntr_t, cntr_fid);
	pthread_mutex_lock(&_cntr->mut);
	_cntr->value = value;
	if (_cntr->value >= _cntr->threshold)
		pthread_cond_signal(&_cntr->cond);
	pthread_mutex_unlock(&_cntr->mut);
	return 0;
}

static int sock_cntr_wait(struct fid_cntr *cntr, uint64_t threshold, int timeout)
{
	sock_cntr_t *_cntr;
	int ret = 0;

	_cntr = container_of(cntr, sock_cntr_t, cntr_fid);
	pthread_mutex_lock(&_cntr->mut);
	_cntr->threshold = threshold;
	while (_cntr->value < _cntr->threshold && !ret)
		ret = fi_wait_cond(&_cntr->cond, &_cntr->mut, timeout);
	_cntr->threshold = ~0;
	pthread_mutex_unlock(&_cntr->mut);
	return ret;
}

static int sock_cntr_close(struct fid *fid)
{
	sock_cntr_t *cntr;

	cntr = container_of(fid, sock_cntr_t, cntr_fid.fid);
	if (atomic_get(&cntr->ref))
		return -FI_EBUSY;
	
	pthread_mutex_destroy(&cntr->mut);
	pthread_cond_destroy(&cntr->cond);
	atomic_dec(&cntr->dom->ref);
	free(cntr);
	return 0;
}

static struct fi_ops_cntr sock_cntr_ops = {
	.size = sizeof(struct fi_ops_cntr),
	.read = sock_cntr_read,
	.add = sock_cntr_add,
	.set = sock_cntr_set,
	.wait = sock_cntr_wait,
};

static struct fi_ops sock_cntr_fi_ops = {
	.size = sizeof(struct fi_ops),
	.close = sock_cntr_close,
};

int sock_cntr_open(struct fid_domain *domain, struct fi_cntr_attr *attr,
		   struct fid_cntr **cntr, void *context)
{
	sock_domain_t *dom;
	sock_cntr_t *_cntr;
	int ret;

	if ((attr->events != FI_CNTR_EVENTS_COMP) ||
	    (attr->wait_obj != FI_WAIT_MUT_COND) || attr->flags)
		return -FI_ENOSYS;

	_cntr = calloc(1, sizeof(*_cntr));
	if (!_cntr)
		return -FI_ENOMEM;

	ret = pthread_cond_init(&_cntr->cond, NULL);
	if (ret)
		goto err1;

	ret = pthread_mutex_init(&_cntr->mut, NULL);
	if (ret)
		goto err2;

	atomic_init(&_cntr->ref);
	_cntr->cntr_fid.fid.fclass = FI_CLASS_CNTR;
	_cntr->cntr_fid.fid.context = context;
	_cntr->cntr_fid.fid.ops = &sock_cntr_fi_ops;
	_cntr->cntr_fid.ops = &sock_cntr_ops;
	_cntr->threshold = ~0;

	dom = container_of(domain, sock_domain_t, dom_fid);
	atomic_inc(&dom->ref);
	_cntr->dom = dom;
	*cntr = &_cntr->cntr_fid;
	return 0;

err2:
	pthread_cond_destroy(&_cntr->cond);
err1:
	free(_cntr);
	return -ret;
}

#define SOCK_PROGRESS_SENDS (0x1<<0)
#define SOCK_PROGRESS_RECVS (0x1<<1)

int sock_progress_recvs(sock_cq_t *cq)
{
	return 0;
}

int sock_progress_sends(sock_cq_t *cq)
{
	return 0;
}

int sock_progress_engine(sock_cq_t *cq, uint64_t flags)
{
	int ret;
	if(flags & SOCK_PROGRESS_SENDS){
		ret = sock_progress_sends(cq);
		if(ret)
			return ret;
	}
		
	if(flags & SOCK_PROGRESS_RECVS){
		ret = sock_progress_recvs(cq);
		if(ret)
			return ret;
	}

	return 0;
}

int _sock_cq_report_cq(sock_cq_t *sock_cq, 
		    const void *data, size_t len)
{
	ssize_t ret, remaining = len;

	do{
		ret = write(sock_cq->fd[SOCK_WR_FD], data, remaining);
		if(ret > 0){
			remaining -= ret;
		}else if (ret == EWOULDBLOCK || ret == EAGAIN){
			continue;
		}else{
			return -1;
		}
	}while(remaining>0);
	return 0;
}

int _sock_cq_report_cq_err(sock_cq_t *sock_cq, 
		    const void *data, size_t len)
{
	ssize_t ret, remaining = len;

	do{
		ret = write(sock_cq->error_fd[SOCK_WR_FD], data, remaining);
		if(ret > 0){
			remaining -= ret;
		}else if (ret == EWOULDBLOCK || ret == EAGAIN){
			continue;
		}else{
			return -1;
		}
	}while(remaining>0);
	return 0;
}

int sock_cq_report(sock_cq_t *sock_cq, 
		   struct fi_cq_tagged_entry *in_report)
{
	int ret;
	switch(sock_cq->format){

	case FI_CQ_FORMAT_CONTEXT:
	{
		struct fi_cq_entry report;
		report.op_context = in_report->op_context;
		return _sock_cq_report(sock_cq, &report, sizeof(struct fi_cq_entry));
	}

	case FI_CQ_FORMAT_MSG:
	{
		struct fi_cq_msg_entry report;
	}

	/* TODO: add support for other format types */
	case FI_CQ_FORMAT_DATA:
	case FI_CQ_FORMAT_TAGGED:
	default:
		return -1;
	}
	return 0;
}

int sock_cq_report_send_completion(sock_cq_t *sock_cq, 
				   void *comm_item)
{
}

int sock_cq_report_recv_completion(sock_cq_t *sock_cq, 
			       int comm_type, void *item)
{
	return 0;
}

int sock_cq_report_error(sock_cq_t *sock_cq, struct fi_cq_err_entry *error)
{
	return 0;
}
