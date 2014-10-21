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

#include <rdma/fabric.h>
#include <rdma/fi_atomic.h>
#include <rdma/fi_cm.h>
#include <rdma/fi_domain.h>
#include <rdma/fi_endpoint.h>
#include <rdma/fi_eq.h>
#include <rdma/fi_errno.h>
#include <rdma/fi_prov.h>
#include <rdma/fi_rma.h>
#include <rdma/fi_tagged.h>
#include <rdma/fi_trigger.h>

#include "fi.h"
#include "fi_enosys.h"
#include "indexer.h"
#include "list.h"

#ifndef _SOCK_H_
#define _SOCK_H_

#define SOCK_EP_MAX_MSG_SZ (1<<22)
#define SOCK_EP_MAX_INJECT_SZ (1<<12)
#define SOCK_EP_MAX_BUFF_RECV (1<<22)
#define SOCK_EP_MAX_ORDER_RAW_SZ (0)
#define SOCK_EP_MAX_ORDER_WAR_SZ (0)
#define SOCK_EP_MAX_ORDER_WAW_SZ (0)
#define SOCK_EP_MEM_TAG_FMT (0)
#define SOCK_EP_MSG_ORDER (0)
#define SOCK_EP_TX_CTX_CNT (0)
#define SOCK_EP_RX_CTX_CNT (0)
#define SOCK_EP_MAX_IOV_LIMIT (1)

#define SOCK_EP_BACKLOG (8)
#define SOCK_EP_SNDQ_LEN (128)
#define SOCK_EP_RCVQ_LEN (128)

#define SOCK_EQ_DEF_LEN (128)
#define SOCK_CQ_DEF_LEN (128)

#define SOCK_EP_CAP ( FI_MSG | \
		      FI_INJECT |			\
		      FI_SOURCE |			\
		      FI_SEND | FI_RECV |		\
		      FI_CANCEL )

#define SOCK_OPS_CAP (FI_INJECT | FI_SEND | FI_RECV )

#define SOCK_MAJOR_VERSION 1
#define SOCK_MINOR_VERSION 0

extern const char const sock_fab_name[];
extern const char const sock_dom_name[];

struct sock_fabric{
	struct fid_fabric fab_fid;
};

struct sock_domain {
	struct fid_domain dom_fid;
	uint64_t		mode;
	struct sock_fabric *fab;
	fastlock_t lock;
	atomic_t ref;
	struct index_map mr_idm;
};

struct sock_cntr {
	struct fid_cntr		cntr_fid;
	struct sock_domain	*dom;
	uint64_t		value;
	uint64_t		threshold;
	atomic_t		ref;
	pthread_cond_t		cond;
	pthread_mutex_t		mut;
};

#define SOCK_RD_FD		0
#define SOCK_WR_FD		1

struct sock_cq {
	struct fid_cq		cq_fid;
	struct sock_domain	*domain;
	ssize_t cq_entry_size;
	atomic_t ref;
	struct fi_cq_attr attr;
	int fd[2];

	list_t *ep_list;
	list_t *completed_list;
	list_t *error_list;
};

struct sock_mr {
	struct fid_mr		mr_fid;
	struct sock_domain	*dom;
	uint64_t		access;
	uint64_t		offset;
	uint64_t		key;
	size_t			iov_count;
	struct iovec		mr_iov[1];
};

struct sock_av {
	struct fid_av		av_fid;
	struct sock_domain	*dom;
	atomic_t		ref;
	struct fi_av_attr	attr;
	size_t			count;
	struct sockaddr_in	*table;
};

struct sock_poll {
	struct fid_poll		poll_fid;
	struct sock_domain	*dom;
};

struct sock_wait {
	struct fid_wait wait_fid;
	struct sock_domain *dom;
};

struct sock_eq_item{
	int type;
	ssize_t len;
};

enum {
	SOCK_REQ_TYPE_SEND,
	SOCK_REQ_TYPE_RECV,
	SOCK_REQ_TYPE_USER,
};

enum{
	SOCK_COMM_TYPE_SEND,
	SOCK_COMM_TYPE_SENDV,
	SOCK_COMM_TYPE_SENDTO,
	SOCK_COMM_TYPE_SENDMSG,
	SOCK_COMM_TYPE_SENDDATA,
	SOCK_COMM_TYPE_SENDDATATO,
};

struct sock_req_item{
	int req_type;
	int comm_type;
	struct sock_ep *ep;

	void *context;
	uint64_t flags;
	uint64_t tag;
	uint64_t data;

	size_t done_len;
	size_t total_len;
	struct sockaddr  src_addr;
	fi_addr_t addr;

	union{
		struct fi_msg msg;
		void *buf;
	}item;

};

struct sock_eq{
	struct fid_eq eq;
	struct fi_eq_attr attr;
	struct sock_fabric *sock_fab;
	int fd[2];

	list_t *completed_list;
	list_t *error_list;
};

typedef int (*sock_ep_progress_fn) (struct sock_ep *ep, struct sock_cq *cq);

struct sock_ep {
	struct fid_ep		ep;
	struct sock_domain	*domain;	
	int sock_fd;

	struct sock_eq        *eq;
	struct sock_av 	*av;

	struct sock_cq 	*send_cq;
	struct sock_cq 	*recv_cq;
	int send_cq_event_flag;
	int recv_cq_event_flag;

	struct sock_cntr 	*send_cntr;
	struct sock_cntr 	*recv_cntr;
	struct sock_cntr 	*read_cntr;
	struct sock_cntr 	*write_cntr;
	struct sock_cntr 	*rem_read_cntr;
	struct sock_cntr 	*rem_write_cntr;
	
	uint64_t out_send;
	uint64_t out_tagged_send;
	uint64_t out_rma_put;
	uint64_t out_rma_get;

	uint64_t cmpl_send;
	uint64_t cmpl_tagged_send;
	uint64_t cmpl_rma_put;
	uint64_t cmpl_rma_get;

	struct fi_info info;
	struct fi_ep_attr ep_attr;

	list_t *send_list;
	list_t *recv_list;
	
	struct sockaddr src_addr;
	struct sockaddr dest_addr;

	enum fi_ep_type ep_type;

	int connected;
	int enabled;
	int is_alias;

	struct sock_ep *next;
	struct sock_ep *prev;
	struct sock_ep *alias;
	struct sock_ep *base;
	
	int port_num;
	sock_ep_progress_fn progress_fn;
};

struct sock_pep {
	struct fid_pep		pep;
	struct sock_domain  *dom;
	
	int sock_fd;

	struct sock_eq 	*eq;

	struct sock_cq 	*send_cq;
	struct sock_cq 	*recv_cq;

	uint64_t			op_flags;
	uint64_t			pep_cap;

};

int _sock_verify_info(struct fi_info *hints);
int _sock_verify_ep_attr(struct fi_ep_attr *attr);
int _sock_verify_fabric_attr(struct fi_fabric_attr *attr);
int _sock_verify_domain_attr(struct fi_domain_attr *attr);

int sock_rdm_getinfo(uint32_t version, const char *node, const char *service,
		uint64_t flags, struct fi_info *hints, struct fi_info **info);
int sock_dgram_getinfo(uint32_t version, const char *node, const char *service,
		uint64_t flags, struct fi_info *hints, struct fi_info **info);


int sock_domain(struct fid_fabric *fabric, struct fi_info *info,
		struct fid_domain **dom, void *context);


int sock_av_open(struct fid_domain *domain, struct fi_av_attr *attr,
		struct fid_av **av, void *context);
fi_addr_t _sock_av_lookup(struct sock_av *av, struct sockaddr *addr);


int sock_cq_open(struct fid_domain *domain, struct fi_cq_attr *attr,
		 struct fid_cq **cq, void *context);
int _sock_cq_report_completion(struct sock_cq *sock_cq, struct sock_req_item *item);
int _sock_cq_report_error(struct sock_cq *sock_cq, struct fi_cq_err_entry *error);


int sock_eq_open(struct fid_fabric *fabric, struct fi_eq_attr *attr,
		struct fid_eq **eq, void *context);
ssize_t _sock_eq_report_error(struct sock_eq *sock_eq, const void *buf, size_t len);
ssize_t _sock_eq_report_event(struct sock_eq *sock_eq, int event_type, 
			      const void *buf, size_t len);


int sock_cntr_open(struct fid_domain *domain, struct fi_cntr_attr *attr,
		struct fid_cntr **cntr, void *context);


int sock_rdm_ep(struct fid_domain *domain, struct fi_info *info,
		struct fid_ep **ep, void *context);
int sock_dgram_ep(struct fid_domain *domain, struct fi_info *info,
		  struct fid_ep **ep, void *context);
int sock_pendpoint(struct fid_fabric *fabric, struct fi_info *info,
		   struct fid_pep **pep, void *context);


int sock_ep_connect(struct fid_ep *ep, const void *addr,
		    const void *param, size_t paramlen);


int sock_poll_open(struct fid_domain *domain, struct fi_poll_attr *attr,
		struct fid_poll **pollset);
int sock_wait_open(struct fid_domain *domain, struct fi_wait_attr *attr,
		struct fid_wait **waitset);


void free_fi_info(struct fi_info *info);


#endif
