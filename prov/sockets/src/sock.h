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

#define SOCK_EP_BACKLOG (8)
#define SOCK_EP_SNDQ_LEN (128)
#define SOCK_EP_RCVQ_LEN (128)

#define SOCK_EQ_DEF_LEN (128)
#define SOCK_CQ_DEF_LEN (128)

#define SOCK_EP_CAP ( FI_MSG | \
		      FI_INJECT | FI_SOURCE |		\
		      FI_SEND | FI_RECV |		\
		      FI_CANCEL )

#define SOCK_MAJOR_VERSION 1
#define SOCK_MINOR_VERSION 0

#define MIN(_a, _b) (_a) < (_b) ? (_a):(_b)
#define MAX(_a, _b) (_a) > (_b) ? (_a):(_b)

static const char const fab_name[] = "IP";
static const char const dom_name[] = "sockets";

typedef struct _sock_fabric_t{
	struct fid_fabric fab_fid;
}sock_fabric_t;

typedef struct _sock_domain_t {
	struct fid_domain dom_fid;
	uint64_t		mode;
	sock_fabric_t *fab;
	fastlock_t lock;
	atomic_t ref;
	struct index_map mr_idm;
}sock_domain_t;

typedef struct _sock_cntr_t {
	struct fid_cntr		cntr_fid;
	sock_domain_t	*dom;
	uint64_t		value;
	uint64_t		threshold;
	atomic_t		ref;
	pthread_cond_t		cond;
	pthread_mutex_t		mut;
}sock_cntr_t;

#define SOCK_RD_FD		0
#define SOCK_WR_FD		1

typedef struct _sock_cq_t {
	struct fid_cq		cq_fid;
	sock_domain_t	*domain;
	ssize_t cq_entry_size;
	atomic_t ref;
	struct fi_cq_attr attr;
	int fd[2];

	list_t *ep_list;
	list_t *completed_list;
	list_t *error_list;
}sock_cq_t;

typedef struct _sock_mr_t {
	struct fid_mr		mr_fid;
	sock_domain_t	*dom;
	uint64_t		access;
	uint64_t		offset;
	uint64_t		key;
	size_t			iov_count;
	struct iovec		mr_iov[1];
}sock_mr_t;

typedef struct _sock_av_t {
	struct fid_av		av_fid;
	sock_domain_t	*dom;
	atomic_t		ref;
	struct fi_av_attr	attr;
	size_t			count;
	struct sockaddr_in	*table;
}sock_av_t;

typedef struct _sock_poll_t {
	struct fid_poll		poll_fid;
	sock_domain_t	*dom;
}sock_poll_t;

typedef struct _sock_wait_t {
	struct fid_wait wait_fid;
	sock_domain_t *dom;
}sock_wait_t;

typedef struct _sock_ep_t sock_ep_t;

typedef struct _sock_eq_item_t{
	int type;
	ssize_t len;
}sock_eq_item_t;

#define REQ_TYPE_SEND (1)
#define REQ_TYPE_RECV (2)
#define REQ_TYPE_USER (3)

#define COMM_TYPE_SEND (1)
#define COMM_TYPE_SENDV (2)
#define COMM_TYPE_SENDTO (3)
#define COMM_TYPE_SENDMSG (4)
#define COMM_TYPE_SENDDATA (5)
#define COMM_TYPE_SENDDATATO (6)

typedef struct _sock_req_item_t
{
	int req_type;
	int comm_type;
	sock_ep_t *ep;

	void *context;
	uint64_t flags;
	uint64_t tag;
	uint64_t data;

	size_t done_len;
	size_t total_len;
	struct sockaddr  src_addr;
	struct sockaddr addr;

	union{
		struct fi_msg msg;
		void *buf;
	}item;

}sock_req_item_t;

typedef struct _sock_comm_item_t{
	int type;
	int is_done;
	void *context;
	size_t done_len;
	size_t total_len;
	uint64_t flags;

	struct sockaddr addr;

	union{
		struct fi_msg msg;
		void *buf;
	}item;
}sock_comm_item_t;

typedef struct _sock_eq_t{
	struct fid_eq eq;
	struct fi_eq_attr attr;
	sock_fabric_t *sock_fab;
	int fd[2];

	list_t *completed_list;
	list_t *error_list;
}sock_eq_t;

typedef int (*sock_ep_progress_fn) (sock_ep_t *ep, sock_cq_t *cq);

struct _sock_ep_t {
	struct fid_ep		ep;
	sock_domain_t	*domain;	
	int sock_fd;

	sock_eq_t        *eq;
	sock_av_t 	*av;

	sock_cq_t 	*send_cq;
	sock_cq_t 	*recv_cq;
	int send_cq_event_flag;
	int recv_cq_event_flag;

	sock_cntr_t 	*send_cntr;
	sock_cntr_t 	*recv_cntr;
	sock_cntr_t 	*read_cntr;
	sock_cntr_t 	*write_cntr;
	sock_cntr_t 	*rem_read_cntr;
	sock_cntr_t 	*rem_write_cntr;
	
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

	struct _sock_ep_t *next;
	struct _sock_ep_t *prev;
	struct _sock_ep_t *alias;
	struct _sock_ep_t *base;
	
	int port_num;
	sock_ep_progress_fn progress_fn;
};

typedef struct _sock_pep_t {
	struct fid_pep		pep;
	sock_domain_t	*dom;
	
	int sock_fd;

	sock_eq_t 	*send_cq;
	sock_eq_t 	*recv_cq;

	sock_cntr_t 	*send_cntr;
	sock_cntr_t 	*recv_cntr;
	sock_cntr_t 	*read_cntr;
	sock_cntr_t 	*write_cntr;
	sock_cntr_t 	*rem_read_cntr;
	sock_cntr_t 	*rem_write_cntr;

	uint64_t			op_flags;
	uint64_t			pep_cap;

}sock_pep_t;


int sock_rdm_getinfo(uint32_t version, const char *node, const char *service,
		uint64_t flags, struct fi_info *hints, struct fi_info **info);
int sock_dgram_getinfo(uint32_t version, const char *node, const char *service,
		uint64_t flags, struct fi_info *hints, struct fi_info **info);
int sock_av_open(struct fid_domain *domain, struct fi_av_attr *attr,
		struct fid_av **av, void *context);
int sock_cntr_open(struct fid_domain *domain, struct fi_cntr_attr *attr,
		struct fid_cntr **cntr, void *context);
int sock_domain(struct fid_fabric *fabric, struct fi_info *info,
		struct fid_domain **dom, void *context);
int sock_eq_open(struct fid_fabric *fabric, struct fi_eq_attr *attr,
		struct fid_eq **eq, void *context);
int sock_cq_open(struct fid_domain *domain, struct fi_cq_attr *attr,
		 struct fid_cq **cq, void *context);
int sock_rdm_ep(struct fid_domain *domain, struct fi_info *info,
		struct fid_ep **ep, void *context);
int sock_poll_open(struct fid_domain *domain, struct fi_poll_attr *attr,
		struct fid_poll **pollset);
int sock_wait_open(struct fid_domain *domain, struct fi_wait_attr *attr,
		struct fid_wait **waitset);

int sock_ep_connect(struct fid_ep *ep, const void *addr,
		    const void *param, size_t paramlen);

void free_fi_info(struct fi_info *info);

fi_addr_t _sock_av_lookup(sock_av_t *av, struct sockaddr *addr);

int _sock_cq_report_completion(sock_cq_t *sock_cq, 
			       sock_req_item_t *item);
int _sock_cq_report_error(sock_cq_t *sock_cq, 
			  struct fi_cq_err_entry *error);

ssize_t _sock_eq_report_error(sock_eq_t *sock_eq, const void *buf, size_t len);
ssize_t _sock_eq_report_event(sock_eq_t *sock_eq, int event_type, 
			      const void *buf, size_t len);
