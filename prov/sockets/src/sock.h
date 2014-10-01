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

//#include <errno.h>
//#include <fcntl.h>
//#include <netdb.h>
//#include <netinet/in.h>
//#include <netinet/tcp.h>
//#include <poll.h>
#include <pthread.h>
//#include <stdarg.h>
//#include <stddef.h>
//#include <stdio.h>
//#include <string.h>
//#include <sys/select.h>
//#include <sys/socket.h>
//#include <sys/types.h>
//#include <sys/time.h>
//#include <unistd.h>

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
#include "indexer.h"
#include "list.h"

#define DEF_SOCK_EP_BACKLOG (8)
#define DEF_SOCK_EP_NUM_BUFS (128)

#define MIN(_a, _b) (_a) < (_b) ? (_a):(_b)
#define MAX(_a, _b) (_a) > (_b) ? (_a):(_b)

static const char const fab_name[] = "IP";
static const char const dom_name[] = "sockets";

typedef struct _sock_fabric_t{
	struct fid_fabric fab_fid;
}sock_fabric_t;

typedef struct _sock_domain_t {
	struct fid_domain dom_fid;
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
	sock_domain_t	*dom;
	int			fd[2];
	enum fi_cq_format	format;
	atomic_t		ref;
	struct fi_cq_err_entry	err_entry;
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
}sock_av_t;

typedef struct _sock_poll_t {
	struct fid_poll		poll_fid;
	sock_domain_t	*dom;
}sock_poll_t;

typedef struct _sock_wait_t {
	struct fid_wait wait_fid;
	sock_domain_t *dom;
}sock_wait_t;

typedef struct _send_buf_t{
	void *buf;
	size_t buf_len;
	size_t completed;
	struct _send_buf_t *next;
}send_buf_t;

typedef struct _recv_buf_t{
	void *buf;
	size_t buf_len;
	struct _recv_buf_t *next;
}recv_buf_t;

typedef struct _sock_eq_t{
	struct fid_eq eq;
	struct fi_eq_attr attr;
	void *context;
	list_t *eq_list;
	list_t *eq_error_list;
}sock_eq_t;

typedef struct _sock_ep_t {
	struct fid_ep		ep;
	sock_domain_t	*dom;
	sock_av_t	*av;
	
	int sock_fd;

	sock_eq_t 	*send_cq;
	sock_eq_t 	*recv_cq;
	sock_eq_t 	*put_cq;
	sock_eq_t 	*get_cq;

	sock_cntr_t 	*send_cntr;
	sock_cntr_t 	*recv_cntr;
	sock_cntr_t 	*put_cntr;
	sock_cntr_t 	*get_cntr;

	uint64_t			out_send;
	uint64_t			out_tagged_send;
	uint64_t			out_rma_put;
	uint64_t			out_rma_get;

	uint64_t			cmpl_send;
	uint64_t			cmpl_tagged_send;
	uint64_t			cmpl_rma_put;
	uint64_t			cmpl_rma_get;

	uint64_t			op_flags;
	uint64_t			ep_cap;

	uint64_t num_recv_buf_list;
	void *recv_buf_list_mem;

	recv_buf_t *free_recv_list_head;
	recv_buf_t *free_recv_list_tail;
	recv_buf_t *posted_recv_list_head;
	recv_buf_t *posted_recv_list_tail;

	uint64_t num_send_buf_list;
	void *send_buf_list_mem;

	send_buf_t *free_send_list_head;
	send_buf_t *free_send_list_tail;
	send_buf_t *posted_send_list_head;
	send_buf_t *posted_send_list_tail;

	int connected;
}sock_ep_t;

typedef struct _sock_pep_t {
	struct fid_pep		pep;
	sock_domain_t	*dom;
	
	int sock_fd;

	sock_eq_t 	*send_cq;
	sock_eq_t 	*recv_cq;
	sock_eq_t 	*put_cq;
	sock_eq_t 	*get_cq;

	sock_cntr_t 	*send_cntr;
	sock_cntr_t 	*recv_cntr;
	sock_cntr_t 	*put_cntr;
	sock_cntr_t 	*get_cntr;

	uint64_t			op_flags;
	uint64_t			pep_cap;

}sock_pep_t;


int sock_rdm_getinfo(uint32_t version, const char *node, const char *service,
		uint64_t flags, struct fi_info *hints, struct fi_info **info);
int sock_av_open(struct fid_domain *domain, struct fi_av_attr *attr,
		struct fid_av **av, void *context);
int sock_cntr_open(struct fid_domain *domain, struct fi_cntr_attr *attr,
		struct fid_cntr **cntr, void *context);
int sock_domain(struct fid_fabric *fabric, struct fi_domain_attr *attr,
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

inline void enqueue_free_recv_list(sock_ep_t *sock_ep, recv_buf_t *item);
inline void enqueue_post_recv_list(sock_ep_t *sock_ep, recv_buf_t *item);
inline recv_buf_t *get_from_free_recv_list(sock_ep_t *sock_ep);
inline recv_buf_t *dequeue_post_recv_list(sock_ep_t *sock_ep);
int alloc_free_recv_buf_lists(sock_ep_t *sock_ep, int num_bufs);

inline void enqueue_free_send_list(sock_ep_t *sock_ep, send_buf_t *item);
inline void enqueue_post_send_list(sock_ep_t *sock_ep, send_buf_t *item);
inline send_buf_t *get_from_free_send_list(sock_ep_t *sock_ep);
inline send_buf_t *dequeue_post_send_list(sock_ep_t *sock_ep);
int alloc_free_send_buf_lists(sock_ep_t *sock_ep, int num_bufs);
