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
#include "fi_enosys.h"
#include "indexer.h"
#include "list.h"

#define DEF_SOCK_EP_BACKLOG (8)
#define DEF_SOCK_EP_NUM_BUFS (128)

#define MIN(_a, _b) (_a) < (_b) ? (_a):(_b)
#define MAX(_a, _b) (_a) > (_b) ? (_a):(_b)

static const char const fab_name[] = "IP";
static const char const dom_name[] = "sockets";


#define SOCK_EP_CAP ( FI_MSG | FI_INJECT | \
		      FI_SEND | FI_RECV |  \
		      FI_CANCEL )


#define SOCK_MAJOR_VERSION 0
#define SOCK_MINOR_VERSION 2

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
	int fd[2];
	list_t *eq_list;
	list_t *eq_error_list;
}sock_eq_t;

typedef struct _sock_ep_t {
	struct fid_ep		ep;
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

	int connected;
}sock_ep_t;

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
