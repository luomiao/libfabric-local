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

#include <fi.h>
#include <fi_enosys.h>
#include <fi_indexer.h>
#include "list.h"
#include <fi_rbuf.h>
#include <fi_list.h>

#include <netdb.h>

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
#define SOCK_EP_MAX_EP_CNT (128)
#define SOCK_EP_MAX_TX_CNT (16)
#define SOCK_EP_MAX_RX_CNT (16)
#define SOCK_EP_MAX_IOV_LIMIT (8)
#define SOCK_EP_MAX_TX_CTX_SZ (1<<12)

#define SOCK_PE_POLL_TIMEOUT (100000)
#define SOCK_PE_MAX_ENTRIES (128)

#define SOCK_EQ_DEF_SZ (1<<8)
#define SOCK_CQ_DEF_SZ (1<<8)

#define SOCK_EP_RDM_CAP (FI_MSG | FI_INJECT | FI_SOURCE | FI_SEND | FI_RECV)
#define SOCK_EP_DGRAM_CAP (FI_MSG | FI_INJECT | FI_SOURCE | FI_SEND | FI_RECV)
#define SOCK_OPS_CAP (FI_INJECT | FI_SEND | FI_RECV )
#define SOCK_MODE (0)

#define SOCK_MAJOR_VERSION 1
#define SOCK_MINOR_VERSION 0

/* TODO: to remove */
#define SOCK_EP_SNDQ_LEN (128)
#define SOCK_EP_RCVQ_LEN (128)

#define SOCK_DEFAULT_PORT "3391"

extern const char const sock_fab_name[];
extern const char const sock_dom_name[];

struct sock_fabric{
	struct fid_fabric fab_fid;
	atomic_t ref;
};

struct sock_conn {
        int sock_fd;
        struct sockaddr addr;
        struct sock_pe_entry *pe_entry;
};

struct sock_conn_map {
        struct sock_conn *table;
        int used;
        int size;
		struct sock_domain *dom;
};

struct sock_domain {
	struct fi_info info;
	struct fid_domain dom_fid;
	struct sock_fabric *fab;
	fastlock_t lock;
	atomic_t ref;
	
	struct sock_eq *eq;
	struct sock_eq *mr_eq;

	enum fi_progress progress_mode;
	struct index_map mr_idm;
	struct sock_pe *pe;
	struct sock_conn_map u_cmap;
	struct sock_conn_map r_cmap;
	pthread_t listen_thread;
	int	listening;
	char service[NI_MAXSERV];
};

struct sock_cntr {
	struct fid_cntr		cntr_fid;
	struct sock_domain	*dom;
	uint64_t		value;
	uint64_t		threshold;
	atomic_t		ref;
	atomic_t err_cnt;
	pthread_cond_t		cond;
	pthread_mutex_t		mut;
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

typedef int (*sock_connect_fn) (struct sock_conn_map *map, void *addr, 
		int count, socklen_t addrlen, uint16_t *key_table, int port);

struct sock_av {
	struct fid_av		av_fid;
	struct sock_domain	*dom;
	atomic_t		ref;
	struct fi_av_attr	attr;
	uint64_t		mask;
	int			rx_ctx_bits;
	int			port_num;
	size_t			count;
	size_t			stored;
	uint16_t		*key_table;
	struct sockaddr_storage *addr_table;
	socklen_t		addrlen;
	sock_connect_fn		connect_fn;
	struct sock_conn_map	*cmap;
};

struct sock_poll {
	struct fid_poll		poll_fid;
	struct sock_domain	*dom;
};

struct sock_wait {
	struct fid_wait wait_fid;
	struct sock_domain *dom;
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
	struct sockaddr addr;

	union{
		struct fi_msg msg;
		void *buf;
	}item;

};

struct sock_comm_item{
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
};

enum {
	SOCK_OP_SEND,
	SOCK_OP_SEND_COMPLETE,
	SOCK_OP_RECV,
	SOCK_OP_SEND_INJECT,
	SOCK_OP_TSEND_INJECT,

	SOCK_OP_WRITE,
	SOCK_OP_WRITE_COMPLETE,
	SOCK_OP_WRITE_ERROR,

	SOCK_OP_READ,
	SOCK_OP_READ_COMPLETE,
	SOCK_OP_READ_ERROR,

	SOCK_OP_TSEND,
	SOCK_OP_TRECV,

	SOCK_OP_ATOMIC,
	SOCK_OP_ATOMIC_COMPLETE,
	SOCK_OP_ATOMIC_ERROR,
};

/*
 * Transmit context - ring buffer data:
 *    tx_op + flags + context + dest_addr + conn + [data] + [tag] + tx_iov
 *     8B       8B      8B         8B         8B       8B      24B+
 * data - only present if flags indicate
 * tag - only present for TSEND op
 */
struct sock_op {
	uint8_t			op;
	uint8_t			src_iov_len;
	uint8_t			dest_iov_len;
	union {
		struct {
			uint8_t	op;
			uint8_t	datatype;
		} atomic;
		uint8_t		reserved[5];
	};
};

struct sock_op_send {
	struct sock_op op;
	uint64_t flags;
	uint64_t context;
	uint64_t dest_addr;
	struct sock_conn *conn;
};

struct sock_op_tsend {
	struct sock_op op;
	uint64_t flags;
	uint64_t context;
	uint64_t dest_addr;
	struct sock_conn *conn;
	uint64_t tag;
};

union sock_iov {
	struct fi_rma_iov	iov;
	struct fi_rma_ioc	ioc;
};

struct sock_rxtx {
	struct ringbuffd	rbfd;
	fastlock_t		wlock;
	fastlock_t		rlock;
};

struct sock_eq_entry{
	uint32_t type;
	size_t len;
	uint64_t flags;
	struct dlist_entry entry;
	char event[0];
};

struct sock_eq{
	struct fid_eq eq;
	struct fi_eq_attr attr;
	struct sock_fabric *sock_fab;

	struct dlistfd_head list;
	struct dlistfd_head err_list;
	fastlock_t lock;
};

struct sock_ep {
	struct fid_ep ep;

	uint8_t enabled;
	uint8_t connected;

	uint8_t send_cq_event;
	uint8_t recv_cq_event;
	uint8_t read_cq_event;
	uint8_t write_cq_event;
	uint8_t rem_read_cq_event;
	uint8_t rem_write_cq_event;

	uint16_t sock_fd;
	uint8_t reserved[6];

	atomic_t ref;

	struct sock_eq *eq;
	struct sock_av *av;
	struct sock_domain *domain;	

	struct sock_cq	*send_cq;
	struct sock_cq	*recv_cq;
	struct sock_cq	*read_cq;
	struct sock_cq	*write_cq;
	struct sock_cq *rem_read_cq;
	struct sock_cq *rem_write_cq;

	struct sock_cntr *send_cntr;
	struct sock_cntr *recv_cntr;
	struct sock_cntr *read_cntr;
	struct sock_cntr *write_cntr;
	struct sock_cntr *rem_read_cntr;
	struct sock_cntr *rem_write_cntr;

	struct sock_rx_ctx *rx_ctx;
	struct sock_tx_ctx *tx_ctx;

	struct sock_rx_ctx **rx_array;
	struct sock_tx_ctx **tx_array;
	atomic_t num_rx_ctx;
	atomic_t num_tx_ctx;

	struct dlist_entry rx_ctx_entry;
	struct dlist_entry tx_ctx_entry;

	struct fi_info info;
	struct fi_ep_attr ep_attr;
	struct fi_tx_ctx_attr tx_attr;
	struct fi_rx_ctx_attr rx_attr;

	enum fi_ep_type ep_type;
	struct sockaddr_in *src_addr;
	struct sockaddr_in *dest_addr;

	/* TODO: remove */
	struct sock_ep *next;
	struct sock_ep *prev;
	struct sock_ep *alias;
	struct sock_ep *base;

	list_t *send_list;
	list_t *recv_list;
	int port_num;
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

struct sock_rx_entry {
	struct sock_op rx_op;

	uint64_t flags;
	uint64_t context;
	uint64_t addr;
	uint64_t data;
	uint64_t tag;
	uint64_t ignore;
	
	union sock_iov iov[SOCK_EP_MAX_IOV_LIMIT];
	struct dlist_entry entry;
};

struct sock_rx_ctx {
	struct fid_ep ctx;

	uint16_t rx_id;
	uint8_t enabled;
	uint8_t progress;

	uint8_t recv_cq_event;
	uint8_t rem_read_cq_event;
	uint8_t rem_write_cq_event;
	uint8_t reserved[1];

	uint64_t addr;

	struct sock_cq *recv_cq;
	struct sock_cq *rem_read_cq;
	struct sock_cq *rem_write_cq;

	struct sock_ep *ep;
	struct sock_av *av;
	struct sock_eq *eq;
 	struct sock_domain *domain;

	struct sock_cntr *recv_cntr;
	struct sock_cntr  *rem_read_cntr;
	struct sock_cntr  *rem_write_cntr;

	struct dlist_entry cq_entry;
	struct dlist_entry pe_entry;

	struct dlist_entry pe_entry_list;
	struct dlist_entry rx_entry_list;
	struct dlist_entry ep_list;
	fastlock_t lock;

	struct fi_rx_ctx_attr attr;
};

struct sock_tx_ctx {
	struct fid_ep ctx;

	struct ringbuffd	rbfd;
	fastlock_t		wlock;
	fastlock_t		rlock;

	uint16_t tx_id;
	uint8_t enabled;
	uint8_t progress;

	uint8_t send_cq_event;
	uint8_t read_cq_event;
	uint8_t write_cq_event;
	uint8_t reserved[1];

	uint64_t addr;

	struct sock_cq *send_cq;
	struct sock_cq *read_cq;
	struct sock_cq *write_cq;

	struct sock_ep *ep;
	struct sock_av *av;
	struct sock_eq *eq;
 	struct sock_domain *domain;

	struct sock_cntr *send_cntr;
	struct sock_cntr *read_cntr;
	struct sock_cntr *write_cntr;

	struct dlist_entry cq_entry;
	struct dlist_entry pe_entry;

	struct dlist_entry pe_entry_list;
	struct dlist_entry ep_list;
	fastlock_t lock;

	struct fi_tx_ctx_attr attr;
};


#define SOCK_WIRE_PROTO_VERSION (0)

struct sock_msg_hdr{
	uint8_t version;
	uint8_t op_type;
	uint16_t rx_id;
	uint16_t pe_entry_id;
	uint8_t reserved[2];

	uint64_t src_addr;
	uint64_t flags;
	uint64_t msg_len; /* includes header len */
};

struct sock_msg_send{
	struct sock_msg_hdr msg_hdr;
	/* user data */
	/* data */
};

struct sock_msg_tsend{
	struct sock_msg_hdr msg_hdr;
	uint64_t tag;
	/* user data */
	/* data */
};

struct sock_rma_write_req {
	struct sock_msg_hdr msg_hdr;
	uint16_t pe_index;
	/* dest iov(s)*/
	/* user data */
};

struct sock_rma_ok {
	struct sock_msg_hdr msg_hdr;
	uint16_t pe_index;
};

struct sock_rma_err {
	struct sock_msg_hdr msg_hdr;
	uint16_t pe_index;
};

struct sock_tx_iov {
	union sock_iov src;
	union sock_iov dst;
};

struct sock_tx_pe_entry{
	struct sock_op tx_op;	
	uint8_t header_sent;
	uint8_t send_done;
	uint8_t ack_done;
	uint8_t reserved[5];

	union {
		struct sock_tx_iov tx_iov[SOCK_EP_MAX_IOV_LIMIT];
		char inject_data[SOCK_EP_MAX_INJECT_SZ];
	};
};

struct sock_rx_pe_entry{
	struct sock_op rx_op;
	uint8_t recv_done;
	uint8_t reserved[7];
	void *raw_data;
	union sock_iov rx_iov[SOCK_EP_MAX_IOV_LIMIT];
};

/* PE entry type */
enum{
	SOCK_PE_RX,
	SOCK_PE_TX,
};

struct sock_pe_entry{
	union{
		struct sock_tx_pe_entry tx;
		struct sock_rx_pe_entry rx;
	};

	struct sock_msg_hdr msg_hdr;

	uint64_t flags;
	uint64_t context;
	uint64_t addr;
	uint64_t data;
	uint64_t tag;

	uint8_t type;
	uint8_t is_complete;
	uint8_t reserved[6];

	uint64_t done_len;
	uint64_t total_len;
	struct sock_ep *ep;
	struct sock_conn *conn;

	struct dlist_entry entry;
	struct dlist_entry ctx_entry;
};

struct sock_pe{
	struct sock_domain *domain;

	struct sock_pe_entry pe_table[SOCK_PE_MAX_ENTRIES];
	fastlock_t lock;

	struct dlist_entry free_list;
	struct dlist_entry busy_list;

	struct dlistfd_head tx_list;
	struct dlistfd_head rx_list;

	pthread_t progress_thread;
	volatile int do_progress;
};

typedef int (*sock_cq_report_fn) (struct sock_cq *cq, fi_addr_t addr,
				  struct sock_pe_entry *pe_entry);

struct sock_cq {
	struct fid_cq cq_fid;
	struct sock_domain *domain;
	ssize_t cq_entry_size;
	atomic_t ref;
	struct fi_cq_attr attr;

	struct ringbuf addr_rb;
	struct ringbuffd cq_rbfd;
	struct ringbuf cqerr_rb;
	fastlock_t lock;

	struct dlist_entry ep_list;
	struct dlist_entry rx_list;
	struct dlist_entry tx_list;

	sock_cq_report_fn report_completion;
};

int sock_verify_info(struct fi_info *hints);
int sock_verify_fabric_attr(struct fi_fabric_attr *attr);
int sock_verify_domain_attr(struct fi_domain_attr *attr);


int sock_rdm_getinfo(uint32_t version, const char *node, const char *service,
		uint64_t flags, struct fi_info *hints, struct fi_info **info);
int sock_rdm_verify_ep_attr(struct fi_ep_attr *ep_attr, 
			struct fi_tx_ctx_attr *tx_attr,
			struct fi_rx_ctx_attr *rx_attr);


int sock_dgram_getinfo(uint32_t version, const char *node, const char *service,
		uint64_t flags, struct fi_info *hints, struct fi_info **info);


int sock_domain(struct fid_fabric *fabric, struct fi_info *info,
		struct fid_domain **dom, void *context);


#define SOCK_GET_RX_ID(_addr, _bits) (((uint64_t)_addr) >> (64 - _bits))
int sock_av_open(struct fid_domain *domain, struct fi_av_attr *attr,
		struct fid_av **av, void *context);
fi_addr_t _sock_av_lookup(struct sock_av *av, struct sockaddr *addr);
int sock_av_lookup_addr(struct sock_av *av, fi_addr_t addr, 
			struct sock_conn **entry);
int sock_conn_map_lookup_key(struct sock_conn_map *conn_map,
			     uint16_t key, struct sock_conn **entry);


int sock_cq_open(struct fid_domain *domain, struct fi_cq_attr *attr,
		 struct fid_cq **cq, void *context);
int sock_cq_report_error(struct sock_cq *cq, struct sock_pe_entry *entry,
			 size_t olen, int err, int prov_errno, void *err_data);


int sock_eq_open(struct fid_fabric *fabric, struct fi_eq_attr *attr,
		struct fid_eq **eq, void *context);
ssize_t sock_eq_report_event(struct sock_eq *sock_eq, uint32_t event, 
			     const void *buf, size_t len, uint64_t flags);
ssize_t sock_eq_report_error(struct sock_eq *sock_eq, fid_t fid, void *context,
			     int err, int prov_errno, void *err_data);


int sock_cntr_open(struct fid_domain *domain, struct fi_cntr_attr *attr,
		struct fid_cntr **cntr, void *context);
int sock_cntr_inc(struct sock_cntr *cntr);
int sock_cntr_err_inc(struct sock_cntr *cntr);

int sock_rdm_ep(struct fid_domain *domain, struct fi_info *info,
		struct fid_ep **ep, void *context);
int sock_dgram_ep(struct fid_domain *domain, struct fi_info *info,
		  struct fid_ep **ep, void *context);
int sock_pendpoint(struct fid_fabric *fabric, struct fi_info *info,
		   struct fid_pep **pep, void *context);


int sock_mr_verify_key(struct sock_domain *domain, uint16_t key, 
		       void *buf, size_t len, uint64_t access);
int sock_mr_verify_desc(struct sock_domain *domain, void *desc, 
			void *buf, size_t len, uint64_t access);


int sock_ep_connect(struct fid_ep *ep, const void *addr,
		    const void *param, size_t paramlen);
struct sock_rx_entry *sock_ep_get_rx_entry(struct sock_ep *ep, 
					   struct sock_pe_entry *pe_entry);


struct sock_rx_ctx *sock_rx_ctx_alloc(struct fi_rx_ctx_attr *attr, 
				      void *context);
void sock_rx_ctx_add_ep(struct sock_rx_ctx *rx_ctx, struct sock_ep *ep);
void sock_rx_ctx_free(struct sock_rx_ctx *rx_ctx);


struct sock_tx_ctx *sock_tx_ctx_alloc(struct fi_tx_ctx_attr *attr, 
				      void *context);
void sock_tx_ctx_add_ep(struct sock_tx_ctx *tx_ctx, struct sock_ep *ep);
void sock_tx_ctx_free(struct sock_tx_ctx *tx_ctx);
void sock_tx_ctx_start(struct sock_tx_ctx *tx_ctx);
void sock_tx_ctx_write(struct sock_tx_ctx *tx_ctx, const void *buf, size_t len);
void sock_tx_ctx_commit(struct sock_tx_ctx *tx_ctx);
void sock_tx_ctx_abort(struct sock_tx_ctx *tx_ctx);
int sock_tx_ctx_read(struct sock_tx_ctx *tx_ctx, void *buf, size_t len);


int sock_poll_open(struct fid_domain *domain, struct fi_poll_attr *attr,
		struct fid_poll **pollset);
int sock_wait_open(struct fid_domain *domain, struct fi_wait_attr *attr,
		struct fid_wait **waitset);


int sock_av_lookup_addr(struct sock_av *av, fi_addr_t addr, 
			struct sock_conn **entry);
int sock_conn_map_lookup_key(struct sock_conn_map *conn_map,
			     uint16_t key, struct sock_conn **entry);

/* FIXME: handle shared ctx */
#define SOCK_GET_RX_ID(_addr, _bits) (((uint64_t)_addr) >> (64 - _bits))
int sock_dgram_connect_conn_map(struct sock_conn_map *map, void *addr, 
		int count, socklen_t addrlen, uint16_t *key_table, int port);
int sock_rdm_connect_conn_map(struct sock_conn_map *map, void *addr, 
		int count, socklen_t addrlen, uint16_t *key_table, int port);
int sock_conn_map_set_key(struct sock_conn_map *conn_map, uint16_t *key_p,
			  struct sockaddr_storage *addr);
int sock_conn_listen(struct sock_domain *domain);
int sock_conn_map_clear_pe_entry(struct sock_conn *conn_entry, 
		uint16_t key);
void sock_conn_map_destroy(struct sock_conn_map *cmap);


struct sock_pe *sock_pe_init(struct sock_domain *domain);
int sock_pe_add_tx_ctx(struct sock_pe *pe, struct sock_tx_ctx *ctx);
int sock_pe_add_rx_ctx(struct sock_pe *pe, struct sock_rx_ctx *ctx);
int sock_pe_progress_rx_ctx(struct sock_pe *pe, struct sock_rx_ctx *rx_ctx);
int sock_pe_progress_tx_ctx(struct sock_pe *pe, struct sock_tx_ctx *tx_ctx);
void sock_pe_finalize(struct sock_pe *pe);


void free_fi_info(struct fi_info *info);

#endif
