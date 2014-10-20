/*
 * Copyright (c) 2014, Cisco Systems, Inc. All rights reserved.
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
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
#ifndef _USDF_H_
#define _USDF_H_

#define USDF_FI_NAME "usnic"
#define USDF_HDR_BUF_ENTRY 64
#define USDF_EP_CAP_PIO (1ULL << 63)
#define USDF_CAPS (FI_MSG | FI_SOURCE | FI_SEND | FI_RECV)

#define USDF_SUPP_MODE (FI_LOCAL_MR | FI_MSG_PREFIX)
#define USDF_REQ_MODE (FI_LOCAL_MR)

struct usdf_fabric {
	struct fid_fabric   fab_fid;
	char *fab_name;
};
#define fab_fidtou(FID) container_of(FID, struct usdf_fabric, fab_fid.fid)

struct usdf_domain {
	struct fid_domain   dom_fid;
	struct usd_device   *dom_dev;
	struct usd_device_attrs dom_dev_attrs;
};
#define dom_ftou(FDOM) container_of(FDOM, struct usdf_domain, dom_fid)
#define dom_utof(DOM) (&(DOM)->dom_fid)

struct usdf_ep {
	struct fid_ep ep_fid;
	uint64_t ep_caps;
	uint64_t ep_mode;
	uint64_t ep_req_port;
	struct usdf_domain *ep_domain;
	struct usdf_av *ep_av;
	struct usdf_cq *ep_wcq;
	struct usdf_cq *ep_rcq;
	struct usd_qp *ep_qp;
	struct usd_dest *ep_dest;
	struct usd_qp_attrs ep_qp_attrs;
	void *ep_hdr_buf;
	struct usd_udp_hdr **ep_hdr_ptr;
};
#define ep_ftou(FEP) container_of(FEP, struct usdf_ep, ep_fid)
#define ep_fidtou(FID) container_of(FID, struct usdf_ep, ep_fid.fid)
#define ep_utof(EP) (&(EP)->ep_fid)

struct usdf_mr {
	struct fid_mr mr_fid;
	struct usd_mr *mr_mr;
};

struct usdf_cq {
	struct fid_cq cq_fid;
	struct usdf_domain *cq_domain;
	struct usd_cq *cq_cq;
	struct usd_completion cq_comp;
};
#define cq_ftou(FCQ) container_of(FCQ, struct usdf_cq, cq_fid)
#define cq_fidtou(FID) container_of(FID, struct usdf_cq, cq_fid.fid)
#define cq_utof(CQ) (&(CQ).cq_fid)

struct usdf_av {
	struct fid_av av_fid;
	struct usdf_domain *av_domain;
};
#define av_ftou(FAV) container_of(FAV, struct usdf_av, av_fid)
#define av_fidtou(FID) container_of(FID, struct usdf_av, av_fid.fid)
#define av_utof(AV) (&(AV)->av_fid)


/*
 * Prototypes
 */

/* fi_ops_fabric */
int usdf_domain_open(struct fid_fabric *fabric, struct fi_info *info,
	struct fid_domain **domain, void *context);
int usdf_eq_open(struct fid_fabric *fabric, struct fi_eq_attr *attr,
	struct fid_eq **eq, void *context);

/* fi_ops_domain */
int usdf_cq_open();
int usdf_endpoint_open(struct fid_domain *domain, struct fi_info *info,
		struct fid_ep **ep, void *context);
int usdf_av_open(struct fid_domain *domain, struct fi_av_attr *attr,
		 struct fid_av **av_o, void *context);

/* fi_ops_mr */
int usdf_reg_mr(struct fid_domain *domain, const void *buf, size_t len,
	uint64_t access, uint64_t offset, uint64_t requested_key,
	uint64_t flags, struct fid_mr **mr_o, void *context);

/* fi_ops_cm for US */
int usdf_cm_ud_connect(struct fid_ep *ep, const void *addr,
	const void *param, size_t paramlen);
int usdf_cm_ud_shutdown(struct fid_ep *ep, uint64_t flags);

/* fi_ops_msg for UD */
ssize_t usdf_msg_ud_recv(struct fid_ep *ep, void *buf, size_t len, void *desc,
	void *context);
ssize_t usdf_msg_ud_recvv(struct fid_ep *ep, const struct iovec *iov,
	void **desc, size_t count, void *context);
ssize_t usdf_msg_ud_recvfrom(struct fid_ep *ep, void *buf, size_t len,
	void *desc, fi_addr_t src_addr, void *context);
ssize_t usdf_msg_ud_recvmsg(struct fid_ep *ep, const struct fi_msg *msg,
	uint64_t flags);
ssize_t usdf_msg_ud_send(struct fid_ep *ep, const void *buf, size_t len,
	void *desc, void *context);
ssize_t usdf_msg_ud_sendv(struct fid_ep *ep, const struct iovec *iov,
	void **desc, size_t count, void *context);
ssize_t usdf_msg_ud_sendto(struct fid_ep *ep, const void *buf, size_t len,
	void *desc, fi_addr_t dest_addr, void *context);
ssize_t usdf_msg_ud_sendmsg(struct fid_ep *ep, const struct fi_msg *msg,
	uint64_t flags);
ssize_t usdf_msg_ud_inject(struct fid_ep *ep, const void *buf, size_t len);
ssize_t usdf_msg_ud_injectto(struct fid_ep *ep, const void *buf, size_t len,
	fi_addr_t dest_addr);
ssize_t usdf_msg_ud_senddata(struct fid_ep *ep, const void *buf, size_t len,
	void *desc, uint64_t data, void *context);
ssize_t usdf_msg_ud_senddatato(struct fid_ep *ep, const void *buf, size_t len,
	void *desc, uint64_t data, fi_addr_t dest_addr, void *context);
ssize_t usdf_msg_ud_prefix_recv(struct fid_ep *ep, void *buf, size_t len, void *desc,
	void *context);
ssize_t usdf_msg_ud_prefix_recvv(struct fid_ep *ep, const struct iovec *iov,
	void **desc, size_t count, void *context);
	


#endif /* _USDF_H_ */
