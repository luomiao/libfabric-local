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

#include <stdlib.h>
#include <string.h>

#include "sock.h"
#include "sock_util.h"


int sock_poll_add(struct fid_poll *pollset, struct fid *event_fid, 
			 uint64_t flags)
{
	return 0;
}

int sock_poll_del(struct fid_poll *pollset, struct fid *event_fid, 
			 uint64_t flags)
{
	return 0;
}

static int sock_poll_poll(struct fid_poll *pollset, void **context, int count)
{
	return 0;
}

static int sock_poll_close(fid_t fid)
{
	return 0;
}

static int sock_wait_close(fid_t fid)
{
	return 0;
}

static struct fi_ops sock_poll_fi_ops = {
	.size = sizeof(struct fi_ops),
	.close = sock_poll_close,
	.bind = fi_no_bind,
	.control = fi_no_control,
	.ops_open = fi_no_ops_open,
};

static struct fi_ops sock_wait_fi_ops = {
	.size = sizeof(struct fi_ops),
	.close = sock_wait_close,
	.bind = fi_no_bind,
	.control = fi_no_control,
	.ops_open = fi_no_ops_open,
};


static struct fi_ops_poll sock_poll_ops = {
	.size = sizeof(struct fi_ops_poll),
	.poll = sock_poll_poll,
};

int sock_poll_open(struct fid_domain *domain, struct fi_poll_attr *attr,
		   struct fid_poll **pollset)
{
	struct sock_domain *dom;
	struct sock_poll *poll;

	dom = container_of(domain, struct sock_domain, dom_fid);

	poll = calloc(1, sizeof(*poll));
	if (!poll)
		return -FI_ENOMEM;
	
	dlist_init(&poll->head);
	poll->poll_fid.fid.fclass = FI_CLASS_POLL;
	poll->poll_fid.fid.context = 0;
	poll->poll_fid.fid.ops = &sock_poll_fi_ops;
	poll->poll_fid.ops = &sock_poll_ops;
	poll->domain = dom;
	atomic_inc(&dom->ref);

	*pollset = &poll->poll_fid;
	return 0;
}

int sock_wait_open(struct fid_domain *domain, struct fi_wait_attr *attr,
		   struct fid_wait **waitset)
{
	return -FI_ENOSYS; /* TODO */
}
