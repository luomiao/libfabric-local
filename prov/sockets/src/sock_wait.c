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

#define READ_FD (0)
#define WRITE_FD (1)

int sock_wait_get_obj(struct sock_wait *wait, void *arg)
{
	void *obj_ptr;
	int obj_size;
	enum fi_wait_obj obj_type;
	struct fi_wait_obj_set *wait_obj_set;
	struct {
		pthread_mutex_t *mutex;
		pthread_cond_t *cond;
	} mutex_cond;

	wait_obj_set = (struct fi_wait_obj_set*)arg;

	if (!arg)
		return -EINVAL;

	if (wait) {
		switch (wait->type) {
		case FI_WAIT_FD:
			obj_size = sizeof(wait->fd[0]);
			obj_type = wait->type;
			obj_ptr = &wait->fd[0];
			break;
			
		case FI_WAIT_MUT_COND:
			mutex_cond.mutex = &wait->mutex;
			mutex_cond.cond = &wait->cond;
			obj_size = sizeof(mutex_cond);
			obj_type = wait->type;
			obj_ptr = &mutex_cond;
			break;
			
		default:
			SOCK_LOG_ERROR("Invalid wait obj type\n");
			return -FI_EINVAL;
		}
	}

	if (obj_size) {
		if (wait_obj_set->count)
			memcpy(wait_obj_set->obj, obj_ptr, obj_size);
	}
	
	wait_obj_set->count = 1;
	wait_obj_set->wait_obj = obj_type;
	return 0;
}

static int sock_verify_wait_attr(struct fi_wait_attr *attr)
{
	if (attr) {
		switch (attr->wait_obj) {
		case FI_WAIT_UNSPEC:
		case FI_WAIT_FD:
		case FI_WAIT_MUT_COND:
			break;
	 
		default:
			SOCK_LOG_ERROR("Invalid wait object type\n");
			return -FI_EINVAL;
		}
	}
	return 0;
}

static int sock_wait_init(struct sock_wait *wait, enum fi_wait_obj type)
{
	long flags = 0;
	wait->type = type;
	
	switch (type) {
	case FI_WAIT_UNSPEC:
	case FI_WAIT_FD:
		if (socketpair(AF_UNIX, SOCK_STREAM, 0, wait->fd))
			return -errno;
		
		fcntl(wait->fd[READ_FD], F_GETFL, &flags);
		if (fcntl(wait->fd[READ_FD], F_SETFL, flags | O_NONBLOCK)) {
			close(wait->fd[READ_FD]);
			close(wait->fd[WRITE_FD]);
			return -errno;
		}
		break;
		
	case FI_WAIT_MUT_COND:
		pthread_mutex_init(&wait->mutex, NULL);
		pthread_cond_init(&wait->cond, NULL);
		break;
		
	default:
		SOCK_LOG_ERROR("Invalid wait object type\n");
		return -FI_EINVAL;
	}	
	return 0;
}

int sock_wait_wait(struct fid_wait *wait_fid, int timeout)
{
	struct sock_wait *wait;
	int err = 0;
	
	wait = container_of(wait_fid, struct sock_wait, wait_fid);
	switch (wait->type) {
	case FI_WAIT_FD:
		err = fi_poll_fd(wait->fd[READ_FD], timeout);
		if (err > 0)
			err = 0;
		else if (err == 0)
			err = -FI_ETIMEDOUT;
		break;

	case FI_WAIT_MUT_COND:
		err = fi_wait_cond(&wait->cond,
				   &wait->mutex, timeout);
		break;

	default:
		SOCK_LOG_ERROR("Invalid wait object type\n");
		return -FI_EINVAL;
	}
	return err;
}

void sock_wait_signal(struct fid_wait *wait_fid)
{
	struct sock_wait *wait;
	static char c = 'x';

	wait = container_of(wait_fid, struct sock_wait, wait_fid);

	switch (wait->type) {
	case FI_WAIT_FD:
		write(wait->fd[WRITE_FD], &c, 1);
		break;
		
	case FI_WAIT_MUT_COND:
		pthread_cond_signal(&wait->cond);
		break;
	default:
		SOCK_LOG_ERROR("Invalid wait object type\n");
		return;
	}
}

static struct fi_ops_wait sock_wait_ops = {
	.size = sizeof(struct fi_ops_wait),
	.wait = sock_wait_wait,
};

static int sock_wait_close(fid_t fid)
{
	struct sock_wait *wait;

	wait = container_of(fid, struct sock_wait, wait_fid);
	if (wait->type == FI_WAIT_FD) {
		close(wait->fd[READ_FD]);
		close(wait->fd[WRITE_FD]);
	}
	free(wait);
	return 0;
}

static struct fi_ops sock_wait_fi_ops = {
	.size = sizeof(struct fi_ops),
	.close = sock_wait_close,
	.bind = fi_no_bind,
	.control = fi_no_control,
	.ops_open = fi_no_ops_open,
};

int sock_wait_open(struct fid_domain *domain, struct fi_wait_attr *attr,
		   struct fid_wait **waitset)
{
	int err;
	struct sock_wait *wait;
	struct sock_domain *dom;
	enum fi_wait_obj wait_obj_type;


	if(attr && sock_verify_wait_attr(attr))
		return -FI_EINVAL;
	
	dom = container_of(domain, struct sock_domain, dom_fid);
	if (!attr || attr->wait_obj == FI_WAIT_UNSPEC)
		wait_obj_type = FI_WAIT_FD;
	
	wait = calloc(1, sizeof(*wait));
	if (!wait)
		return -FI_ENOMEM;
	
	err = sock_wait_init(wait, wait_obj_type);
	if (err) {
		free(wait);
		return err;
	}
	
	wait->wait_fid.fid.fclass = FI_CLASS_WAIT;
	wait->wait_fid.fid.context = 0;
	wait->wait_fid.fid.ops = &sock_wait_fi_ops;
	wait->wait_fid.ops = &sock_wait_ops;
	wait->domain = dom;
	wait->type = wait_obj_type;

	*waitset = &wait->wait_fid;
	return 0;
}
