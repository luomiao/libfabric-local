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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/types.h>

#include "sock.h"

#define SOCK_EQ_DEF_LEN (128)

ssize_t sock_eq_read(struct fid_eq *eq, enum fi_eq_event *event, void *buf, size_t len,
		     uint64_t flags)
{
/*
	void *entry;
	sock_eq_t *sock_eq;

	sock_eq = container_of(eq, sock_eq_t, eq);
	if(!sock_eq)
		return -FI_ENOENT;

	if(peek_list(sock_eq->eq_error_list)
		return -FI_EAVAIL;

	if(FI_PEEK & flags)
		entry = peek_list(sock_eq->eq_list);
	else{
		entry = dequeue_list(sock_eq->eq_list);
		if(entry){
			int read_done = 0;
			do{
				char tmp;
				read_done = read(sock_eq->fd[SOCK_RD_FD], &tmp, 1);
			}while(read_done == 1);
		}
	}
	
	if(entry){
		memcpy(buf, entry, MIN(len, entry_len));
		if(event)
			*event = *((enum fi_eq_event *)entry);

		if(!(FI_PEEK & flags))
			free(entry);
		return MIN(len, entry_len);
	}
*/
	return 0;
}

ssize_t sock_eq_readerr(struct fid_eq *eq, struct fi_eq_err_entry *buf,
		     size_t len, uint64_t flags)
{
/*
	void *entry;
	size_t entry_len;
	sock_eq_t *sock_eq;

	sock_eq = container_of(eq, sock_eq_t, eq);
	if(!sock_eq)
		return -FI_ENOENT;

	entry = dequeue_list(sock_eq->eq_error_list, &entry_len);

	if(entry){
		memcpy(buf, entry, MIN(len, entry_len));
		free(entry);
		return MIN(len, entry_len);
	}
	return 0;
*/
}

static ssize_t _sock_eq_write(sock_eq_t *sock_eq, const void *buf, size_t len)
{
/*
	int ret;
	void *data = malloc(len);
	if(!data)
		return -FI_ENOMEM;

	if((ret = write(sock_eq->fd[SOCK_WR_FD], data, 1)) < 0)
		return ret;

	ret = enqueue_list(sock_eq->eq_list, data, len);
	return (ret == 0) ? len : ret;
*/
}

static ssize_t _sock_eq_error_write(sock_eq_t *sock_eq, const void *buf, size_t len)
{
/*
	int ret;
	void *data = malloc(len);
	if(!data)
		return -FI_ENOMEM;
	
	ret = enqueue_list(sock_eq->eq_error_list, data, len);
	return (ret == 0) ? len : ret;
*/
}

ssize_t sock_eq_write(struct fid_eq *eq, enum fi_eq_event event, const void *buf, size_t len,
		      int64_t flags)
{
	sock_eq_t *sock_eq;
	sock_eq = container_of(eq, sock_eq_t, eq);
	if(!sock_eq)
		return -FI_ENOENT;

	if(!(sock_eq->attr.flags & FI_WRITE))
		return -FI_EINVAL;
	
	return _sock_eq_write(sock_eq, buf, len);
}

ssize_t sock_eq_sread(struct fid_eq *eq, enum fi_eq_event *event, 
			  void *buf, size_t len, int timeout, uint64_t flags)
{
	int ret;
	fd_set rfds;
	struct timeval tv;
	sock_eq_t *sock_eq;

	sock_eq = container_of(eq, sock_eq_t, eq);
	if(!sock_eq)
		return -FI_ENOENT;

	FD_ZERO(&rfds);
	FD_SET(sock_eq->fd[SOCK_RD_FD], &rfds);
	tv.tv_sec = timeout;
	tv.tv_usec = 0;

	ret = select(1, &rfds, NULL, NULL, &tv);
	
	if (ret == -1 || ret == 0)
		return ret;
	else
		return sock_eq_read(eq, event, buf, len, flags);
}

const char * sock_eq_strerror(struct fid_eq *eq, int prov_errno,
			      const void *err_data, void *buf, size_t len)
{
	if (buf && len)
		strncpy(buf, strerror(prov_errno), len);
	return strerror(prov_errno);
}

static struct fi_ops_eq sock_eq_ops = {
	.size = sizeof(struct fi_ops_eq),
	.read = sock_eq_read,
	.readerr = sock_eq_readerr,
	.write = sock_eq_write,
	.sread = sock_eq_sread,
	.strerror = sock_eq_strerror,
};

int sock_eq_fi_close(struct fid *fid)
{
	sock_eq_t *sock_eq;
	sock_eq = container_of(fid, sock_eq_t, eq.fid);
	if(!sock_eq)
		return -FI_ENOENT;

	free_list(sock_eq->eq_list);
	free(sock_eq);
	return 0;
}

int sock_eq_fi_bind(struct fid *fid, struct fid *bfid, uint64_t flags)
{
	return -FI_ENOSYS;
}

int sock_eq_fi_sync(struct fid *fid, uint64_t flags, void *context)
{
	return -FI_ENOSYS;
}

int sock_eq_fi_control(struct fid *fid, int command, void *arg)
{
	/* TODO: */
	return -FI_ENOSYS;
}

int sock_eq_fi_open(struct fid *fid, const char *name,
		    uint64_t flags, void **ops, void *context)
{
	return -FI_ENOSYS;
}

static struct fi_ops sock_eq_fi_ops = {
	.size = sizeof(struct fi_ops),
	.close = sock_eq_fi_close,
	.bind = sock_eq_fi_bind,
	.sync = sock_eq_fi_sync,
	.control = sock_eq_fi_control,
	.ops_open = sock_eq_fi_open,
};

int sock_eq_open(struct fid_fabric *fabric, struct fi_eq_attr *attr,
		 struct fid_eq **eq, void *context)
{
	int ret;
	long flags;

	if(attr && attr->wait_obj != FI_WAIT_UNSPECIFIED)
		return -FI_ENOSYS;

	sock_eq_t *sock_eq = (sock_eq_t *)calloc(1, sizeof(sock_eq_t));
	if(!sock_eq)
		return -FI_ENOMEM;

	sock_eq->eq.fid.fclass = FI_CLASS_EQ;
	sock_eq->eq.fid.context = context;
	sock_eq->eq.fid.ops = &sock_eq_fi_ops;

	sock_eq->eq.ops = &sock_eq_ops;			
	sock_eq->context = context;

	ret = socketpair(AF_UNIX, 0, 0, sock_eq->fd);
	if (ret)
		goto err1;

	fcntl(sock_eq->fd[SOCK_RD_FD], F_GETFL, &flags);
	ret = fcntl(sock_eq->fd[SOCK_RD_FD], F_SETFL, flags | O_NONBLOCK);
	if (ret) {
		ret = -errno;
		goto err1;
	}

	sock_eq->eq_list = new_list( (attr && attr->size >0)? attr->size :
				     SOCK_EQ_DEF_LEN);
	if(!sock_eq->eq_list)
		goto err1;

	sock_eq->eq_error_list = new_list( (attr && attr->size >0)? attr->size :
				     SOCK_EQ_DEF_LEN);
	if(!sock_eq->eq_error_list)
		goto err2;
	
	memcpy(&(sock_eq->attr), attr, sizeof(struct fi_eq_attr));
	return 0;

err2:
	free_list(sock_eq->eq_list);
err1:
	free(sock_eq);
	return -FI_EAVAIL;
}
