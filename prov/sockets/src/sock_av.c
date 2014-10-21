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

#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

#include "sock.h"
#include "sock_util.h"

static int sock_at_insert(struct fid_av *av, const void *addr, size_t count,
			  fi_addr_t *fi_addr, uint64_t flags)
{
	int i;
	struct sock_av *_av;

	_av = container_of(av, struct sock_av, av_fid);
	_av->table = calloc(count, sizeof(struct sockaddr_in));
	if (!_av->table)
		return -ENOMEM;

	for (i=0; i<count; i++) {
		memcpy(&_av->table[i], &((struct sockaddr_in *)addr)[i], sizeof(struct sockaddr_in));
	}
	_av->count = count;

	return 0;
}

static int sock_at_remove(struct fid_av *av, fi_addr_t *fi_addr, size_t count,
			  uint64_t flags)
{
	return 0;
}

static int sock_at_lookup(struct fid_av *av, fi_addr_t fi_addr, void *addr,
			  size_t *addrlen)
{
	int idx;
	idx = (int)(int64_t)fi_addr;
	struct sock_av *_av;

	_av = container_of(av, struct sock_av, av_fid);
	if (idx >= _av->count || idx < 0)
		return -EINVAL;
	memcpy(addr, &_av->table[idx], min(*addrlen, sizeof(struct sockaddr_in)));
	*addrlen = sizeof(struct sockaddr_in);
	return 0;
}

static const char * sock_at_straddr(struct fid_av *av, const void *addr,
				    char *buf, size_t *len)
{
	return NULL;
}

static int sock_am_insert(struct fid_av *av, const void *addr, size_t count,
			  fi_addr_t *fi_addr, uint64_t flags)
{
	const struct sockaddr_in *sin;
	struct sockaddr_in *fin;
	int i;

	if (flags)
		return -FI_EBADFLAGS;
	if (sizeof(void *) != sizeof(*sin))
		return -FI_ENOSYS;

	sin = addr;
	fin = (struct sockaddr_in *) fi_addr;
	for (i = 0; i < count; i++)
		memcpy(&fin[i], &sin[i], sizeof(*sin));

	return 0;
}

static int sock_am_remove(struct fid_av *av, fi_addr_t *fi_addr, size_t count,
			  uint64_t flags)
{
	return 0;
}

static int sock_am_lookup(struct fid_av *av, fi_addr_t fi_addr, void *addr,
			  size_t *addrlen)
{
	memcpy(addr, &fi_addr, min(*addrlen, sizeof(struct sockaddr_in)));
	*addrlen = sizeof(struct sockaddr_in);
	return 0;
}

static const char * sock_am_straddr(struct fid_av *av, const void *addr,
				    char *buf, size_t *len)
{
	const struct sockaddr_in *sin;
	char straddr[24];
	int size;

	sin = addr;
	size = snprintf(straddr, sizeof straddr, "%s:%d",
			inet_ntoa(sin->sin_addr), sin->sin_port);
	snprintf(buf, *len, "%s", straddr);
	*len = size + 1;
	return buf;
}

static int sock_av_bind(struct fid *fid, struct fid *bfid, uint64_t flags)
{
	return -FI_ENOSYS;
}

static int sock_av_close(struct fid *fid)
{
	struct sock_av *av;

	av = container_of(fid, struct sock_av, av_fid.fid);
	if (atomic_get(&av->ref))
		return -FI_EBUSY;

	atomic_dec(&av->dom->ref);
	free(av);
	return 0;
}

static struct fi_ops sock_av_fi_ops = {
	.size = sizeof(struct fi_ops),
	.close = sock_av_close,
	.bind = sock_av_bind,
	.sync = fi_no_sync,
	.control = fi_no_control,
	.ops_open = fi_no_ops_open,
};

static struct fi_ops_av sock_am_ops = {
	.size = sizeof(struct fi_ops_av),
	.insert = sock_am_insert,
	.remove = sock_am_remove,
	.lookup = sock_am_lookup,
	.straddr = sock_am_straddr
};

static struct fi_ops_av sock_at_ops = {
	.size = sizeof(struct fi_ops_av),
	.insert = sock_at_insert,
	.remove = sock_at_remove,
	.lookup = sock_at_lookup,
	.straddr = sock_at_straddr
};

//static struct fi_ops_av sock_av_ops = {
//	.size = sizeof(struct fi_ops_av),
//	.insert = sock_av_insert,
//	.remove = sock_av_remove,
//	.lookup = sock_av_lookup,
//	.straddr = sock_av_straddr
//};

#if 0
static int sock_open_am(struct sock_domain *dom, struct fi_av_attr *attr,
			struct sock_av **av, void *context)
{
	struct sock_av *_av;

	_av = calloc(1, sizeof(*_av));
	if (!_av)
		return -FI_ENOMEM;

	_av->av_fid.fid.fclass = FI_CLASS_AV;
	_av->av_fid.fid.context = context;
	_av->av_fid.fid.ops = &sock_av_fi_ops;
	_av->av_fid.ops = &sock_am_ops;

	*av = _av;
	return 0;
}
#endif

int sock_av_open(struct fid_domain *domain, struct fi_av_attr *attr,
		 struct fid_av **av, void *context)
{
	struct sock_domain *dom;
	struct sock_av *_av;
//	int ret;

	if (attr->name || attr->flags)
		return -FI_ENOSYS;

	dom = container_of(domain, struct sock_domain, dom_fid);

	_av = calloc(1, sizeof(*_av));
	if (!_av)
		return -FI_ENOMEM;

	_av->av_fid.fid.fclass = FI_CLASS_AV;
	_av->av_fid.fid.context = context;
	_av->av_fid.fid.ops = &sock_av_fi_ops;

	switch (attr->type) {
	case FI_AV_MAP:
//		ret = sock_open_am(dom, attr, &_av, context);
		_av->av_fid.ops = &sock_am_ops;
		break;
	case FI_AV_TABLE:
		_av->av_fid.ops = &sock_at_ops;
		break;
	default:
		return -FI_ENOSYS;
	}
#if 0
	if (ret)
		return ret;
#endif

	atomic_init(&_av->ref);
	atomic_inc(&dom->ref);
	_av->dom = dom;
	_av->attr = *attr;
	*av = &_av->av_fid;
	return 0;
}

struct sockaddr *_sock_av_lookup_addr(struct sock_ep *ep, fi_addr_t addr)
{
	if(ep->av->attr.type == FI_AV_MAP)
		return (struct sockaddr*) addr;
	
	if (addr >= ep->av->count || addr < 0) {
		sock_debug(SOCK_ERROR, "Invalid address for lookup\n");
		return NULL;
	}	

	switch (ep->info.addr_format){

	case FI_SOCKADDR:
	{
		struct sockaddr *table = (struct sockaddr*)ep->av->table;
		return (struct sockaddr*)&table[addr];
	}

	case FI_SOCKADDR_IN:
	{
		struct sockaddr_in *table = (struct sockaddr_in*)ep->av->table;
		return (struct sockaddr*)&table[addr];
	}

	case FI_SOCKADDR_IN6:
	{
		struct sockaddr_in6 *table = (struct sockaddr_in6*)ep->av->table;
		return (struct sockaddr*)&table[addr];
	}
	default:
		sock_debug(SOCK_ERROR, "Invalid address for lookup\n");
		return NULL;
	}
}
				      

fi_addr_t _sock_av_lookup_in(struct sock_av *av, struct sockaddr *addr)
{
	int i;
	struct sockaddr_in *addrin;
	struct sockaddr_in *table;

	if (av->attr.type == FI_AV_MAP) {
		return (fi_addr_t)addr;
	} else {
		addrin = (struct sockaddr_in*)addr;
		table = (struct sockaddr_in*) av->table;
		for (i = 0 ; i < av->count ; i++) {
			if (table[i].sin_addr.s_addr == addrin->sin_addr.s_addr &&
			    table[i].sin_port == addrin->sin_port)
				return (fi_addr_t)i;
		}
		sock_debug(SOCK_ERROR, "[sock] failed to lookup src_addr in av table\n");
	}
	return FI_ADDR_UNSPEC;
}

fi_addr_t _sock_av_lookup_in6(struct sock_av *av, struct sockaddr *addr)
{
	if (av->attr.type == FI_AV_MAP) {
		return (fi_addr_t)addr;
	} else {
		/* TODO */
	}
	return FI_ADDR_UNSPEC;
}

socklen_t _sock_addrlen(struct sock_ep *ep)
{
	switch(ep->info.addr_format){
	case FI_SOCKADDR:
		return sizeof(struct sockaddr);
	case FI_SOCKADDR_IN:
		return sizeof(struct sockaddr_in);
	case FI_SOCKADDR_IN6:
		return sizeof(struct sockaddr_in6);
	default:
		sock_debug(SOCK_ERROR, "Invalid address format\n");
		return 0;
	}
}

