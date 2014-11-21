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

int sock_av_lookup_addr(struct sock_av *av, 
		fi_addr_t addr, struct sock_conn **entry)
{
	int index = ((uint64_t)addr & av->mask);
	uint16_t key;

	if (index >= av->stored || index < 0) {
		SOCK_LOG_ERROR("requested rank is larger than av table\n");
		return -EINVAL;
	}

	if (!av->cmap) {
		SOCK_LOG_ERROR("EP with no AV bound\n");
		return -EINVAL;
	}

	key = av->key_table[index];

	if (!key) {
		if(sock_conn_map_set_key(av->cmap, &key, &av->addr_table[index])) {
			SOCK_LOG_ERROR("failed to set key\n");
			return -EINVAL;
		}
		av->key_table[index] = key;
	}
	sock_conn_map_lookup_key(av->cmap, key, entry);

	return 0;
}

static inline int check_table_in(struct sock_av *_av, struct sockaddr_in *addr,
		int count)
{
	int i;

	if (!_av->count) {
		_av->key_table = (uint16_t*)calloc(count, sizeof(uint16_t));
		_av->addr_table = (struct sockaddr_storage*)calloc(count, sizeof(struct
					sockaddr_storage));
		if (!_av->key_table || !_av->addr_table) {
			return -ENOMEM;
		}

		for (i=0; i<count; i++) {
			memcpy(&_av->addr_table[i], &addr[i], sizeof(struct sockaddr_in));
		}
		_av->count = _av->stored = count;
	} else {
		if (_av->stored + count > _av->count) {
			int new_size;
			new_size = MAX(_av->count, count) * 2;
			_av->key_table = (uint16_t*)realloc(_av->key_table, 
					new_size * sizeof(uint16_t));
			_av->addr_table = (struct sockaddr_storage*)realloc(_av->addr_table,
					new_size * sizeof(struct sockaddr_storage));
			if (!_av->key_table || !_av->addr_table) {
				return -ENOMEM;
			}

			/* init new allocated key_table */
			memset(&_av->key_table[_av->count], 0, (new_size -
						_av->count)*sizeof(uint16_t));

			_av->count = new_size;
		}

		for (i=0; i<count; i++) {
			memcpy(&_av->addr_table[_av->stored+i], &addr[i], sizeof(struct
						sockaddr_in));
		}
	}

	return 0;
}

static int sock_at_insert(struct fid_av *av, const void *addr, size_t count,
			  fi_addr_t *fi_addr, uint64_t flagsi, void *context)
{
	struct sock_av *_av;

	_av = container_of(av, struct sock_av, av_fid);

	switch(((struct sockaddr *)addr)->sa_family) {
		case AF_INET:
			if (_av->addrlen != sizeof(struct sockaddr_in)) {
				SOCK_LOG_ERROR("Invalid address type\n");
				return -EINVAL;
			}
			return check_table_in(_av, (struct sockaddr_in *)addr, count);
		default:
			SOCK_LOG_ERROR("inserted address not supported\n");
			return -EINVAL;
	}
}

static int sock_at_remove(struct fid_av *av, fi_addr_t *fi_addr, size_t count,
			  uint64_t flags)
{
	return 0;
}

static int sock_at_lookup(struct fid_av *av, fi_addr_t fi_addr, void *addr,
			  size_t *addrlen)
{
	int index;
	struct sock_conn *entry;
	struct sock_av *_av;

	_av = container_of(av, struct sock_av, av_fid);
	index = ((uint64_t)fi_addr & _av->mask);
	if (index >= _av->count || index < 0) {
		SOCK_LOG_ERROR("requested rank is larger than av table\n");
		return -EINVAL;
	}

	sock_conn_map_lookup_key(_av->cmap, _av->key_table[index], &entry);
	addr = &entry->addr;
	*addrlen = _av->addrlen;
	return 0;
}

static const char * sock_at_straddr(struct fid_av *av, const void *addr,
				    char *buf, size_t *len)
{
	return NULL;
}

static int sock_am_insert(struct fid_av *av, const void *addr, size_t count,
			  fi_addr_t *fi_addr, uint64_t flags, void *context)
{
#if 0
	const struct sockaddr_in *sin;
	struct sockaddr_in *fin;

	if (flags)
		return -FI_EBADFLAGS;
	if (sizeof(void *) != sizeof(*sin))
		return -FI_ENOSYS;

	sin = addr;
	fin = (struct sockaddr_in *) fi_addr;
	for (i = 0; i < count; i++)
		memcpy(&fin[i], &sin[i], sizeof(*sin));
#endif
	int i;
	sock_at_insert(av, addr, count, fi_addr, flags, context);
	for (i = 0; i < count; i++)
		fi_addr[i] = (fi_addr_t)i;

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
	sock_at_lookup(av, fi_addr, addr, addrlen);
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

	if (attr->flags)
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

	atomic_init(&_av->ref, 0);
	atomic_inc(&dom->ref);
	_av->dom = dom;
	switch (dom->info.addr_format) {
	case FI_SOCKADDR:
		_av->addrlen = sizeof(struct sockaddr);
		break;
	case FI_SOCKADDR_IN:
		_av->addrlen = sizeof(struct sockaddr_in);
		break;
	case FI_SOCKADDR_IN6:
		_av->addrlen = sizeof(struct sockaddr_in6);
		break;
	default:
		SOCK_LOG_ERROR("Invalid address format\n");
		return -EINVAL;
	}
	if (attr->rx_ctx_bits > 63) {
		SOCK_LOG_ERROR("Invalid rx_ctx_bits\n");
		return -EINVAL;
	}
	_av->rx_ctx_bits = attr->rx_ctx_bits;
	_av->mask = ((uint64_t)1<<(64 - attr->rx_ctx_bits + 1))-1;
	_av->attr = *attr;
	*av = &_av->av_fid;
	return 0;
}
