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

static struct fi_ops_fabric sock_fab_ops = {
	.size = sizeof(struct fi_ops_fabric),
	.domain = sock_domain,
	/*.endpoint = sock_pendpoint,*/
	/*.eq_open = sock_eq_open,*/
};

static int sock_fabric_close(fid_t fid)
{
	free(fid);
	return 0;
}

int sock_fabric_bind(struct fid *fid, struct fid *bfid, uint64_t flags)
{
	return -FI_ENOSYS;
}

int sock_fabric_sync(struct fid *fid, uint64_t flags, void *context)
{
	return -FI_ENOSYS;
}

int sock_fabric_control(struct fid *fid, int command, void *arg)
{
	return -FI_ENOSYS;
}

int sock_fabric_ops_open(struct fid *fid, const char *name,
		    uint64_t flags, void **ops, void *context)
{
	return -FI_ENOSYS;
}

static struct fi_ops sock_fab_fi_ops = {
	.size = sizeof(struct fi_ops),
	.close = sock_fabric_close,
	.bind = sock_fabric_bind,
	.sync = sock_fabric_sync,
	.control = sock_fabric_control,
	.ops_open = sock_fabric_ops_open,
};

static int sock_fabric(struct fi_fabric_attr *attr,
		       struct fid_fabric **fabric, void *context)
{
	sock_fabric_t *fab;

	if (strcmp(attr->name, fab_name))
		return -FI_ENODATA;

	fab = calloc(1, sizeof(*fab));
	if (!fab)
		return -FI_ENOMEM;

	fab->fab_fid.fid.fclass = FI_CLASS_FABRIC;
	fab->fab_fid.fid.context = context;
	fab->fab_fid.fid.ops = &sock_fab_fi_ops;
	fab->fab_fid.ops = &sock_fab_ops;
	*fabric = &fab->fab_fid;
	return 0;
}

static int sock_getinfo(uint32_t version, const char *node, const char *service,
			uint64_t flags, struct fi_info *hints, struct fi_info **info)
{
	char *tmp = getenv("SFI_SOCK_DEBUG_LEVEL");
	if (tmp){
		sock_debug_level = atoi(tmp);
	}else{
		sock_debug_level = SOCK_ERROR;
	}

	if (hints) {
		switch (hints->ep_type) {
		case FI_EP_RDM:
			return sock_rdm_getinfo(version, node, service, flags,
						hints, info);
		case FI_EP_DGRAM:
			return sock_dgram_getinfo(version, node, service, flags,
						hints, info);
		default:
			return -FI_ENODATA;
		}
	} else {
		/* Call all socket endpoint providers. */
		return sock_rdm_getinfo(version, node, service, flags,
					hints, info);
	}

	return -FI_ENODATA;
}

int sock_freeinfo(struct fi_info *info)
{
	if(info)
		free(info);

	return 0;
}

int sock_free_info(struct fi_info *info)
{
	free_fi_info(info);
	return 0;
}

static struct fi_provider sock_prov = {
	.name = fab_name,
	.version = FI_VERSION(SOCK_MAJOR_VERSION, SOCK_MINOR_VERSION), 
	.getinfo = sock_getinfo,
	.freeinfo = sock_free_info,
	.fabric = sock_fabric,
};

static void __attribute__((constructor)) sock_ini(void)
{
	(void) fi_register(&sock_prov);
}

static void __attribute__((destructor)) sock_fini(void)
{
}
