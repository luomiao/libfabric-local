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
#include <stdio.h>

#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <ifaddrs.h>

#include "sock.h"
#include "sock_util.h"

#define PORT "9931"

static inline int _init_map(struct sock_conn_map *map, int init_size) 
{
	map->table = (struct sock_conn*)calloc(init_size, 
			sizeof(struct sock_conn));
	if (!map->table) 
		return -ENOMEM;
	map->used = 0;
	map->size = init_size;
	return 0;
}

static inline int _increase_map(struct sock_conn_map *map, int new_size) 
{
	if (map->used + new_size > map->size) {
		map->size = MAX(map->size, new_size) * 2;
		map->table = (struct sock_conn*)realloc(map->table, 
				map->size * sizeof(struct sock_conn));
		if (!map->table)
			return -ENOMEM;
	}

	return 0;
}

static inline void _free_map(struct sock_conn_map *map)
{
	free(map->table);
	map->table = NULL;
	map->used = map->size = 0;
}

#if 0
int sock_conn_check_conn_map(struct sock_conn_map *map, int count)
{
	if (map->size == 0)
		return _init_map(map, count);

	if (map->used + count < map->size)
		return 0;
	else
		return _increase_map(map, count);
}
#endif

int sock_dgram_connect_conn_map(struct sock_conn_map *map, void *addr, int
		count, socklen_t addrlen, uint16_t *key_table, int port)
{
	int i;
	for (i=0; i<count; i++) {
		memcpy(&map->table[i+map->used], 
				(char *)((char*)addr + addrlen*(i+map->used)), 
				addrlen);
		key_table[i] = i + map->used + 1;
	}
	map->used += count;
	return 0;
}

#if 0
static int _sock_accept_in(struct sock_conn_map *map, struct sockaddr_in *addr, 
		uint16_t *key_table, int listen_fd, int to_accept, int count)
{
	int j, k;
	int conn_fd;
	socklen_t addr_size;
	struct sockaddr_in remote;
	char remote_ip[INET_ADDRSTRLEN];
	char cmp_ip[INET_ADDRSTRLEN];

	addr_size = sizeof(struct sockaddr_in);
	for (j=0;j<to_accept;j++) {
		conn_fd = accept(listen_fd, (struct sockaddr *)&remote, 
				&addr_size);
		if (conn_fd < 0) {
			sock_log(SOCK_ERROR, "failed to accept: %d\n", errno);
			return -errno;
		}
		memcpy(remote_ip, inet_ntoa(remote.sin_addr), INET_ADDRSTRLEN);
		for (k=0;k<count;k++) {
			memcpy(cmp_ip, inet_ntoa(addr[k].sin_addr), 
					INET_ADDRSTRLEN);
			if (!strcmp(cmp_ip, remote_ip)) {
				memcpy(&map->table[map->used].addr, &remote, 
						addr_size);
				map->table[map->used].sock_fd = conn_fd;
				key_table[k] = map->used + 1;
				map->used++;
				break;
			}
		}
		if (k==count) {
			sock_log(SOCK_ERROR, 
					"Invalid accepted connection: %s\n", 
					remote_ip);
			return -EINVAL;
		}
	}
	return 0;
}

int _connect_conn_map_in(struct sock_conn_map *map, struct sockaddr_in *addr,
		int count, uint16_t *key_table, int port)
{
	struct ifaddrs *myaddrs, *ifa;
	struct addrinfo *s_res = NULL;
	struct addrinfo *c_res = NULL;
	struct addrinfo hints;
	struct sockaddr_in *my_sa;
	struct sockaddr_in *entry;
	struct sockaddr_in *sa_p;
	char my_ip[INET_ADDRSTRLEN];
	char entry_ip[INET_ADDRSTRLEN];
	char sa_ip[INET_ADDRSTRLEN];
	int i, j, listen_fd, conn_fd;
	int to_accept = 0;
	int optval;

	if (getifaddrs(&myaddrs)) {
		sock_log(SOCK_ERROR, "getifaddrs failed\n");
		return -errno;
	}

	for (ifa=myaddrs; ifa != NULL; ifa = ifa->ifa_next) {
		if (ifa->ifa_addr == NULL)
			continue;
		if (!(ifa->ifa_flags & IFF_UP))
			continue;
		if (!(strcmp(ifa->ifa_name, "lo")))
			continue;

		if (ifa->ifa_addr->sa_family == AF_INET) {
			my_sa = (struct sockaddr_in *)ifa->ifa_addr;
			memcpy(&my_ip, inet_ntoa(my_sa->sin_addr), 
					INET_ADDRSTRLEN);
			break;
		}
	}

	if (!ifa) {
		sock_log(SOCK_ERROR, "no available IPv4 address\n");
		return -EINVAL;
	}
	freeifaddrs(myaddrs);

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE;
	if(getaddrinfo(NULL, PORT, &hints, &s_res)) {
		sock_log(SOCK_ERROR, "no available AF_INET address\n");
		return -EINVAL;
	}

#if 0
	for(addr_p = s_res; addr_p != NULL; addr_p = addr_p->ai_next) {
		if (addr_p->ai_family == AF_INET) {
			my_sa = (struct sockaddr_in *)addr_p->ai_addr;
			my_ip = inet_ntoa(my_sa->sin_addr);
			break;
		}
	}

	if (!addr_p) {
		sock_log(SOCK_ERROR, "no available IPv4 address\n");
		return -EINVAL;
	}
#endif

	for (i=0; i<count; i++) {
		/* check if this entry is already connected */
		entry = &addr[i];
		memcpy(entry_ip, inet_ntoa(entry->sin_addr), INET_ADDRSTRLEN);
		if (!strcmp(my_ip, entry_ip)) {
			to_accept = count-1-i;
			continue;
		}

		for (j=0; j < map->used; j++) {
			sa_p = (struct sockaddr_in *)&map->table[j].addr;
			memcpy(sa_ip, inet_ntoa(sa_p->sin_addr), INET_ADDRSTRLEN);
			if(!strcmp(entry_ip, sa_ip)) {
				key_table[i] = j + 1;
				to_accept--;
				break;
			}
		}
	}

	for (i=0; i<count; i++) {
		entry = &addr[i];
		memcpy(entry_ip, inet_ntoa(entry->sin_addr), INET_ADDRSTRLEN);
		if (!strcmp(my_ip, entry_ip)) {
			/* server */
			listen_fd = socket(s_res->ai_family, 
					   s_res->ai_socktype, 0);
			if (listen_fd < 0) {
				sock_log(SOCK_ERROR, 
						"failed to open socket: %d\n", 
						errno);
				goto err;
			}
			optval = 1;
			setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, 
					&optval, sizeof optval);
			if (bind(listen_fd, s_res->ai_addr, s_res->ai_addrlen)) {
				sock_log(SOCK_ERROR, 
						"failed to bind socket: %d\n", 
						errno);
				goto err;
			}
			if (listen(listen_fd, count-i-1)) {
				sock_log(SOCK_ERROR, 
						"failed to listen socket: %d\n", 
						errno);
				goto err;
			}
#if 0
			addr_size = sizeof(struct sockaddr_in);
			for (j=0;j<to_accept;j++) {
				conn_fd = accept(listen_fd, 
						(struct sockaddr *)&remote, 
						&addr_size);
				if (conn_fd < 0) {
					sock_log(SOCK_ERROR, 
							"failed to accept: %d\n", 
							errno);
					goto err;
				}
				memcpy(remote_ip, inet_ntoa(remote.sin_addr), 
						INET_ADDRSTRLEN);
				for (k=0;k<count;k++) {
					memcpy(cmp_ip, inet_ntoa(addr[k].sin_addr), INET_ADDRSTRLEN);
					if (!strcmp(cmp_ip, remote_ip)) {
						memcpy(&map->table[map->used].addr, &remote, addr_size);
						map->table[map->used].sock_fd = conn_fd;
						key_table[k] = map->used + 1;
						map->used++;
						break;
					}
				}
				if (k==count) {
					sock_log(SOCK_ERROR, "accepted connection is not found in the address table: %s\n", remote_ip);
					errno = EINVAL;
					goto err;
				}
			}
#endif
			if (_sock_accept_in(map, addr, key_table, listen_fd, to_accept, count))
				goto err;
			close(listen_fd);
			break;
		} else {
			if (!key_table[i]) {
				/* client */
				memset(&hints, 0, sizeof hints);
				hints.ai_family = AF_INET;
				hints.ai_socktype = SOCK_STREAM;
				getaddrinfo(entry_ip, PORT, &hints, &c_res);
				conn_fd = socket(c_res->ai_family, c_res->ai_socktype, 0);
				if (conn_fd < 0) {
					sock_log(SOCK_ERROR, "failed to create conn_fd, errno: %d\n", errno);
					return -errno;
				}
				/* TODO: handle connect error return; timeout? */
				while (connect(conn_fd, c_res->ai_addr, c_res->ai_addrlen));

				memcpy(&map->table[map->used].addr, c_res->ai_addr, c_res->ai_addrlen);
				map->table[map->used].sock_fd = conn_fd;
				key_table[i] = map->used + 1;
				map->used++;
			}
		}
	}

	if (s_res)
		freeaddrinfo(s_res);
	if (c_res)
		freeaddrinfo(c_res);
	return 0;
err:
	close(listen_fd);
	/* TODO: close all open sock_fd */
	return -errno;
}

int _connect_conn_map_in6(struct sock_conn_map *map, struct sockaddr_in6 *addr,
		int count, uint16_t *key_table, int port)
{
	return -ENOSYS;
}

int sock_rdm_connect_conn_map(struct sock_conn_map *map, void *addr, int count,
		socklen_t addrlen, uint16_t *key_table, int port)
{
	switch(((struct sockaddr *)addr)->sa_family) {
	case AF_INET:
		if (addrlen != sizeof(struct sockaddr_in)) {
			sock_log(SOCK_ERROR, "Invalid address type\n");
			return -EINVAL;
		}
		return _connect_conn_map_in(map, addr, count, key_table, port);
	default:
		sock_log(SOCK_ERROR, "inserted address not supported\n");
		return -EINVAL;

	}
}
#endif

void sock_conn_map_destroy(struct sock_conn_map *cmap)
{
	_free_map(cmap);
}

int sock_conn_map_lookup_key(struct sock_conn_map *conn_map, 
		uint16_t key, struct sock_conn **entry) 
{
	if (key > conn_map->used) {
		SOCK_LOG_ERROR("requested key is larger than conn_map size\n");
		return -EINVAL;
	}

	*entry = &(conn_map->table[key-1]);
	return 0;
}

static inline uint16_t _set_key(struct sock_conn_map *map, struct
		sockaddr_in *addr)
{
	int i, conn_fd;
	char entry_ip[INET_ADDRSTRLEN];
	char sa_ip[INET_ADDRSTRLEN];
	struct sockaddr_in *entry;
	struct addrinfo *c_res = NULL;
	struct addrinfo hints;
	struct sock_conn *conn;

	memcpy(sa_ip, inet_ntoa(addr->sin_addr), INET_ADDRSTRLEN);
	for (i=0; i < map->used; i++) {
		entry = (struct sockaddr_in *)&map->table[i].addr;
		memcpy(entry_ip, inet_ntoa(entry->sin_addr), INET_ADDRSTRLEN);
		if(!strcmp(entry_ip, sa_ip)) {
			return i+1;
		}
	}

	/* connect */
	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	getaddrinfo(sa_ip, PORT, &hints, &c_res);
	conn_fd = socket(c_res->ai_family, c_res->ai_socktype, 0);
	if (conn_fd < 0) {
		SOCK_LOG_ERROR("failed to create conn_fd, errno: %d\n", errno);
		return 0;
	}

	fprintf(stderr, "[_set_key] before connect\n");
	while (connect(conn_fd, c_res->ai_addr, c_res->ai_addrlen)) {
		fprintf(stderr, "[_set_key] connect failed with errno: %d\n", errno);
		if (errno != ETIMEDOUT)
			return 0;
	}
	fprintf(stderr, "[_set_key] after connect\n");

	memcpy(&map->table[map->used].addr, c_res->ai_addr, c_res->ai_addrlen);
	map->table[map->used].sock_fd = conn_fd;
	conn = &map->table[map->used];
	sock_comm_buffer_init(conn);
	map->used++;
	return map->used;

}

int sock_conn_map_set_key(struct sock_conn_map *conn_map, uint16_t *key_p,
		struct sockaddr_storage *addr)
{
	switch(((struct sockaddr *)addr)->sa_family) {
		case AF_INET:
			*key_p = _set_key(conn_map, (struct sockaddr_in *)addr);
			if (!*key_p) return -errno;
			break;
		default:
			SOCK_LOG_ERROR("inserted address not supported\n");
			return -EINVAL;
	}

	return 0;
}

static void * _sock_conn_listen(void *arg)
{
	struct sock_domain *domain = (struct sock_domain*) arg;
	struct sock_conn_map *map = &domain->r_cmap;
	struct addrinfo *s_res = NULL;
	struct addrinfo hints;
	int optval;
	int listen_fd, conn_fd;
	struct sockaddr_in remote;
	socklen_t addr_size;
	struct sock_conn *conn;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE;

	if(getaddrinfo(NULL, PORT, &hints, &s_res)) {
		SOCK_LOG_ERROR("no available AF_INET address\n");
		perror("no available AF_INET address");
		return NULL;
	}

	listen_fd = socket(s_res->ai_family, s_res->ai_socktype, 0);
	if (listen_fd < 0) {
		SOCK_LOG_ERROR("failed to open socket: %d\n", errno);
		goto err;
	}
	optval = 1;
	setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof optval);
	if (bind(listen_fd, s_res->ai_addr, s_res->ai_addrlen)) {
		SOCK_LOG_ERROR("failed to bind socket: %d\n", errno);
		goto err;
	}

	if (listen(listen_fd, 128)) {
		SOCK_LOG_ERROR("failed to listen socket: %d\n", errno);
		goto err;
	}
 
	_init_map(&domain->r_cmap, 128); /* TODO: init cmap size */
	while(domain->listening) {
		addr_size = sizeof(struct sockaddr_in);
		conn_fd = accept(listen_fd, (struct sockaddr *)&remote, &addr_size);
		SOCK_LOG_INFO("CONN: accepted conn-req: %d\n", conn_fd);
		if (conn_fd < 0) {
			SOCK_LOG_ERROR("failed to accept: %d\n", errno);
			goto err;
		}

		/* TODO: lock for multi-threads */
		if ((map->size - map->used) == 0) {
			_increase_map(map, map->size*2);
		}
		memcpy(&map->table[map->used].addr, &remote, addr_size);

		conn = &map->table[map->used];
		conn->sock_fd = conn_fd;
		sock_comm_buffer_init(conn);
		map->used++;
	}

	return NULL;

err:
	close(listen_fd);
	perror("listening thread failed");
	return NULL;
}

int sock_conn_listen(struct sock_domain *domain)
{
	domain->listening = 1;
	pthread_create(&domain->listen_thread, 0, _sock_conn_listen, domain);
	return 0;
}
