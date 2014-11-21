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
	getaddrinfo(sa_ip, map->dom->service, &hints, &c_res);
	conn_fd = socket(c_res->ai_family, c_res->ai_socktype, 0);
	if (conn_fd < 0) {
		SOCK_LOG_ERROR("failed to create conn_fd, errno: %d\n", errno);
		return 0;
	}

	while (connect(conn_fd, c_res->ai_addr, c_res->ai_addrlen)) {
		SOCK_LOG_ERROR("connect to %s:%s failed with errno: %d\n", 
				sa_ip, map->dom->service, errno);
		if (errno != ETIMEDOUT)
			return 0;
	}

	memcpy(&map->table[map->used].addr, c_res->ai_addr, c_res->ai_addrlen);
	map->table[map->used].sock_fd = conn_fd;
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

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE;

	if(getaddrinfo(NULL, domain->service, &hints, &s_res)) {
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
		map->table[map->used].sock_fd = conn_fd;
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
