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

#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/time.h>
#include <unistd.h>
#include <pthread.h>

#include "sock.h"
#include "sock_util.h"


int sock_comm_send_socket(struct sock_conn *conn, const void *buf, size_t len, 
			uint64_t flags)
{
	int ret;

	ret = send(conn->sock_fd, buf, len, flags);
	if (ret < 0) {
		if (ret == EWOULDBLOCK || ret == EAGAIN)
			return 0;
		else{
			SOCK_LOG_ERROR("Failed to send [buf:%p, len:%lu, flags: %lx]\n",
				       buf, (long unsigned int)len, (long unsigned int)flags);
			return ret;
		}		
	}	
	SOCK_LOG_INFO("Sent %lu on wire\n", len);
	return ret;
}

int sock_comm_send_flush(struct sock_conn *conn)
{
	int ret;
	size_t endlen, len;

	rbcommit(&conn->outbuf);
	len = rbused(&conn->outbuf);
	endlen = conn->outbuf.size - (conn->outbuf.rcnt & conn->outbuf.size_mask);
	if (len <= endlen) {
		ret = sock_comm_send_socket(
			conn, 
			conn->outbuf.buf + 
			(conn->outbuf.rcnt & conn->outbuf.size_mask), 
			len, 0);
		if (ret < 0)
			return ret;
		conn->outbuf.rcnt += ret;
		SOCK_LOG_INFO("Sent out part: %lu\n", ret);
		return ret;
	} 

	ret = sock_comm_send_socket(
		conn,
		conn->outbuf.buf + 
		(conn->outbuf.rcnt & conn->outbuf.size_mask),
		len - endlen, 0);
	if (ret < 0 || ret != endlen) {
		SOCK_LOG_INFO("Sent out part: %lu\n", ret);
		conn->outbuf.rcnt += ret;
		return ret;
	}

	conn->outbuf.rcnt += ret;
	SOCK_LOG_INFO("Sent out: %lu\n", ret);
	ret = sock_comm_send_socket(conn,
				    conn->outbuf.buf, len - endlen, 0);
	if (ret < 0)
		return ret;

	conn->outbuf.rcnt += ret;
	SOCK_LOG_INFO("Sent out: %lu\n", ret);
	return ret + endlen;
}


int sock_comm_send(struct sock_conn *conn, const void *buf, size_t len, 
			uint64_t flags) 
{
	int ret;

	if (rbavail(&conn->outbuf) < len) {
		ret = sock_comm_send_flush(conn);
		if (ret != 0)
			return 0;
		return sock_comm_send_socket(conn, buf, len, flags);
	}

	rbwrite(&conn->outbuf, buf, len);
	SOCK_LOG_INFO("Buffered %lu\n", len);
	return len;
}



int sock_comm_recv_socket(struct sock_conn *conn, void *buf, size_t len, 
			uint64_t flags)
{
	int ret;
	
	ret = recv(conn->sock_fd, buf, len, flags);
	if (ret < 0) {
		if (ret == EWOULDBLOCK || ret == EAGAIN)
			return 0;
		else{
			SOCK_LOG_ERROR("Failed to recv [buf:%p, len:%lu, flags: %lx]\n",
				       buf, (long unsigned int)len, (long unsigned int)flags);
			return ret;
		}
	}
	SOCK_LOG_INFO("Read %lu from socket\n", ret);
	return ret;
}

int sock_comm_try_recv(struct sock_conn *conn)
{
	int ret;
	size_t avail, endlen, used, size;

	used = rbused(&conn->inbuf);
	avail = rbavail(&conn->inbuf);
	size = conn->inbuf.size;

	SOCK_LOG_INFO("INBUF: avail:%llu, used:%llu, size: %llu\n", avail, used, size);


	endlen = conn->inbuf.size - (conn->inbuf.wpos & conn->inbuf.size_mask);
	SOCK_LOG_INFO("Try recv: avail:%llu, endlen:%llu\n", avail, endlen);

	if (avail <= endlen) {
		ret = sock_comm_recv_socket(conn, 
					    conn->inbuf.buf + 
					    (conn->inbuf.wpos & conn->inbuf.size_mask),
					    avail, 0);
		if (ret < 0)
			return 0;
		SOCK_LOG_INFO("Read: %lu into buffer\n", ret);
		conn->inbuf.wpos += ret;
		rbcommit(&conn->inbuf);
		return 0;
	}

	ret = sock_comm_recv_socket(conn, 
				    conn->inbuf.buf + (conn->inbuf.wpos & conn->inbuf.size_mask),
				    endlen, 0);
	if (ret < 0)
		return 0;
	SOCK_LOG_INFO("Read: %lu into buffer\n", ret);
	conn->inbuf.wpos += ret;
	rbcommit(&conn->inbuf);

	if (ret < endlen)
		return ret;

	ret = sock_comm_recv_socket(conn, 
				    conn->inbuf.buf,
				    avail - endlen, 0);
	if (ret < 0)
		return 0;
	SOCK_LOG_INFO("Read: %lu into buffer\n", ret);
	conn->inbuf.wpos += ret;
	rbcommit(&conn->inbuf);
	return 0;
}



int sock_comm_recv(struct sock_conn *conn, void *buf, size_t len, 
			uint64_t flags)
{
	int ret;
	size_t used = rbused(&conn->inbuf);
	SOCK_LOG_INFO("Len in buffer: %lu\n", used);

	if (used == 0) {
		sock_comm_try_recv(conn);
		used = rbused(&conn->inbuf);
	}

	if (used >= len) {
		rbread(&conn->inbuf, buf, len);
		SOCK_LOG_INFO("Read %lu from buffer\n", len);
		return len;
	}

	if (used > 0) {
		rbread(&conn->inbuf, buf, used);
		SOCK_LOG_INFO("Read %lu from buffer\n", used);
	}

	ret = sock_comm_recv_socket(conn, (char*)buf + used, len-used, 0);
	SOCK_LOG_INFO("Read %lu directly from socket\n", ret);
	return (ret < 0) ? used : (ret + used);
}
