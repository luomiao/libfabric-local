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

inline void sock_pe_progress_rx_entry(struct sock_pe *pe,
				      struct sock_pe_entry *entry)
{
}

inline void sock_pe_progress_tx_entry(struct sock_pe *pe,
				      struct sock_pe_entry *entry)
{
}

static void sock_pe_progress_table(struct sock_progress_engine *engine,
				  struct sock_cq *cq)
{
	struct sock_progress_entry *entry;
	
	if(cq->table_entry == -1)
		return;

	entry = &engine->pe_table[cq->table_entry];
	while(entry != NULL){

		entry->type == SOCK_RX ? sock_pe_progress_rx_entry(engine, entry):
			sock_pe_progress_tx_entry(engine, entry);
		
		entry = entry->cq_list.next;
	}
}

static void sock_pe_progress(struct sock_progress_engine *engine,
			    struct sock_cq *cq)
{
	fastlock_acquire(&engine->engine_lock);
	
	sock_pe_progress_table(engine, cq);
	
	if(engine->free_head != -1){
		/* check for entries that can be pulled in from TX/RX for this CQ */
	}

	fastlock_release(&engine->engine_lock);
}

static void *sock_pe_progress_thread(void *data)
{
	size_t ret;
	struct sock_cq *cq;
	struct sock_progress_engine *engine = 
		(struct sock_progress_engine *)data;

	sock_debug(SOCK_INFO, "[SOCK_PROGRESS]: Progress thread started\n");

	while(engine->do_progress){

		cq = NULL;
		if(rbfdempty(&engine->cq_rb) && engine->busy_head == -1){
			ret = rbfdsread(engine->cq_rb,
					(void*)&cq, sizeof(struct sock_cq*), 1000);
			if(ret < 0)
				continue;
		}
				
		if(cq != NULL){
			sock_progress_cq(engine, cq);
			sock_progress_engine_add_cq(engine, cq);
		}

		if(engine->busy_head != -1){
			sock_progress_table(engine);
		}
	}
	return NULL;
}

static void sock_pe_init_table(
	struct sock_progress_engine *engine)
{
	int64_t i;
	
	engine->busy_head = -1;
	engine->free_head = 0;
	
	memset(&engine->pe_table, 0, 
	       sizeof(struct sock_progress_entry) * MAX_PROGRESS_ENTRIES);
	for(i=0; i<MAX_PROGRESS_ENTRIES-1; i++){
		engine->progress_entry[i].next = i+1;
	}
	engine->progress_entry[NUM_PROGRESS_ENTRIES].next = -1;
	fastlock_init(&engine->engine_lock);
}

struct sock_progress_engine *sock_pe_init(
	struct sock_domain *domain)
{
	struct sock_progress_engine *engine = 
		calloc(1, struct sock_progress_engine);
	if(!engine)
		return NULL;

	sock_pe_init_table(engine);

	if(rbfdinit(&engine->cq_rb, 
		    SOCK_NUM_PROGRESS_CQS * sizeof(struct sock_cq*))){
		sock_debug(SOCK_ERROR, 
			   "[SOCK_PROGRESS]: Couldn't create CQ rb\n");
		goto err;
	}
	fastlock_init(&engine->cq_lock);

	engine->do_progress = 1;
	if(pthread_create(&engine->progress_thread, NULL, sock_pe_progress_thread,
			  (void *)engine)){
		sock_debug(SOCK_ERROR, 
			   "[SOCK_PROGRESS]: Couldn't create progress thread\n");
		goto err;
      }

err:
	free(engine);
	return NULL;
}

int sock_pe_add_cq(struct sock_progress_engine *engine,
				struct sock_cq *cq)
{
	if(rbfdavail(&engine->cq_rb) < sizeof(struct sock_cq*))
		return -FI_ENOMEM;

	fastlock_acquire(&engine->cq_lock);
	rbfdwrite(&engine->cq_rb, cq, sizeof(struct sock_cq*));
	rbfdcommit(&engine->cq_rb);
	fastlock_release(&engine->cq_lock);
	return 0;
}


