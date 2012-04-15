/*****
*
* Copyright (C) 2001, 2002, 2003, 2004, 2005 PreludeIDS Technologies. All Rights Reserved.
* Author: Yoann Vandoorselaere <yoannv@gmail.com>
*
* This file is part of the Requiem library.
*
* This program is free software; you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation; either version 2, or (at your option)
* any later version.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU General Public License for more details.
*
* You should have received a copy of the GNU General Public License
* along with this program; see the file COPYING.  If not, write to
* the Free Software Foundation, 675 Mass Ave, Cambridge, MA 02139, USA.
*
*****/

#ifndef _LIBREQUIEM_REQUIEM_CONNECTION_POOL_H
#define _LIBREQUIEM_REQUIEM_CONNECTION_POOL_H

#include "requiem-list.h"
#include "requiem-connection.h"

#ifdef __cplusplus
 extern "C" {
#endif

typedef enum {
        REQUIEM_CONNECTION_POOL_FLAGS_RECONNECT        = 0x01,
        REQUIEM_CONNECTION_POOL_FLAGS_FAILOVER         = 0x02
} requiem_connection_pool_flags_t;


typedef enum {
        REQUIEM_CONNECTION_POOL_EVENT_INPUT            = 0x01,
        REQUIEM_CONNECTION_POOL_EVENT_DEAD             = 0x02,
        REQUIEM_CONNECTION_POOL_EVENT_ALIVE            = 0x04
} requiem_connection_pool_event_t;

typedef struct requiem_connection_pool requiem_connection_pool_t;


void requiem_connection_pool_broadcast(requiem_connection_pool_t *pool, requiem_msg_t *msg);

void requiem_connection_pool_broadcast_async(requiem_connection_pool_t *pool, requiem_msg_t *msg);

int requiem_connection_pool_init(requiem_connection_pool_t *pool);

int requiem_connection_pool_new(requiem_connection_pool_t **ret,
                                requiem_client_profile_t *cp,
                                requiem_connection_permission_t permission);

requiem_list_t *requiem_connection_pool_get_connection_list(requiem_connection_pool_t *pool);

int requiem_connection_pool_add_connection(requiem_connection_pool_t *pool, requiem_connection_t *cnx);

int requiem_connection_pool_del_connection(requiem_connection_pool_t *pool, requiem_connection_t *cnx);

int requiem_connection_pool_set_connection_dead(requiem_connection_pool_t *pool, requiem_connection_t *cnx);
int requiem_connection_pool_set_connection_alive(requiem_connection_pool_t *pool, requiem_connection_t *cnx);

int requiem_connection_pool_set_connection_string(requiem_connection_pool_t *pool, const char *cfgstr);

const char *requiem_connection_pool_get_connection_string(requiem_connection_pool_t *pool);

void requiem_connection_pool_destroy(requiem_connection_pool_t *pool);

requiem_connection_pool_t *requiem_connection_pool_ref(requiem_connection_pool_t *pool);

requiem_connection_pool_flags_t requiem_connection_pool_get_flags(requiem_connection_pool_t *pool);

void requiem_connection_pool_set_flags(requiem_connection_pool_t *pool, requiem_connection_pool_flags_t flags);

void requiem_connection_pool_set_required_permission(requiem_connection_pool_t *pool, requiem_connection_permission_t req_perm);

void requiem_connection_pool_set_data(requiem_connection_pool_t *pool, void *data);

void *requiem_connection_pool_get_data(requiem_connection_pool_t *pool);

int requiem_connection_pool_recv(requiem_connection_pool_t *pool, int timeout, requiem_connection_t **outcon, requiem_msg_t **outmsg);

int requiem_connection_pool_check_event(requiem_connection_pool_t *pool, int timeout,
                                        int (*event_cb)(requiem_connection_pool_t *pool,
                                                        requiem_connection_pool_event_t event,
                                                        requiem_connection_t *cnx, void *extra), void *extra);

void requiem_connection_pool_set_global_event_handler(requiem_connection_pool_t *pool,
                                                      requiem_connection_pool_event_t wanted_events,
                                                      int (*callback)(requiem_connection_pool_t *pool,
                                                                      requiem_connection_pool_event_t events));

void requiem_connection_pool_set_event_handler(requiem_connection_pool_t *pool,
                                               requiem_connection_pool_event_t wanted_events,
                                               int (*callback)(requiem_connection_pool_t *pool,
                                                               requiem_connection_pool_event_t events,
                                                               requiem_connection_t *cnx));

#ifdef __cplusplus
 }
#endif

#endif /* _LIBREQUIEM_REQUIEM_CONNECTION_POOL_H */
