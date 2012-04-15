/*****
*
* Copyright (C) 2004, 2005 PreludeIDS Technologies. All Rights Reserved.
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

#ifndef _LIBREQUIEM_REQUIEM_CLIENT_H
#define _LIBREQUIEM_REQUIEM_CLIENT_H

#ifdef __cplusplus
 extern "C" {
#endif

typedef enum {
        REQUIEM_CLIENT_EXIT_STATUS_SUCCESS = 0,
        REQUIEM_CLIENT_EXIT_STATUS_FAILURE = -1
} requiem_client_exit_status_t;


typedef enum {
        REQUIEM_CLIENT_FLAGS_ASYNC_SEND  = 0x01,
        REQUIEM_CLIENT_FLAGS_ASYNC_TIMER = 0x02,
        REQUIEM_CLIENT_FLAGS_HEARTBEAT   = 0x04,
        REQUIEM_CLIENT_FLAGS_CONNECT     = 0x08,
        REQUIEM_CLIENT_FLAGS_AUTOCONFIG  = 0x10
} requiem_client_flags_t;


typedef struct requiem_client requiem_client_t;


#include "requiem-client-profile.h"
#include "requiem-ident.h"
#include "requiem-connection.h"
#include "requiem-connection-pool.h"
#include "idmef.h"


requiem_ident_t *requiem_client_get_unique_ident(requiem_client_t *client);

void requiem_client_set_connection_pool(requiem_client_t *client, requiem_connection_pool_t *pool);

requiem_connection_pool_t *requiem_client_get_connection_pool(requiem_client_t *client);

int requiem_client_start(requiem_client_t *client);

int requiem_client_init(requiem_client_t *client);

int requiem_client_new(requiem_client_t **client, const char *profile);

requiem_client_t *requiem_client_ref(requiem_client_t *client);

idmef_analyzer_t *requiem_client_get_analyzer(requiem_client_t *client);

requiem_client_flags_t requiem_client_get_flags(requiem_client_t *client);

void requiem_client_set_required_permission(requiem_client_t *client, requiem_connection_permission_t permission);

requiem_connection_permission_t requiem_client_get_required_permission(requiem_client_t *client);

void requiem_client_send_msg(requiem_client_t *client, requiem_msg_t *msg);

int requiem_client_recv_msg(requiem_client_t *client, int timeout, requiem_msg_t **msg);

void requiem_client_set_heartbeat_cb(requiem_client_t *client, void (*cb)(requiem_client_t *client, idmef_message_t *hb));

void requiem_client_send_idmef(requiem_client_t *client, idmef_message_t *msg);

int requiem_client_recv_idmef(requiem_client_t *client, int timeout, idmef_message_t **idmef);

void requiem_client_destroy(requiem_client_t *client, requiem_client_exit_status_t status);

int requiem_client_set_flags(requiem_client_t *client, requiem_client_flags_t flags);

int requiem_client_set_config_filename(requiem_client_t *client, const char *filename);

const char *requiem_client_get_config_filename(requiem_client_t *client);

requiem_client_profile_t *requiem_client_get_profile(requiem_client_t *client);

int requiem_client_new_msgbuf(requiem_client_t *client, requiem_msgbuf_t **msgbuf);

int requiem_client_handle_msg_default(requiem_client_t *client, requiem_msg_t *msg, requiem_msgbuf_t *msgbuf);

int _requiem_client_register_options(void);

#ifndef REQUIEM_DISABLE_DEPRECATED
const char *requiem_client_get_setup_error(requiem_client_t *client);

requiem_bool_t requiem_client_is_setup_needed(int error);
#endif

void requiem_client_print_setup_error(requiem_client_t *client);


#ifdef __cplusplus
 }
#endif

#endif
