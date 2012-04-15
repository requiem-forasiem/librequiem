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

#ifndef _LIBREQUIEM_REQUIEM_CONNECTION_H
#define _LIBREQUIEM_REQUIEM_CONNECTION_H

#ifdef __cplusplus
 extern "C" {
#endif

typedef enum {
        REQUIEM_CONNECTION_PERMISSION_IDMEF_READ      = 0x01, /* client might read received IDMEF message */
        REQUIEM_CONNECTION_PERMISSION_ADMIN_READ      = 0x02, /* client might read received ADMIN message */
        REQUIEM_CONNECTION_PERMISSION_IDMEF_WRITE     = 0x04, /* client might send IDMEF message          */
        REQUIEM_CONNECTION_PERMISSION_ADMIN_WRITE     = 0x08  /* client might issue OPTION request        */
} requiem_connection_permission_t;

typedef enum {
        REQUIEM_CONNECTION_STATE_ESTABLISHED     = 0x01
} requiem_connection_state_t;


typedef struct requiem_connection requiem_connection_t;


#include "requiem-msg.h"
#include "requiem-msgbuf.h"
#include "requiem-string.h"
#include "requiem-client-profile.h"
#include "idmef.h"


void requiem_connection_destroy(requiem_connection_t *conn);

requiem_connection_t *requiem_connection_ref(requiem_connection_t *conn);

int requiem_connection_send(requiem_connection_t *cnx, requiem_msg_t *msg);

int requiem_connection_recv(requiem_connection_t *cnx, requiem_msg_t **outmsg);

int requiem_connection_recv_idmef(requiem_connection_t *con, idmef_message_t **idmef);

int requiem_connection_connect(requiem_connection_t *cnx,
                               requiem_client_profile_t *profile,
                               requiem_connection_permission_t permission);

ssize_t requiem_connection_forward(requiem_connection_t *cnx, requiem_io_t *src, size_t count);

const char *requiem_connection_get_local_addr(requiem_connection_t *cnx);

unsigned int requiem_connection_get_local_port(requiem_connection_t *cnx);

const char *requiem_connection_get_peer_addr(requiem_connection_t *cnx);

unsigned int requiem_connection_get_peer_port(requiem_connection_t *cnx);

requiem_bool_t requiem_connection_is_alive(requiem_connection_t *cnx);

requiem_io_t *requiem_connection_get_fd(requiem_connection_t *cnx);

int requiem_connection_close(requiem_connection_t *cnx);

void requiem_connection_set_fd_ref(requiem_connection_t *cnx, requiem_io_t *fd);

void requiem_connection_set_fd_nodup(requiem_connection_t *cnx, requiem_io_t *fd);

void requiem_connection_set_state(requiem_connection_t *cnx, requiem_connection_state_t state);

requiem_connection_state_t requiem_connection_get_state(requiem_connection_t *cnx);

void requiem_connection_set_data(requiem_connection_t *cnx, void *data);

void *requiem_connection_get_data(requiem_connection_t *cnx);

const char *requiem_connection_get_default_socket_filename(void);

requiem_connection_permission_t requiem_connection_get_permission(requiem_connection_t *conn);

uint64_t requiem_connection_get_peer_analyzerid(requiem_connection_t *cnx);

void requiem_connection_set_peer_analyzerid(requiem_connection_t *cnx, uint64_t analyzerid);

#include "requiem-client.h"

int requiem_connection_new(requiem_connection_t **ret, const char *addr);

int requiem_connection_new_msgbuf(requiem_connection_t *connection, requiem_msgbuf_t **msgbuf);

int requiem_connection_permission_to_string(requiem_connection_permission_t perm, requiem_string_t *out);

int requiem_connection_permission_new_from_string(requiem_connection_permission_t *out, const char *buf);

requiem_connection_t *requiem_connection_ref(requiem_connection_t *conn);

#ifdef __cplusplus
 }
#endif

#endif /* _LIBREQUIEM_REQUIEM_CONNECTION_H */
