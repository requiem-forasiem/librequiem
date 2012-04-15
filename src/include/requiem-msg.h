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

#ifndef _LIBREQUIEM_REQUIEM_MESSAGE_H
#define _LIBREQUIEM_REQUIEM_MESSAGE_H

#include "requiem-io.h"


#ifdef __cplusplus
 extern "C" {
#endif

typedef struct requiem_msg requiem_msg_t;


typedef enum {
        REQUIEM_MSG_PRIORITY_NONE = 0,
        REQUIEM_MSG_PRIORITY_LOW  = 1,
        REQUIEM_MSG_PRIORITY_MID  = 2,
        REQUIEM_MSG_PRIORITY_HIGH = 3
} requiem_msg_priority_t;


int requiem_msg_read(requiem_msg_t **msg, requiem_io_t *pio);

int requiem_msg_forward(requiem_msg_t *msg, requiem_io_t *dst, requiem_io_t *src);

int requiem_msg_get(requiem_msg_t *msg, uint8_t *tag, uint32_t *len, void **buf);



/*
 * Write function.
 */
void requiem_msg_recycle(requiem_msg_t *msg);

void requiem_msg_mark_end(requiem_msg_t *msg);

int requiem_msg_dynamic_new(requiem_msg_t **ret, int (*flush_msg_cb)(requiem_msg_t **msg, void *data), void *data);

int requiem_msg_new(requiem_msg_t **ret, size_t msgcount, size_t msglen, uint8_t tag, requiem_msg_priority_t priority);

int requiem_msg_set(requiem_msg_t *msg, uint8_t tag, uint32_t len, const void *data);

int requiem_msg_write(requiem_msg_t *msg, requiem_io_t *dst);



/*
 *
 */
void requiem_msg_set_tag(requiem_msg_t *msg, uint8_t tag);

void requiem_msg_set_priority(requiem_msg_t *msg, requiem_msg_priority_t priority);

uint8_t requiem_msg_get_tag(requiem_msg_t *msg);

requiem_msg_priority_t requiem_msg_get_priority(requiem_msg_t *msg);

uint32_t requiem_msg_get_len(requiem_msg_t *msg);

uint32_t requiem_msg_get_datalen(requiem_msg_t *msg);

const unsigned char *requiem_msg_get_message_data(requiem_msg_t *msg);

struct timeval *requiem_msg_get_time(requiem_msg_t *msg, struct timeval *tv);

int requiem_msg_is_empty(requiem_msg_t *msg);

int requiem_msg_is_fragment(requiem_msg_t *msg);

void requiem_msg_destroy(requiem_msg_t *msg);

void requiem_msg_set_callback(requiem_msg_t *msg, int (*flush_msg_cb)(requiem_msg_t **msg, void *data));

void requiem_msg_set_data(requiem_msg_t *msg, void *data);

requiem_msg_t *requiem_msg_ref(requiem_msg_t *msg);

#ifdef __cplusplus
 }
#endif

#endif /* _LIBREQUIEM_REQUIEM_MESSAGE_H */
