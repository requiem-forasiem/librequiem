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

#ifndef _LIBREQUIEM_REQUIEM_MSGBUF_H
#define _LIBREQUIEM_REQUIEM_MSGBUF_H

#ifdef __cplusplus
 extern "C" {
#endif
         
typedef struct requiem_msgbuf requiem_msgbuf_t;

typedef enum {
        REQUIEM_MSGBUF_FLAGS_ASYNC = 0x01
} requiem_msgbuf_flags_t;


#include "requiem-client.h"
#include "requiem-msg.h"


int requiem_msgbuf_new(requiem_msgbuf_t **msgbuf);

void requiem_msgbuf_destroy(requiem_msgbuf_t *msgbuf);

void requiem_msgbuf_mark_end(requiem_msgbuf_t *msgbuf);

int requiem_msgbuf_set(requiem_msgbuf_t *msgbuf, uint8_t tag, uint32_t len, const void *data);

requiem_msg_t *requiem_msgbuf_get_msg(requiem_msgbuf_t *msgbuf);

void requiem_msgbuf_set_callback(requiem_msgbuf_t *msgbuf, int (*send_msg)(requiem_msgbuf_t *msgbuf, requiem_msg_t *msg));

void requiem_msgbuf_set_data(requiem_msgbuf_t *msgbuf, void *data);

void *requiem_msgbuf_get_data(requiem_msgbuf_t *msgbuf);

void requiem_msgbuf_set_flags(requiem_msgbuf_t *msgbuf, requiem_msgbuf_flags_t flags);

requiem_msgbuf_flags_t requiem_msgbuf_get_flags(requiem_msgbuf_t *msgbuf);

#ifdef __cplusplus
 }
#endif
         
#endif /* _LIBREQUIEM_REQUIEM_MSGBUF_H */
