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

#ifndef _LIBREQUIEM_REQUIEM_ASYNC_H
#define _LIBREQUIEM_REQUIEM_ASYNC_H


#include "requiem-linked-object.h"

#ifdef __cplusplus
 extern "C" {
#endif


/**
 * requiem_async_flags_t
 * @REQUIEM_ASYNC_FLAGS_TIMER: Enable asynchronous timer.
 *
 * This provides asynchronous timer. When enabled, the heartbeat
 * function (and user specified callback, if any) will be called
 * automatically, from an asynchronous thread.
 *
 * If you use this flags, you won't need to call requiem_wake_up_timer()
 * anymore.
 */
typedef enum {
        REQUIEM_ASYNC_FLAGS_TIMER   = 0x01
} requiem_async_flags_t;

typedef void (*requiem_async_callback_t)(void *object, void *data);



#define REQUIEM_ASYNC_OBJECT                   \
        REQUIEM_LINKED_OBJECT;                 \
        void *_async_data;                     \
        requiem_async_callback_t _async_func


typedef struct {
        REQUIEM_ASYNC_OBJECT;
} requiem_async_object_t;



static inline void requiem_async_set_data(requiem_async_object_t *obj, void *data)
{
        obj->_async_data = data;
}


static inline void requiem_async_set_callback(requiem_async_object_t *obj, requiem_async_callback_t func)
{
        obj->_async_func = func;
}

int requiem_async_init(void);

requiem_async_flags_t requiem_async_get_flags(void);

void requiem_async_set_flags(requiem_async_flags_t flags);

void requiem_async_add(requiem_async_object_t *obj);

void requiem_async_del(requiem_async_object_t *obj);

void requiem_async_exit(void);


void _requiem_async_fork_prepare(void);
void _requiem_async_fork_parent(void);
void _requiem_async_fork_child(void);


#ifdef __cplusplus
 }
#endif

#endif /* _LIBREQUIEM_REQUIEM_ASYNC_H */

