/*****
*
* Copyright (C) 2002,2003,2004,2005 PreludeIDS Technologies. All Rights Reserved.
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

#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "requiem-log.h"
#include "requiem-list.h"
#include "requiem-inttypes.h"
#include "requiem-linked-object.h"
#include "requiem-async.h"
#include "requiem-io.h"
#include "requiem-msg.h"
#include "requiem-msgbuf.h"
#include "requiem-error.h"


struct requiem_msgbuf {
        int flags;
        void *data;
        requiem_msg_t *msg;
        int (*send_msg)(requiem_msgbuf_t *msgbuf, requiem_msg_t *msg);
};


static int default_send_msg_cb(requiem_msg_t **msg, void *data);


static int do_send_msg(requiem_msgbuf_t *msgbuf, requiem_msg_t *msg) 
{
        int ret;

        ret = msgbuf->send_msg(msgbuf, msg);
        if ( ret < 0 && requiem_error_get_code(ret) == REQUIEM_ERROR_EAGAIN )
                return ret;
        
        requiem_msg_recycle(msg);
        requiem_msg_set_priority(msg, REQUIEM_MSG_PRIORITY_NONE);
        
        return ret;
}



static int do_send_msg_async(requiem_msgbuf_t *msgbuf, requiem_msg_t *msg) 
{
        int ret;

        ret = msgbuf->send_msg(msgbuf, msg);
        if ( ret < 0 && requiem_error_get_code(ret) == REQUIEM_ERROR_EAGAIN )
                return ret;
        
        ret = requiem_msg_dynamic_new(&msgbuf->msg, default_send_msg_cb, msgbuf);
        if ( ret < 0 )
                return ret;

        return 0;
}



static int default_send_msg_cb(requiem_msg_t **msg, void *data)
{
        int ret;
        requiem_msgbuf_t *msgbuf = data;

        if ( msgbuf->flags & REQUIEM_MSGBUF_FLAGS_ASYNC )
                ret = do_send_msg_async(msgbuf, *msg);
        else
                ret = do_send_msg(msgbuf, *msg);

        *msg = msgbuf->msg;
        
        return ret;
}



/**
 * requiem_msgbuf_set:
 * @msgbuf: Pointer on a #requiem_msgbuf_t object to store the data to.
 * @tag: 8 bits unsigned integer describing the kind of data.
 * @len: len of the data chunk.
 * @data: Pointer to the data.
 *
 * requiem_msgbuf_set() append @len bytes of data from the @data buffer
 * to the @msgbuf object representing a message. The data is tagged with @tag.
 *
 * Returns: 0 on success, a negative value if an error occured.
 */
int requiem_msgbuf_set(requiem_msgbuf_t *msgbuf, uint8_t tag, uint32_t len, const void *data)
{
        return requiem_msg_set(msgbuf->msg, tag, len, data);
}




/**
 * requiem_msgbuf_new:
 * @msgbuf: Pointer where to store the created #requiem_msgbuf_t object.
 *
 * Create a new #requiem_msgbuf_t object and store it into @msgbuf.
 * You can then write data to @msgbuf using the requiem_msgbuf_set() function.
 *
 * When the message buffer is full, the message will be flushed using the
 * user provided callback.
 *
 * Returns: 0 on success, or a negative value if an error occured.
 */
int requiem_msgbuf_new(requiem_msgbuf_t **msgbuf)
{
        int ret;

        *msgbuf = calloc(1, sizeof(**msgbuf));
        if ( ! *msgbuf )
                return requiem_error_from_errno(errno);
        
        ret = requiem_msg_dynamic_new(&(*msgbuf)->msg, default_send_msg_cb, *msgbuf);     
        if ( ret < 0 )
                return ret;
        
        return 0;
}



/**
 * requiem_msgbuf_get_msg:
 * @msgbuf: Pointer on a #requiem_msgbuf_t object.
 *
 * Returns: This function return the current message associated with
 * the message buffer.
 */
requiem_msg_t *requiem_msgbuf_get_msg(requiem_msgbuf_t *msgbuf)
{
        return msgbuf->msg;
}



/**
 * requiem_msgbuf_mark_end:
 * @msgbuf: Pointer on #requiem_msgbuf_t object.
 *
 * This function should be called to tell the msgbuf subsystem
 * that you finished writing your message.
 */
void requiem_msgbuf_mark_end(requiem_msgbuf_t *msgbuf) 
{
        requiem_msg_mark_end(msgbuf->msg);
        
        /*
         * FIXME:
         * only flush the message if we're not under an alert burst.
         */
        default_send_msg_cb(&msgbuf->msg, msgbuf);
}




/**
 * requiem_msgbuf_destroy:
 * @msgbuf: Pointer on a #requiem_msgbuf_t object.
 *
 * Destroy @msgbuf, all data remaining will be flushed.
 */
void requiem_msgbuf_destroy(requiem_msgbuf_t *msgbuf) 
{        
        if ( msgbuf->msg && ! requiem_msg_is_empty(msgbuf->msg) )
                default_send_msg_cb(&msgbuf->msg, msgbuf);

        if ( msgbuf->msg )
                requiem_msg_destroy(msgbuf->msg);

        free(msgbuf);
}




/**
 * requiem_msgbuf_set_callback:
 * @msgbuf: Pointer on a #requiem_msgbuf_t object.
 * @send_msg: Pointer to a function for sending a message.
 *
 * Associate an application specific callback to this @msgbuf.
 */
void requiem_msgbuf_set_callback(requiem_msgbuf_t *msgbuf,
                                 int (*send_msg)(requiem_msgbuf_t *msgbuf, requiem_msg_t *msg))
{
        msgbuf->send_msg = send_msg;
}




void requiem_msgbuf_set_data(requiem_msgbuf_t *msgbuf, void *data) 
{
        msgbuf->data = data;
}



void *requiem_msgbuf_get_data(requiem_msgbuf_t *msgbuf)
{
        return msgbuf->data;
}


void requiem_msgbuf_set_flags(requiem_msgbuf_t *msgbuf, requiem_msgbuf_flags_t flags)
{        
        msgbuf->flags = flags;
}



requiem_msgbuf_flags_t requiem_msgbuf_get_flags(requiem_msgbuf_t *msgbuf)
{
        return msgbuf->flags;
}




