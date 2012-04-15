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

#ifndef _LIBREQUIEM_REQUIEM_GETOPT_WIDE_H
#define _LIBREQUIEM_REQUIEM_GETOPT_WIDE_H

#define REQUIEM_OPTION_REPLY_TYPE_SET   0x01
#define REQUIEM_OPTION_REPLY_TYPE_GET   0x02
#define REQUIEM_OPTION_REPLY_TYPE_LIST  0x04
#define REQUIEM_OPTION_REPLY_TYPE_ERROR 0x08


int requiem_option_push_request(requiem_msgbuf_t *msg, int type, const char *request);

int requiem_option_new_request(requiem_msgbuf_t *msgbuf,
                               uint32_t request_id, uint64_t *target_id, size_t size);

int requiem_option_process_request(requiem_client_t *client, requiem_msg_t *msg, requiem_msgbuf_t *reply);

int requiem_option_recv_reply(requiem_msg_t *msg, uint64_t *source_id, uint32_t *request_id, void **value);

#endif /* _LIBREQUIEM_REQUIEM_GETOPT_WIDE_H */

