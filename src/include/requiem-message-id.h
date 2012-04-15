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

#ifndef _LIBREQUIEM_REQUIEM_MESSAGE_ID_H
#define _LIBREQUIEM_REQUIEM_MESSAGE_ID_H

/*
 * Top level message tag (to be used with requiem_msg_new()).
 */
#define REQUIEM_MSG_IDMEF          0
#define REQUIEM_MSG_ID             3
#define REQUIEM_MSG_AUTH           4
#define REQUIEM_MSG_CM             5 
#define REQUIEM_MSG_CONNECTION_CAPABILITY    6
#define REQUIEM_MSG_OPTION_REQUEST 7
#define REQUIEM_MSG_OPTION_REPLY   8

/*
 * REQUIEM_MSG_ID submessage
 */
#define REQUIEM_MSG_ID_DECLARE  0

/*
 * authentication msg
 */
#define REQUIEM_MSG_AUTH_SUCCEED   6
#define REQUIEM_MSG_AUTH_FAILED    7


/*
 * REQUIEM_MSG_CM submessages
 */
#define REQUIEM_MSG_CM_FIREWALL 0
#define REQUIEM_MSG_CM_THROTTLE 1
#define REQUIEM_MSG_CM_ISLAND   2
#define REQUIEM_MSG_CM_FEATURE  3

/*
 * REQUIEM_MSG_OPTION submessages
 */
#define REQUIEM_MSG_OPTION_TARGET_ID        0
#define REQUIEM_MSG_OPTION_LIST             2
#define REQUIEM_MSG_OPTION_VALUE            3
#define REQUIEM_MSG_OPTION_SET              4
#define REQUIEM_MSG_OPTION_GET              5
#define REQUIEM_MSG_OPTION_REQUEST_ID       6
#define REQUIEM_MSG_OPTION_ERROR            7
#define REQUIEM_MSG_OPTION_START            8
#define REQUIEM_MSG_OPTION_END              9
#define REQUIEM_MSG_OPTION_NAME            10
#define REQUIEM_MSG_OPTION_DESC            11
#define REQUIEM_MSG_OPTION_HAS_ARG         12
#define REQUIEM_MSG_OPTION_HELP            13
#define REQUIEM_MSG_OPTION_INPUT_VALIDATION 14
#define REQUIEM_MSG_OPTION_INPUT_TYPE       15
#define REQUIEM_MSG_OPTION_ARG              16
#define REQUIEM_MSG_OPTION_TYPE             17
#define REQUIEM_MSG_OPTION_DESTROY          18
#define REQUIEM_MSG_OPTION_COMMIT           19
#define REQUIEM_MSG_OPTION_HOP              20
#define REQUIEM_MSG_OPTION_TARGET_INSTANCE_ID 21

#endif /* _LIBREQUIEM_REQUIEM_MESSAGE_ID_H */
