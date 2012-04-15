/*****
*
* Copyright (C) 2004-2006,2007 PreludeIDS Technologies. All Rights Reserved.
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

#ifndef _LIBREQUIEM_REQUIEM_FAILOVER_H
#define _LIBREQUIEM_REQUIEM_FAILOVER_H

#ifdef __cplusplus
 extern "C" {
#endif

typedef struct requiem_failover requiem_failover_t;

void requiem_failover_destroy(requiem_failover_t *failover);

int requiem_failover_new(requiem_failover_t **ret, const char *dirname);

void requiem_failover_set_quota(requiem_failover_t *failover, size_t limit);

int requiem_failover_save_msg(requiem_failover_t *failover, requiem_msg_t *msg);

ssize_t requiem_failover_get_saved_msg(requiem_failover_t *failover, requiem_msg_t **out);

unsigned long requiem_failover_get_deleted_msg_count(requiem_failover_t *failover);

unsigned long requiem_failover_get_available_msg_count(requiem_failover_t *failover);

void requiem_failover_enable_transaction(requiem_failover_t *failover);

void requiem_failover_disable_transaction(requiem_failover_t *failover);

int requiem_failover_commit(requiem_failover_t *failover, requiem_msg_t *msg);

int requiem_failover_rollback(requiem_failover_t *failover, requiem_msg_t *msg);

#ifdef __cplusplus
 }
#endif

#endif
