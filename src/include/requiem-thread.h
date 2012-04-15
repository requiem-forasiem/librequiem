/*****
*
* Copyright (C) 2005 PreludeIDS Technologies. All Rights Reserved.
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

#ifndef _LIBREQUIEM_THREAD_H
#define _LIBREQUIEM_THREAD_H

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#ifdef __cplusplus
 extern "C" {
#endif

/*
 *
 */
int requiem_thread_init(void *nil);

int _requiem_thread_set_error(const char *error);

const char *_requiem_thread_get_error(void);

void _requiem_thread_deinit(void);
         
#ifdef __cplusplus
 }
#endif

#endif
