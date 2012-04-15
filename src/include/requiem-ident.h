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

#ifndef _LIBREQUIEM_REQUIEM_IDENT_H
#define _LIBREQUIEM_REQUIEM_IDENT_H

#include "requiem-inttypes.h"
#include "requiem-string.h"

#ifdef __cplusplus
 extern "C" {
#endif

typedef struct requiem_ident requiem_ident_t;

int requiem_ident_generate(requiem_ident_t *ident, requiem_string_t *out);

uint64_t requiem_ident_inc(requiem_ident_t *ident);

void requiem_ident_destroy(requiem_ident_t *ident);

int requiem_ident_new(requiem_ident_t **ret);

#ifdef __cplusplus
 }
#endif

#endif /* _LIBREQUIEM_REQUIEM_IDENT_H */
