/*****
*
* Copyright (C) 2003, 2004, 2005 PreludeIDS Technologies. All Rights Reserved.
* Author: Nicolas Delon 
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

#ifndef _LIBREQUIEM_HASH_H
#define _LIBREQUIEM_HASH_H

#ifdef __cplusplus
 extern "C" {
#endif
         
typedef struct requiem_hash requiem_hash_t;

int requiem_hash_new(requiem_hash_t **hash,
                     unsigned int (*hash_func)(const void *),
                     int (*key_cmp_func)(const void *, const void *),
                     void (*key_destroy_func)(void *),
                     void (*value_destroy_func)(void *));

int requiem_hash_new2(requiem_hash_t **hash, size_t size,
                      unsigned int (*hash_func)(const void *),
                      int (*key_cmp_func)(const void *, const void *),
                      void (*key_destroy_func)(void *),
                     void (*value_destroy_func)(void *));
                     
void requiem_hash_destroy(requiem_hash_t *hash);

int requiem_hash_set(requiem_hash_t *hash, void *key, void *value);

void *requiem_hash_get(requiem_hash_t *hash, const void *key);

int requiem_hash_elem_destroy(requiem_hash_t *hash, const void *key);

void requiem_hash_iterate(requiem_hash_t *hash, void (*cb)(void *data));

#ifdef __cplusplus
 }
#endif
         
#endif /* _LIBREQUIEM_HASH_H */
