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

#ifndef _LIBREQUIEM_REQUIEM_LINKED_OBJECT_H
#define _LIBREQUIEM_REQUIEM_LINKED_OBJECT_H


#include "requiem-list.h"


#define REQUIEM_LINKED_OBJECT   \
        requiem_list_t _list;   \
        unsigned int _object_id


typedef struct {
        REQUIEM_LINKED_OBJECT;
} requiem_linked_object_t;



static inline void requiem_linked_object_del(requiem_linked_object_t *obj) 
{
        requiem_list_del(&obj->_list);
}



static inline void requiem_linked_object_del_init(requiem_linked_object_t *obj) 
{
        requiem_list_del(&obj->_list);
        requiem_list_init(&obj->_list);
}



static inline void requiem_linked_object_add(requiem_list_t *head, requiem_linked_object_t *obj) 
{
        requiem_list_add(head, &obj->_list);
}



static inline void requiem_linked_object_add_tail(requiem_list_t *head, requiem_linked_object_t *obj) 
{
        requiem_list_add_tail(head, &obj->_list);
}


static inline void requiem_linked_object_set_id(requiem_linked_object_t *obj, unsigned int id)
{
        obj->_object_id = id;
}


static inline unsigned int requiem_linked_object_get_id(requiem_linked_object_t *obj)
{
        return obj->_object_id;
}



#define requiem_linked_object_get_object(object)  \
        (void *) requiem_list_entry(object, requiem_linked_object_t, _list)


#endif /* _LIBREQUIEM_REQUIEM_LINKED_OBJECT_H */
