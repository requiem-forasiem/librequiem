/*****
*
* Copyright (C) 2004-2005,2006,2007 PreludeIDS Technologies. All Rights Reserved.
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

#ifndef _LIBREQUIEM_REQUIEM_STRING_H
#define _LIBREQUIEM_REQUIEM_STRING_H

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdarg.h>

#include "requiem-list.h"
#include "requiem-inttypes.h"

#ifdef __cplusplus
 extern "C" {
#endif

#ifndef __attribute__
/* This feature is available in gcc versions 2.5 and later.  */
# if __GNUC__ < 2 || (__GNUC__ == 2 && __GNUC_MINOR__ < 5) || __STRICT_ANSI__
#  define __attribute__(Spec) /* empty */
# endif
/* The __-protected variants of `format' and `printf' attributes
   are accepted by gcc versions 2.6.4 (effectively 2.7) and later.  */
# if __GNUC__ < 2 || (__GNUC__ == 2 && __GNUC_MINOR__ < 7)
#  define __format__ format
#  define __printf__ printf
# endif
#endif


struct requiem_string {
        requiem_list_t list;

        int flags;
        int refcount;

        union {
                char *rwbuf;
                const char *robuf;
        } data;

        size_t size;
        size_t index;
};



typedef struct requiem_string requiem_string_t;


int requiem_string_new(requiem_string_t **string);

int requiem_string_new_nodup(requiem_string_t **string, char *str);

int requiem_string_new_ref(requiem_string_t **string, const char *str);

int requiem_string_new_dup(requiem_string_t **string, const char *str);

int requiem_string_new_dup_fast(requiem_string_t **string, const char *str, size_t len);

void requiem_string_destroy(requiem_string_t *string);

void requiem_string_destroy_internal(requiem_string_t *string);

int requiem_string_new_nodup_fast(requiem_string_t **string, char *str, size_t len);

int requiem_string_new_ref_fast(requiem_string_t **string, const char *str, size_t len);

int requiem_string_set_dup_fast(requiem_string_t *string, const char *buf, size_t len);

int requiem_string_set_dup(requiem_string_t *string, const char *buf);

int requiem_string_set_nodup_fast(requiem_string_t *string, char *buf, size_t len);

int requiem_string_set_nodup(requiem_string_t *string, char *buf);

int requiem_string_set_ref_fast(requiem_string_t *string, const char *buf, size_t len);

int requiem_string_set_ref(requiem_string_t *string, const char *buf);

int requiem_string_copy_ref(const requiem_string_t *src, requiem_string_t *dst);

int requiem_string_copy_dup(const requiem_string_t *src, requiem_string_t *dst);

requiem_string_t *requiem_string_ref(requiem_string_t *string);

int requiem_string_clone(const requiem_string_t *src, requiem_string_t **dst);

size_t requiem_string_get_len(const requiem_string_t *string);

const char *requiem_string_get_string_or_default(const requiem_string_t *string, const char *def);

const char *requiem_string_get_string(const requiem_string_t *string);

int requiem_string_get_string_released(requiem_string_t *string, char **outptr);

requiem_bool_t requiem_string_is_empty(const requiem_string_t *string);

void requiem_string_clear(requiem_string_t *string);

/*
 * string operation
 */
int requiem_string_cat(requiem_string_t *dst, const char *str);
int requiem_string_ncat(requiem_string_t *dst, const char *str, size_t len);

int requiem_string_sprintf(requiem_string_t *string, const char *fmt, ...)
                           __attribute__ ((__format__ (__printf__, 2, 3)));

int requiem_string_vprintf(requiem_string_t *string, const char *fmt, va_list ap)
                           __attribute__ ((__format__ (__printf__, 2, 0)));

int requiem_string_compare(const requiem_string_t *str1, const requiem_string_t *str2);

#define requiem_string_set_constant(string, str)                         \
        requiem_string_set_ref_fast((string), (str), strlen((str)))

#define requiem_string_new_constant(string, str)                         \
        requiem_string_new_ref_fast((string), (str), strlen((str)))

#ifdef __cplusplus
 }
#endif

#endif /* _LIBREQUIEM_REQUIEM_STRING_H */
