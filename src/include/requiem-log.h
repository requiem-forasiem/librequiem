/*****
*
* Copyright (C) 2005,2006,2007 PreludeIDS Technologies. All Rights Reserved.
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

#ifndef _LIBREQUIEM_REQUIEM_LOG_H
#define _LIBREQUIEM_REQUIEM_LOG_H

#include "requiem-config.h"

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdarg.h>

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


typedef enum {
        REQUIEM_LOG_CRIT  = -1,
        REQUIEM_LOG_ERR   =  0,
        REQUIEM_LOG_WARN  =  1,
        REQUIEM_LOG_INFO  =  2,
        REQUIEM_LOG_DEBUG  = 3
} requiem_log_t;


typedef enum {
        REQUIEM_LOG_FLAGS_QUIET  = 0x01, /* Drop REQUIEM_LOG_PRIORITY_INFO */
        REQUIEM_LOG_FLAGS_SYSLOG = 0x02
} requiem_log_flags_t;



void _requiem_log_v(requiem_log_t level, const char *file,
                    const char *function, int line, const char *fmt, va_list ap)
                    __attribute__ ((__format__ (__printf__, 5, 0)));

void _requiem_log(requiem_log_t level, const char *file,
                  const char *function, int line, const char *fmt, ...)
                  __attribute__ ((__format__ (__printf__, 5, 6)));


#ifdef HAVE_VARIADIC_MACROS

#define requiem_log(level, ...) \
        _requiem_log(level, __FILE__, __REQUIEM_FUNC__, __LINE__, __VA_ARGS__)

#define requiem_log_debug(level, ...) \
        _requiem_log(REQUIEM_LOG_DEBUG + level, __FILE__, __REQUIEM_FUNC__, __LINE__, __VA_ARGS__)
#else

void requiem_log(requiem_log_t level, const char *fmt, ...)
                 __attribute__ ((__format__ (__printf__, 2, 3)));

void requiem_log_debug(requiem_log_t level, const char *fmt, ...)
                       __attribute__ ((__format__ (__printf__, 2, 3)));

#endif


#define requiem_log_v(level, fmt, ap) \
        _requiem_log_v(level, __FILE__, __REQUIEM_FUNC__, __LINE__, fmt, ap)

#define requiem_log_debug_v(level, fmt, ap) \
        _requiem_log_v(REQUIEM_LOG_DEBUG + level, __FILE__, __REQUIEM_FUNC__, __LINE__, fmt, ap)


void requiem_log_set_level(requiem_log_t level);

void requiem_log_set_debug_level(int level);

requiem_log_flags_t requiem_log_get_flags(void);

void requiem_log_set_flags(requiem_log_flags_t flags);

char *requiem_log_get_prefix(void);

void requiem_log_set_prefix(char *prefix);

void requiem_log_set_callback(void log_cb(requiem_log_t level, const char *str));

int requiem_log_set_logfile(const char *filename);

void _requiem_log_set_abort_level(requiem_log_t level);

int _requiem_log_set_abort_level_from_string(const char *level);

#ifdef __cplusplus
 }
#endif

#endif /* _LIBREQUIEM_REQUIEM_LOG_H */
