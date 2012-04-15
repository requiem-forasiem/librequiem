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

#ifndef _LIBREQUIEM_PLUGIN_H
#define _LIBREQUIEM_PLUGIN_H

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include "requiem-list.h"
#include "requiem-option.h"

#ifdef __cplusplus
extern "C" {
#endif


#define REQUIEM_PLUGIN_API_VERSION 1


typedef struct requiem_plugin_entry requiem_plugin_entry_t;
typedef struct requiem_plugin_instance requiem_plugin_instance_t;


#define REQUIEM_PLUGIN_GENERIC               \
        requiem_plugin_entry_t *_pe;         \
        char *name;                          \
        void (*destroy)(requiem_plugin_instance_t *pi, requiem_string_t *err)


typedef struct {
        REQUIEM_PLUGIN_GENERIC;
} requiem_plugin_generic_t;



#ifndef lt_preloaded_symbols
/*
 * Hack for plugin preloading,
 * without having the end program depend on ltdl.
 */
#ifdef REQUIEM_APPLICATION_USE_LIBTOOL2
# define lt_preloaded_symbols lt__PROGRAM__LTX_preloaded_symbols
#endif

extern const void *lt_preloaded_symbols[];

#endif

#define REQUIEM_PLUGIN_SET_PRELOADED_SYMBOLS()         \
        requiem_plugin_set_preloaded_symbols(lt_preloaded_symbols)


#define REQUIEM_PLUGIN_OPTION_DECLARE_STRING_CB(prefix, type, name)                              \
static int prefix ## _set_ ## name(requiem_option_t *opt, const char *optarg, requiem_string_t *err, void *context)  \
{                                                                                                \
        char *dup = NULL;                                                                        \
        type *ptr = requiem_plugin_instance_get_plugin_data(context);                            \
                                                                                                 \
        if ( optarg ) {                                                                          \
                dup = strdup(optarg);                                                            \
                if ( ! dup )                                                                     \
                        return requiem_error_from_errno(errno);                                  \
        }                                                                                        \
                                                                                                 \
        if ( ptr->name )                                                                         \
                free(ptr->name);                                                                 \
                                                                                                 \
        ptr->name = dup;                                                                         \
                                                                                                 \
        return 0;                                                                                \
}                                                                                                \
                                                                                                 \
                                                                                                 \
static int prefix ## _get_ ## name(requiem_option_t *opt, requiem_string_t *out, void *context)  \
{                                                                                                \
        type *ptr = requiem_plugin_instance_get_plugin_data(context);                            \
        if ( ptr->name )                                                                         \
                requiem_string_cat(out, ptr->name);                                              \
                                                                                                 \
        return 0;                                                                                \
}


/*
 *
 */
#define requiem_plugin_get_name(p) (p)->name

#define requiem_plugin_set_name(p, str) (p)->name = (str)

#define requiem_plugin_set_destroy_func(p, func) (p)->destroy = func




/*
 * Plugin need to call this function in order to get registered.
 */
void requiem_plugin_entry_set_plugin(requiem_plugin_entry_t *pe, requiem_plugin_generic_t *pl);

int requiem_plugin_set_activation_option(requiem_plugin_entry_t *pe, requiem_option_t *opt,
                                         int (*commit)(requiem_plugin_instance_t *pi, requiem_string_t *err));

int requiem_plugin_instance_subscribe(requiem_plugin_instance_t *pi);

int requiem_plugin_instance_unsubscribe(requiem_plugin_instance_t *pi);


int requiem_plugin_new_instance(requiem_plugin_instance_t **pi,
                                requiem_plugin_generic_t *plugin, const char *name, void *data);


/*
 *
 */
requiem_plugin_generic_t *requiem_plugin_search_by_name(requiem_list_t *head, const char *name);

requiem_plugin_instance_t *requiem_plugin_search_instance_by_name(requiem_list_t *head,
                                                                  const char *pname, const char *iname);


void requiem_plugin_instance_set_data(requiem_plugin_instance_t *pi, void *data);

void *requiem_plugin_instance_get_data(requiem_plugin_instance_t *pi);

void requiem_plugin_instance_set_plugin_data(requiem_plugin_instance_t *pi, void *data);

void *requiem_plugin_instance_get_plugin_data(requiem_plugin_instance_t *pi);

const char *requiem_plugin_instance_get_name(requiem_plugin_instance_t *pi);

requiem_plugin_generic_t *requiem_plugin_instance_get_plugin(requiem_plugin_instance_t *pi);


/*
 * Load all plugins in directory 'dirname'.
 * The CB arguments will be called for each plugin that register
 * (using the plugin_register function), then the application will
 * have the ability to use plugin_register_for_use to tell it want
 * to use this plugin.
 */
int requiem_plugin_load_from_dir(requiem_list_t *head,
                                 const char *dirname, const char *symbol, void *ptr,
                                 int (*subscribe)(requiem_plugin_instance_t *p),
                                 void (*unsubscribe)(requiem_plugin_instance_t *pi));


/*
 * Call this if you want to use this plugin.
 */
int requiem_plugin_instance_add(requiem_plugin_instance_t *pi, requiem_list_t *h);

void requiem_plugin_instance_del(requiem_plugin_instance_t *pi);

void requiem_plugin_instance_compute_time(requiem_plugin_instance_t *pi,
                                          struct timeval *start, struct timeval *end);


int requiem_plugin_instance_call_commit_func(requiem_plugin_instance_t *pi, requiem_string_t *err);

requiem_bool_t requiem_plugin_instance_has_commit_func(requiem_plugin_instance_t *pi);

void requiem_plugin_set_preloaded_symbols(void *symlist);

requiem_plugin_generic_t *requiem_plugin_get_next(requiem_list_t *head, requiem_list_t **iter);

void requiem_plugin_unload(requiem_plugin_generic_t *plugin);


/*
 *
 */
#define requiem_plugin_compute_stats(pi, func) do {                            \
        struct timeval start, end;                                             \
        gettimeofday(&start, NULL);                                            \
        (func);                                                                \
        gettimeofday(&end, NULL);                                              \
        requiem_plugin_instance_compute_time(&start, &end);                    \
} while(0)


/*
 * Macro used to start a plugin.
 */
#define requiem_plugin_run(pi, type, member, ...) \
        (((type *)requiem_plugin_instance_get_plugin(pi))->member(__VA_ARGS__))

#ifdef __cplusplus
 }
#endif

#endif /* _LIBREQUIEM_PLUGIN_H */
