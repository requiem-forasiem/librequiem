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

#ifndef _LIBREQUIEM_REQUIEM_GETOPT_H
#define _LIBREQUIEM_REQUIEM_GETOPT_H

#include "requiem-msgbuf.h"


#ifdef __cplusplus
 extern "C" {
#endif

typedef enum {
        REQUIEM_OPTION_TYPE_CLI  = 0x01,
        REQUIEM_OPTION_TYPE_CFG  = 0x02,
        REQUIEM_OPTION_TYPE_WIDE = 0x04,
        REQUIEM_OPTION_TYPE_CONTEXT = 0x08,
        REQUIEM_OPTION_TYPE_ROOT    = 0x10,
        REQUIEM_OPTION_TYPE_DESTROY = 0x20
} requiem_option_type_t;


typedef enum {
        REQUIEM_OPTION_INPUT_TYPE_STRING   = 1,
        REQUIEM_OPTION_INPUT_TYPE_INTEGER  = 2,
        REQUIEM_OPTION_INPUT_TYPE_BOOLEAN  = 3
} requiem_option_input_type_t;


typedef struct requiem_option requiem_option_t;
typedef struct requiem_option_context requiem_option_context_t;

typedef int (*requiem_option_destroy_callback_t)(requiem_option_t *opt, requiem_string_t *out, void *context);
typedef int (*requiem_option_commit_callback_t)(requiem_option_t *opt, requiem_string_t *out, void *context);
typedef int (*requiem_option_get_callback_t)(requiem_option_t *opt, requiem_string_t *out, void *context);
typedef int (*requiem_option_set_callback_t)(requiem_option_t *opt, const char *optarg, requiem_string_t *err, void *context);


typedef enum {
        REQUIEM_OPTION_ARGUMENT_REQUIRED = 1,
        REQUIEM_OPTION_ARGUMENT_OPTIONAL = 2,
        REQUIEM_OPTION_ARGUMENT_NONE     = 3
} requiem_option_argument_t;


typedef enum {
        REQUIEM_OPTION_PRIORITY_IMMEDIATE = -2,
        REQUIEM_OPTION_PRIORITY_FIRST     = -1,
        REQUIEM_OPTION_PRIORITY_NONE      =  0,
        REQUIEM_OPTION_PRIORITY_LAST      =  2
} requiem_option_priority_t;


typedef enum {
        REQUIEM_OPTION_WARNING_OPTION    = 0x1,
        REQUIEM_OPTION_WARNING_ARG       = 0x2
} requiem_option_warning_t;


void requiem_option_set_priority(requiem_option_t *option, requiem_option_priority_t priority);


void requiem_option_print(requiem_option_t *opt, requiem_option_type_t type, int descoff, FILE *fd);

int requiem_option_wide_send_msg(requiem_msgbuf_t *msgbuf, void *context);

void requiem_option_destroy(requiem_option_t *option);

int requiem_option_read(requiem_option_t *option, const char **filename,
                        int *argc, char **argv, requiem_string_t **err, void *context);


int requiem_option_add(requiem_option_t *parent, requiem_option_t **retopt, requiem_option_type_t type,
                       char shortopt, const char *longopt, const char *desc, requiem_option_argument_t has_arg,
                       int (*set)(requiem_option_t *opt, const char *optarg, requiem_string_t *err, void *context),
                       int (*get)(requiem_option_t *opt, requiem_string_t *out, void *context));

void requiem_option_set_type(requiem_option_t *opt, requiem_option_type_t type);

requiem_option_type_t requiem_option_get_type(requiem_option_t *opt);

void requiem_option_set_warnings(requiem_option_warning_t new_warnings, requiem_option_warning_t *old_warnings);

char requiem_option_get_shortname(requiem_option_t *opt);

const char *requiem_option_get_longname(requiem_option_t *opt);

void _requiem_option_set_private_data(requiem_option_t *opt, void *data);

void *_requiem_option_get_private_data(requiem_option_t *opt);

void requiem_option_set_data(requiem_option_t *opt, void *data);

void *requiem_option_get_data(requiem_option_t *opt);


int requiem_option_invoke_commit(requiem_option_t *opt, const char *ctname, requiem_string_t *value, void *context);

int requiem_option_invoke_set(requiem_option_t *opt, const char *ctname, requiem_string_t *value, void **context);

int requiem_option_invoke_get(requiem_option_t *opt, const char *ctname, requiem_string_t *value, void *context);

int requiem_option_invoke_destroy(requiem_option_t *opt, const char *ctname, requiem_string_t *value, void *context);


/*
 *
 */
int requiem_option_new_root(requiem_option_t **retopt);

int requiem_option_new(requiem_option_t *parent, requiem_option_t **retopt);

void requiem_option_set_longopt(requiem_option_t *opt, const char *longopt);

const char *requiem_option_get_longopt(requiem_option_t *opt);

void requiem_option_set_description(requiem_option_t *opt, const char *description);

const char *requiem_option_get_description(requiem_option_t *opt);

void requiem_option_set_has_arg(requiem_option_t *opt, requiem_option_argument_t has_arg);

requiem_option_argument_t requiem_option_get_has_arg(requiem_option_t *opt);

void requiem_option_set_value(requiem_option_t *opt, const char *value);

const char *requiem_option_get_value(requiem_option_t *opt);

void requiem_option_set_help(requiem_option_t *opt, const char *help);

const char *requiem_option_get_help(requiem_option_t *opt);

void requiem_option_set_input_validation_regex(requiem_option_t *opt, const char *regex);

const char *requiem_option_get_input_validation_regex(requiem_option_t *opt);

void requiem_option_set_input_type(requiem_option_t *opt, requiem_option_input_type_t input_type);

requiem_option_input_type_t requiem_option_get_input_type(requiem_option_t *opt);

requiem_list_t *requiem_option_get_optlist(requiem_option_t *opt);

requiem_option_t *requiem_option_get_next(requiem_option_t *start, requiem_option_t *cur);

requiem_bool_t requiem_option_has_optlist(requiem_option_t *opt);

requiem_option_t *requiem_option_get_parent(requiem_option_t *opt);


void requiem_option_set_destroy_callback(requiem_option_t *opt,
                                         requiem_option_destroy_callback_t destroy);

requiem_option_destroy_callback_t requiem_option_get_destroy_callback(requiem_option_t *opt);


void requiem_option_set_set_callback(requiem_option_t *opt,
                                     requiem_option_set_callback_t set);

requiem_option_set_callback_t requiem_option_get_set_callback(requiem_option_t *opt);


void requiem_option_set_get_callback(requiem_option_t *opt,
                                     int (*get)(requiem_option_t *opt, requiem_string_t *out, void *context));

requiem_option_get_callback_t requiem_option_get_get_callback(requiem_option_t *opt);

void requiem_option_set_commit_callback(requiem_option_t *opt, requiem_option_commit_callback_t commit);

requiem_option_commit_callback_t requiem_option_get_commit_callback(requiem_option_t *opt);

void requiem_option_set_default_context(requiem_option_t *opt, void *context);

int requiem_option_new_context(requiem_option_t *opt, requiem_option_context_t **ctx, const char *name, void *data);

void requiem_option_context_destroy(requiem_option_context_t *oc);

void *requiem_option_context_get_data(requiem_option_context_t *oc);

void requiem_option_context_set_data(requiem_option_context_t *oc, void *data);

requiem_option_t *requiem_option_search(requiem_option_t *parent, const char *name,
                                        requiem_option_type_t type, requiem_bool_t walk_children);

requiem_option_context_t *requiem_option_search_context(requiem_option_t *opt, const char *name);

#ifdef __cplusplus
 }
#endif

#endif /* _LIBREQUIEM_REQUIEM_GETOPT_H */
