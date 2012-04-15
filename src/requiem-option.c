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

#include "config.h"
#include "libmissing.h"

#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <sys/types.h>
#include <assert.h>

#include "requiem-inttypes.h"
#include "requiem-message-id.h"
#include "requiem-msgbuf.h"

#include "requiem-linked-object.h"
#include "requiem-list.h"
#include "requiem-log.h"
#include "variable.h"
#include "config-engine.h"
#include "requiem-option.h"
#include "requiem-client.h"
#include "requiem-error.h"
#include "common.h"


#define SET_FROM_CLI  1
#define SET_FROM_CFG  2

#define DEFAULT_INSTANCE_NAME "default"


struct requiem_option_context {
        requiem_list_t list;
        void *data;
        char *name;
};


struct requiem_option {
        REQUIEM_LINKED_OBJECT;

        requiem_list_t optlist;
        requiem_option_t *parent;

        requiem_option_type_t type;
        requiem_option_priority_t priority;
        char shortopt;

        char *value;
        const char *longopt;
        const char *description;
        requiem_option_argument_t has_arg;

        int (*commit)(requiem_option_t *opt, requiem_string_t *out, void *context);
        int (*set)(requiem_option_t *opt, const char *optarg, requiem_string_t *out, void *context);
        int (*get)(requiem_option_t *opt, requiem_string_t *out, void *context);
        int (*destroy)(requiem_option_t *opt, requiem_string_t *out, void *context);

        const char *help;
        const char *input_validation_regex;
        requiem_option_input_type_t input_type;

        void *data;
        void *private_data;
        requiem_list_t value_list;

        void *default_context;
        requiem_list_t context_list;
};



struct cb_list {
        requiem_list_t list;
        char *arg;
        int set_from;
        requiem_list_t children;
        requiem_option_t *option;
};


static int get_missing_options(void *context, config_t *cfg,
                               const char *filename, requiem_list_t *cblist,
                               requiem_option_t *rootlist, unsigned int *line, int depth, requiem_string_t *err);

/*
 * contain all option
 */
static requiem_option_t *root_optlist = NULL;
extern requiem_option_t *_requiem_generic_optlist;


/*
 * Warning are turned on by default.
 */
static int warnings_flags = REQUIEM_OPTION_WARNING_OPTION|REQUIEM_OPTION_WARNING_ARG;




static void option_err(int flag, const char *fmt, ...)
{
        if ( warnings_flags & flag ) {
                va_list ap;

                va_start(ap, fmt);
                vfprintf(stderr, fmt, ap);
                va_end(ap);
        }
}



static int option_ret_error(requiem_error_code_t code, requiem_string_t *err, const char *fmt, ...)
{
        int ret;
        va_list ap;

        va_start(ap, fmt);

        requiem_string_vprintf(err, fmt, ap);
        ret = requiem_error_verbose(code, "%s", requiem_string_get_string(err));

        va_end(ap);

        return ret;
}



static int cmp_option(requiem_option_t *opt, const char *optname, size_t optnamelen, requiem_option_type_t type)
{
        if ( ! (opt->type & type) )
                return -1;

        if ( opt->longopt && strncasecmp(optname, opt->longopt, optnamelen) == 0 && strlen(opt->longopt) == optnamelen )
                return 0;

        if ( optnamelen == 1 && opt->shortopt == *optname )
                return 0;

        return -1;
}




/*
 * Search an option of a given name in the given option list.
 */
static requiem_option_t *search_option_fast(requiem_option_t *root, const char *optname, size_t optnamelen,
                                            requiem_option_type_t type, requiem_bool_t walk_children)
{
        int cmp;
        requiem_list_t *tmp;
        requiem_option_t *item, *ret;

        if ( ! root )
                return NULL;

#if 0
        cmp = cmp_option(root, optname, type);
        if ( cmp == 0 )
                return root;
#endif

        requiem_list_for_each(&root->optlist, tmp) {
                item = requiem_linked_object_get_object(tmp);

                if ( walk_children || (! item->longopt && ! item->shortopt) ) {
                        ret = search_option_fast(item, optname, optnamelen, type, walk_children);
                        if ( ret )
                                return ret;
                }

                cmp = cmp_option(item, optname, optnamelen, type);
                if ( cmp == 0 )
                        return item;
        }

        return NULL;
}

static requiem_option_t *search_option(requiem_option_t *root, const char *optname,
                                       requiem_option_type_t type, requiem_bool_t walk_children)
{
        return search_option_fast(root, optname, strcspn(optname, "="), type, walk_children);
}



static requiem_bool_t is_an_argument(const char *stuff)
{
        requiem_option_t *opt;
        size_t len = strlen(stuff);

        if ( stuff[0] == '-' && (len == 2 || (len > 2 && stuff[1] == '-')) ) {
                opt = requiem_option_search(NULL, stuff + strspn(stuff, "-"), ~0, TRUE);
                return opt ? FALSE : TRUE;
        }

        return TRUE;
}


static int check_option(requiem_option_t *option, const char *arg, requiem_string_t *err)
{
        int ret = 0;

        switch (option->has_arg) {

        case REQUIEM_OPTION_ARGUMENT_NONE:
                if ( arg )
                        ret = option_ret_error(REQUIEM_ERROR_GENERIC, err, "option '%s' does not take an argument", option->longopt);

        case REQUIEM_OPTION_ARGUMENT_OPTIONAL:
                break;

        case REQUIEM_OPTION_ARGUMENT_REQUIRED:
                if ( ! arg || ! is_an_argument(arg) )
                        ret = option_ret_error(REQUIEM_ERROR_GENERIC, err, "option '%s' require an argument", option->longopt);
                break;
        }

        return ret;
}



static int process_cfg_file(void *context, requiem_list_t *cblist, requiem_option_t *optlist,
                            const char *filename, requiem_string_t *err)
{
        int ret;
        config_t *cfg;
        unsigned int line = 0;

        requiem_log_debug(3, "Using configuration file: %s.\n", filename);

        ret = _config_open(&cfg, filename);
        if ( ret < 0 )
                return ret;

        ret = get_missing_options(context, cfg, filename, cblist, optlist, &line, 0, err);

        _config_close(cfg);

        return ret;
}




static int do_set(requiem_option_t *opt, const char *value, requiem_string_t *out, void **context)
{
        int ret;
        requiem_option_context_t *oc;

        if ( opt->default_context )
                *context = opt->default_context;

        if ( ! opt->set )
                return 0;

        if ( opt->has_arg == REQUIEM_OPTION_ARGUMENT_OPTIONAL && value && ! *value )
                value = NULL;

        ret = opt->set(opt, value, out, *context);
        if ( ret < 0 ) {
                if ( requiem_string_is_empty(out) ) {
                        requiem_string_sprintf(out, "error while setting option '%s'", opt->longopt);

                        if ( requiem_error_is_verbose(ret) || requiem_error_get_code(ret) != REQUIEM_ERROR_GENERIC )
                                requiem_string_sprintf(out, ": %s", requiem_strerror(ret));
                }

                return ret;
        }

        if ( opt->type & REQUIEM_OPTION_TYPE_CONTEXT ) {

                oc = requiem_option_search_context(opt, value);
                if ( ! oc )
                        return -1;

                *context = oc->data;
        }

        return ret;
}



static int call_option_cb(void *context, struct cb_list **cbl, requiem_list_t *cblist,
                          requiem_option_t *option, const char *arg, requiem_string_t *err, int set_from)
{
        struct cb_list *new, *cb;
        requiem_option_priority_t pri;
        requiem_list_t *tmp, *prev = NULL;

        if ( option->priority == REQUIEM_OPTION_PRIORITY_IMMEDIATE ) {
                requiem_log_debug(3, "[immediate] %s(%s)\n", option->longopt, arg ? arg : "");
                return do_set(option, arg, err, &context);
        }

        requiem_log_debug(3, "[queue=%p] %s(%s)\n", cblist,  option->longopt, arg ? arg : "");

        requiem_list_for_each(cblist, tmp) {
                cb = requiem_list_entry(tmp, struct cb_list, list);

                pri = option->priority;

                if ( set_from == SET_FROM_CFG && option->priority == cb->option->priority && cb->set_from == SET_FROM_CLI ) {
                        prev = tmp;
                        break;
                }

                else if ( pri < cb->option->priority ) {
                        prev = tmp;
                        break;
                }
        }

        *cbl = new = malloc(sizeof(*new));
        if ( ! new )
                return requiem_error_from_errno(errno);

        requiem_list_init(&new->children);


        new->option = option;
        new->set_from = set_from;
        new->arg = (arg) ? strdup(arg) : NULL;

        if ( option->priority == REQUIEM_OPTION_PRIORITY_LAST ) {
                requiem_list_add_tail(cblist, &new->list);
                return 0;
        }

        if ( ! prev )
                prev = cblist;

        requiem_list_add_tail(prev, &new->list);
        *cbl = new;

        return 0;
}



static int call_option_from_cb_list(requiem_list_t *cblist, requiem_string_t *err, void *default_context, int depth)
{
        int ret = 0;
        struct cb_list *cb;
        requiem_list_t *tmp, *bkp;
        void *context = default_context;

        requiem_list_for_each_safe(cblist, tmp, bkp) {
                cb = requiem_list_entry(tmp, struct cb_list, list);

                requiem_log_debug(2, "%s(%s) context=%p default=%p\n",
                                  cb->option->longopt, cb->arg ? cb->arg : "", context, default_context);

                ret = do_set(cb->option, cb->arg, err, &context);
                if ( ret < 0 )
                        return ret;

                if ( ! requiem_list_is_empty(&cb->children) ) {
                        ret = call_option_from_cb_list(&cb->children, err, context, depth + 1);
                        if ( ret < 0 )
                                return ret;
                }

                if ( cb->option->commit ) {
                        requiem_log_debug(2, "commit %s\n", cb->option->longopt);

                        ret = cb->option->commit(cb->option, err, context);
                        if ( ret < 0 ) {
                                return ret;
                        }
                }

                context = default_context;

                if ( cb->arg )
                        free(cb->arg);

                requiem_list_del(&cb->list);
                free(cb);
        }

        return 0;
}




/*
 * Try to get all option that were not set from the command line in the config file.
 */
static int get_missing_options(void *context, config_t *cfg, const char *filename, requiem_list_t *cblist,
                               requiem_option_t *rootlist, unsigned int *line, int depth, requiem_string_t *err)
{
        int ret;
        requiem_option_t *opt;
        struct cb_list *cbitem;
        char *section = NULL, *entry = NULL, *value = NULL;

        while ( (_config_get_next(cfg, &section, &entry, &value, line)) == 0 ) {
                opt = search_option(rootlist, (section && ! entry) ? section : entry, REQUIEM_OPTION_TYPE_CFG, FALSE);

                if ( ! opt && entry && value && strcmp(entry, "include") == 0 ) {

                        ret = process_cfg_file(context, cblist, rootlist, value, err);
                        if ( ret < 0 )
                                return ret;

                        continue;
                }

                if ( ! opt ) {
                        if ( (opt = search_option(_requiem_generic_optlist, (section && ! entry) ? section : entry, ~0, FALSE)) ) {
                                get_missing_options(context, cfg, filename, NULL, opt, line, depth + 1, err);
                                continue;
                        }

                        if ( depth != 0 ) {
                                (*line)--;
                                if ( entry ) free(entry);
                                if ( value ) free(value);
                                if ( section ) free(section);

                                return 0;
                        }

                        if ( section && ! entry )
                                option_err(REQUIEM_OPTION_WARNING_OPTION,
                                           "%s:%d: invalid section : \"%s\".\n", filename, *line, section);
                        else
                                option_err(REQUIEM_OPTION_WARNING_ARG,
                                           "%s:%d: invalid option \"%s\" in \"%s\" section.\n",
                                           filename, *line, entry, (section) ? section : "global");

                        continue;
                }

                if ( section && ! entry ) {

                        if ( cblist ) {
                                ret = check_option(opt, value, err);
                                if ( ret < 0 ) {
                                        const char *tmp = _requiem_thread_get_error();
                                        return requiem_error_verbose(requiem_error_get_code(ret), "%s:%d: %s", filename, *line, tmp);
                                }

                                ret = call_option_cb(context, &cbitem, cblist, opt, value, err, SET_FROM_CFG);
                                if ( ret < 0 )
                                        return ret;
                        }

                        ret = get_missing_options(context, cfg, filename, (cblist) ?
                                                  &cbitem->children : NULL, opt, line, depth + 1, err);
                        if ( ret < 0 )
                                return ret;

                }

                else if ( cblist ) {
                        ret = check_option(opt, value, err);
                        if ( ret < 0 ) {
                                const char *tmp = _requiem_thread_get_error();
                                return requiem_error_verbose(requiem_error_get_code(ret), "%s:%d: %s", filename, *line, tmp);
                        }

                        ret = call_option_cb(context, &cbitem, cblist, opt, value, err, SET_FROM_CFG);
                        if ( ret < 0 )
                                return ret;
                }
        }

        return 0;
}


static void remove_argv(int argc, char **argv, char **unhandled, int *unhandled_index, int removed)
{
        int i;

        unhandled[(*unhandled_index)++] = argv[removed];

        for ( i = removed; (i + 1) < argc; i++ )
                argv[i] = argv[i + 1];
}



static int parse_option(requiem_option_t *root_optlist, requiem_option_t *optlist,
                        int *argc, char **argv, int *argv_index,
                        char **unhandled, int *unhandled_index, char **option, const char **value,
                        requiem_option_t **opt, requiem_bool_t *ignore)
{
        size_t len;
        int ret, optch = 0;
        requiem_option_t *tmp;

        *value = NULL;

        *option = argv[(*argv_index)++];
        len = strlen(*option);

        if ( **option != '-' || len == 1 ) {
                remove_argv(*argc, argv, unhandled, unhandled_index, --(*argv_index));
                return 0;
        }

        if ( strcmp(*option, "--") == 0 ) {
                for ( ret = *argv_index; ret < *argc; ret++ )
                        remove_argv(*argc, argv, unhandled, unhandled_index, ret);

                return -1; /* break */
        }

        while ( **option == '-' ) {
                (*option)++;
                optch++;
        }

        if ( ! isalnum((int) **option) )
                return 0;

        /*
         * FIXME: handle consecutive shortopt
         */

        *value = strchr(*option, '=');
        if ( ! *value )
                *option = strdup(*option);
        else {
                *option = strndup(*option, strcspn(*option, "="));
                (*value)++;
        }

        *opt = search_option(optlist, *option, REQUIEM_OPTION_TYPE_CLI, FALSE);

        if ( root_optlist != _requiem_generic_optlist &&
             (tmp = search_option(_requiem_generic_optlist, *option, ~0, FALSE)) ) {
                *opt = tmp;
                *ignore = TRUE;
        }

        if ( ! *opt )
                return 1;

        if ( (*opt)->has_arg == REQUIEM_OPTION_ARGUMENT_REQUIRED && ! *value && (*argv_index < *argc)  )
                *value = argv[(*argv_index)++];

        return 1;
}



static int parse_argument(void *context, requiem_list_t *cb_list,
                          requiem_option_t *root_optlist, requiem_option_t *optlist,
                          int *argc, char **argv, int *argv_index,
                          char **unhandled, int *unhandled_index,
                          int depth, requiem_string_t *err, requiem_bool_t ignore)
{
        int ret;
        char *option;
        const char *arg;
        requiem_option_t *opt;
        struct cb_list *cbitem;

        while ( *argv_index < (*argc - *unhandled_index) ) {
                ret = parse_option(root_optlist, optlist, argc, argv, argv_index,
                                   unhandled, unhandled_index, &option, &arg, &opt, &ignore);
                if ( ret < 0 )
                        break;

                else if ( ret == 0 )
                        continue;

                if ( ! opt ) {
                        if ( depth ) {
                                free(option);
                                (*argv_index)--;
                                return 0;
                        }

                        remove_argv(*argc, argv, unhandled, unhandled_index, --(*argv_index));
                        option_err(REQUIEM_OPTION_WARNING_OPTION, "Invalid option -- \"%s\" (%d).\n", option, depth);
                        free(option);

                        continue;
                }

                free(option);

                ret = check_option(opt, arg, err);
                if ( ret < 0 )
                        return ret;

                if ( ! ignore ) {
                        ret = call_option_cb(context, &cbitem, cb_list, opt, arg, err, SET_FROM_CLI);
                        if ( ret < 0 )
                                return ret;
                }

                /*
                 * If the option we just found have sub-option.
                 * Try to match the rest of our argument against them.
                 */
                if ( ! requiem_list_is_empty(&opt->optlist) ) {

                        ret = parse_argument(context, &cbitem->children, root_optlist, opt,
                                             argc, argv, argv_index, unhandled, unhandled_index, depth + 1, err, ignore);

                        if ( ret < 0 )
                                return ret;

                        ignore = FALSE;
                }
        }

        return 0;
}




static int get_option_from_optlist(void *context, requiem_option_t *optlist,
                                   const char **filename, int *argc, char **argv, requiem_string_t **err)
{
        char **unhandled;
        requiem_list_t cblist;
        int i, unhandled_index = 0, argv_index = 1, ret = 0;

        requiem_list_init(&cblist);

        if ( argc ) {
                unhandled = malloc(*argc * sizeof(*unhandled));
                if ( ! unhandled )
                        return requiem_error_from_errno(errno);

                ret = parse_argument(context, &cblist, optlist, optlist, argc, argv, &argv_index,
                                     unhandled, &unhandled_index, 0, *err, FALSE);

                for ( i = 0; i < unhandled_index; i++)
                        argv[*argc - unhandled_index + i] = unhandled[i];

                free(unhandled);

                if ( ret < 0 )
                        return ret;

                unhandled_index += ret;
        }

        if ( filename && *filename ) {
                ret = process_cfg_file(context, &cblist, optlist, *filename, *err);
                if ( ret < 0 )
                        return ret;
        }

        ret = call_option_from_cb_list(&cblist, *err, context, 0);
        if ( ret < 0 )
                return ret;

        return *argc - unhandled_index;
}






/**
 * requiem_option_read:
 * @option: A pointer on an option (list).
 * @filename: Pointer to the config filename.
 * @argc: Number of argument.
 * @argv: Argument list.
 * @err: Pointer to a #requiem_string_t object where to store an error string.
 * @context: Pointer to an optional option context.
 *
 * requiem_option_read(), parse the given argument and try to
 * match them against option in @option. If an option match, it's associated
 * callback function is called with the eventual option argument if any.
 *
 * Option not matched on the command line are searched in the configuration file
 * specified by @filename.
 *
 * if @option is NULL, all system option will be matched against argc, and argv.
 *
 * Returns: The index of the first unhandled parameter if option parsing succeeded,
 * or a negative value if an error occured.
 */
int requiem_option_read(requiem_option_t *option, const char **filename,
                        int *argc, char **argv, requiem_string_t **err, void *context)
{
        int ret;
        REQUIEM_LIST(optlist);

        ret = requiem_string_new(err);
        if ( ret < 0 )
                return ret;

        if ( option )
                ret = get_option_from_optlist(context, option, filename, argc, argv, err);
        else
                ret = get_option_from_optlist(context, root_optlist, filename, argc, argv, err);

        if ( ret < 0 )
                goto err;

 err:
        if ( requiem_string_is_empty(*err) ) {
                requiem_string_destroy(*err);
                *err = NULL;
        }

        return ret;
}





/**
 * requiem_option_add:
 * @parent: Pointer on a parent option.
 * @retopt: Pointer where to store the created option.
 * @type: bitfields.
 * @shortopt: Short option name.
 * @longopt: Long option name.
 * @desc: Description of the option.
 * @has_arg: Define if the option has argument.
 * @set: Callback to be called when the value for this option change.
 * @get: Callback to be called to get the value for this option.
 *
 * requiem_option_add() create a new option. The option is set to be the child
 * of @parent, unless it is NULL. In this case the option is a root option.
 *
 * The @type parameters can be set to REQUIEM_OPTION_TYPE_CLI (telling the
 * option may be searched on the command line), REQUIEM_OPTION_TYPE_CFG (telling
 * the option may be searched in the configuration file) or both.
 *
 * Returns: Pointer on the option object, or NULL if an error occured.
 */
int requiem_option_add(requiem_option_t *parent, requiem_option_t **retopt, requiem_option_type_t type,
                       char shortopt, const char *longopt, const char *desc, requiem_option_argument_t has_arg,
                       int (*set)(requiem_option_t *opt, const char *optarg, requiem_string_t *err, void *context),
                       int (*get)(requiem_option_t *opt, requiem_string_t *out, void *context))
{
        int ret;
        requiem_option_t *new;

        if ( parent ) {
                requiem_option_t *dup;
                char tmp[2] = { shortopt, 0 };

                if ( longopt && (dup = requiem_option_search(parent, longopt, ~0, FALSE)) ) {
                        requiem_log(REQUIEM_LOG_WARN, "New option '%s' ('%c') conflict with '%s' ('%c').\n",
                                    longopt, shortopt, dup->longopt, dup->shortopt);
                        return -1;
                }

                if ( shortopt && (dup = requiem_option_search(parent, tmp, ~0, FALSE)) ) {
                        requiem_log(REQUIEM_LOG_WARN, "New option '%s' ('%c') conflict with '%s' ('%c').\n",
                                    longopt, shortopt, dup->longopt, dup->shortopt);
                        return -1;
                }
        }

        if ( type & REQUIEM_OPTION_TYPE_WIDE && ! longopt )
                return -1;

        ret = requiem_option_new(parent, &new);
        if ( ret < 0 )
                return ret;

        requiem_list_init(&new->optlist);
        requiem_list_init(&new->context_list);

        new->priority = REQUIEM_OPTION_PRIORITY_NONE;
        new->input_type = REQUIEM_OPTION_INPUT_TYPE_STRING;

        new->type = type;
        new->has_arg = has_arg;
        new->longopt = longopt;
        new->shortopt = shortopt;
        new->description = desc;
        new->set = set;
        new->get = get;

        if ( retopt )
                *retopt = new;

        return 0;
}



static int uint32_write(uint32_t data, requiem_msgbuf_t *msg, uint8_t tag)
{
        data = htonl(data);
        return requiem_msgbuf_set(msg, tag, sizeof(data), &data);
}



static void send_option_msg(requiem_bool_t parent_need_context,
                            void *context, requiem_option_t *opt, const char *iname, requiem_msgbuf_t *msg)
{
        int ret;
        requiem_string_t *value;
        const char *name = (iname) ? iname : opt->longopt;

        requiem_msgbuf_set(msg, REQUIEM_MSG_OPTION_START, 0, NULL);
        requiem_msgbuf_set(msg, REQUIEM_MSG_OPTION_NAME, strlen(name) + 1, name);

        uint32_write(opt->type, msg, REQUIEM_MSG_OPTION_TYPE);
        uint32_write(opt->has_arg, msg, REQUIEM_MSG_OPTION_HAS_ARG);
        uint32_write(opt->input_type, msg, REQUIEM_MSG_OPTION_INPUT_TYPE);

        if ( opt->description )
                requiem_msgbuf_set(msg, REQUIEM_MSG_OPTION_DESC, strlen(opt->description) + 1, opt->description);

        if ( opt->type & REQUIEM_OPTION_TYPE_CONTEXT && ! context )
                return;

        if ( parent_need_context && ! context )
                return;

        if ( ! opt->get )
                return;

        ret = requiem_string_new(&value);
        if ( ret < 0 )
                return;

        ret = opt->get(opt, value, context);
        if ( ret < 0 ) {
                requiem_string_destroy(value);
                return;
        }

        if ( ! requiem_string_is_empty(value) )
                requiem_msgbuf_set(msg, REQUIEM_MSG_OPTION_VALUE,
                                   requiem_string_get_len(value) + 1,
                                   requiem_string_get_string(value));

        requiem_string_destroy(value);
}


static void construct_option_msg(requiem_bool_t parent_need_context,
                                 void *default_context, requiem_msgbuf_t *msg, requiem_option_t *root)
{
        char value[1024];
        requiem_option_t *opt;
        requiem_list_t *tmp, *tmp2;
        requiem_option_context_t *oc;

        requiem_list_for_each(&root->optlist, tmp) {
                opt = requiem_linked_object_get_object(tmp);

                requiem_list_for_each(&opt->context_list, tmp2) {
                        oc = requiem_list_entry(tmp2, requiem_option_context_t, list);

                        snprintf(value, sizeof(value), "%s[%s]", opt->longopt, oc->name);

                        if ( opt->type & REQUIEM_OPTION_TYPE_WIDE )
                                send_option_msg(TRUE, oc->data, opt, value, msg);

                        construct_option_msg(TRUE, oc->data, msg, opt);

                        if ( opt->type & REQUIEM_OPTION_TYPE_WIDE )
                                requiem_msgbuf_set(msg, REQUIEM_MSG_OPTION_END, 0, NULL);
                }

                if ( requiem_list_is_empty(&opt->context_list) ) {
                        void *ctx = NULL;
                        requiem_bool_t need_ctx = opt->type & REQUIEM_OPTION_TYPE_CONTEXT ? TRUE : parent_need_context;

                        if ( ! (opt->type & REQUIEM_OPTION_TYPE_CONTEXT) )
                                ctx = opt->default_context ? opt->default_context : default_context;

                        if ( opt->type & REQUIEM_OPTION_TYPE_WIDE )
                                send_option_msg(need_ctx, ctx, opt, NULL, msg);

                        construct_option_msg(need_ctx, ctx, msg, opt);

                        if ( opt->type & REQUIEM_OPTION_TYPE_WIDE )
                                requiem_msgbuf_set(msg, REQUIEM_MSG_OPTION_END, 0, NULL);
                }
        }
}




int requiem_option_wide_send_msg(requiem_msgbuf_t *msgbuf, void *context)
{
        requiem_msgbuf_set(msgbuf, REQUIEM_MSG_OPTION_LIST, 0, NULL);
        requiem_msgbuf_set(msgbuf, REQUIEM_MSG_OPTION_START, 0, NULL);

        construct_option_msg(FALSE, context, msgbuf, root_optlist);

        return 0;
}




static int get_max_char(const char *line, int descoff)
{
        int desclen;
        int max = 0 , i;

        desclen = 80 - descoff;

        for ( i = 0; i < desclen; i++ ) {

                if ( line[i] == '\0' )
                        return i;

                if ( line[i] == ' ' )
                        max = i;
        }

        return max;
}



static int print_space(FILE *fd, size_t num)
{
        char buf[3];
        size_t len, totlen = 0;

        do {
                len = MIN(sizeof(buf), num - totlen);

                memset(buf, ' ', len);
                fwrite(buf, 1, len, fd);
                totlen += len;

        } while ( totlen < num );

        return num;
}


static void print_wrapped(FILE *fd, const char *line, int descoff)
{
        int max;
        size_t size = 0, i;

        while ( 1 ) {
                max = get_max_char(line + size, descoff);

                size += i= fwrite(line + size, 1, max, fd);
                if ( line[size] == '\0' ) {
                        fputc('\n', fd);
                        return;
                }

                fputc('\n', fd);
                print_space(fd, descoff - 1);
        }
}



static void print_options(FILE *fd, requiem_option_t *root, requiem_option_type_t type, int descoff, int depth)
{
        int i;
        requiem_option_t *opt;
        requiem_list_t *tmp;

        requiem_list_for_each(&root->optlist, tmp) {

                opt = requiem_linked_object_get_object(tmp);

                /*
                 * If type is not there, continue.
                 */
                if ( opt->type == REQUIEM_OPTION_TYPE_ROOT )
                        print_options(fd, opt, type, descoff, depth);
                else {
                        i = 0;
                        if ( type && ! (opt->type & type) )
                                continue;

                        if ( depth ) {
                                i += depth;
                                print_space(fd, depth * 2);
                        }

                        if ( ! requiem_list_is_empty(&opt->optlist) )
                                fputc('\n', fd);

                        if ( opt->shortopt != 0 )
                                i += fprintf(fd, "-%c%s", opt->shortopt, opt->longopt ? ", " : " ");

                        if ( opt->longopt ) {
                                if ( ! opt->shortopt && requiem_list_is_empty(&opt->optlist) )
                                        i += fprintf(fd, "    ");

                                i += fprintf(fd, "--%s", opt->longopt);
                                if ( (opt->has_arg == REQUIEM_OPTION_ARGUMENT_OPTIONAL ||
                                      opt->has_arg == REQUIEM_OPTION_ARGUMENT_REQUIRED) &&
                                     ! requiem_list_is_empty(&opt->optlist) )
                                        i += fprintf(fd, "=[INAME] ");

                                else if ( opt->has_arg == REQUIEM_OPTION_ARGUMENT_REQUIRED )
                                        i += fprintf(fd, "=ARG ");

                                else if ( opt->has_arg == REQUIEM_OPTION_ARGUMENT_OPTIONAL )
                                        i += fprintf(fd, "=[ARG] ");
                                else
                                        i+= fprintf(fd, " ");
                        }

                        if ( i < descoff )
                                i += print_space(fd, descoff - i);

                        if ( opt->description )
                                print_wrapped(fd, opt->description, depth + descoff);
                        else
                                fputc('\n', fd);

                        if ( ! requiem_list_is_empty(&opt->optlist) )
                                print_options(fd, opt, type, descoff, depth + 1);
                }
        }
        fputc('\n', fd);
}




/**
 * requiem_option_print:
 * @opt: Option(s) to print out.
 * @type: Only option with specified types will be printed.
 * @descoff: offset from the begining of the line where the description should start.
 * @fd: File descriptor where the option should be dumped.
 *
 * Dump option available in @opt and hooked to the given types.
 * If @opt is NULL, then the root of the option list is used.
 */
void requiem_option_print(requiem_option_t *opt, requiem_option_type_t type, int descoff, FILE *fd)
{
        descoff += 9;
        print_options(fd, opt ? opt : root_optlist, type, descoff, 0);
}



/**
 * requiem_option_set_priority:
 * @option: Pointer on an option object.
 * @priority: Priority of the option object.
 *
 * requiem_option_set_priority() can be used to associate a priority
 * with an option. This can be used to solve dependancies problem within
 * differents options.
 *
 * A priority of -1 mean an option will always be executed last (with
 * all other option with a -1 priority).
 *
 * The default priority for an option is 0, the caller is responssible
 * for the way it assign priority (knowing that highest priority are always
 * executed first).
 */
void requiem_option_set_priority(requiem_option_t *option, requiem_option_priority_t priority)
{
        assert(requiem_list_is_empty(&option->optlist));
        option->priority = priority;
}




/**
 * requiem_option_destroy:
 * @option: Pointer on an option object.
 *
 * Destroy a #requiem_option_t object and all data associated
 * with it (including all suboption).
 */
void requiem_option_destroy(requiem_option_t *option)
{
        requiem_list_t *tmp, *bkp;
        requiem_option_t *opt;

        if ( ! option ) {
                option = root_optlist;
                root_optlist = NULL;
        }

        requiem_list_for_each_safe(&option->optlist, tmp, bkp) {
                opt = requiem_linked_object_get_object(tmp);
                requiem_option_destroy(opt);
        }

        if ( option->value )
                free(option->value);

        requiem_list_for_each_safe(&option->context_list, tmp, bkp)
                requiem_option_context_destroy(requiem_list_entry(tmp, requiem_option_context_t, list));

        if ( ! requiem_list_is_empty(&option->_list) )
                requiem_linked_object_del((requiem_linked_object_t *) option);

        free(option);
}




/**
 * requiem_option_set_warnings;
 * @new_warnings: bitwise OR of #requiem_option_warning_t.
 * @old_warnings: Pointer where to store the old #requiem_option_warning_t to.
 *
 * Set current warnings flags to @new_warnings.
 *
 * Uppon return, if not NULL, the pointer to @old_warnings is updated
 * to contain the old warnings.
 */
void requiem_option_set_warnings(requiem_option_warning_t new_warnings, requiem_option_warning_t *old_warnings)
{
        if ( old_warnings )
                *old_warnings = warnings_flags;

        warnings_flags = new_warnings;
}


void requiem_option_set_commit_callback(requiem_option_t *opt,
                                        requiem_option_commit_callback_t commit)
{
        opt->commit = commit;
}


requiem_option_commit_callback_t requiem_option_get_commit_callback(requiem_option_t *opt)
{
        return opt->commit;
}


void requiem_option_set_get_callback(requiem_option_t *opt,
                                     requiem_option_get_callback_t get)
{
        opt->get = get;
}



requiem_option_get_callback_t requiem_option_get_get_callback(requiem_option_t *opt)
{
        return opt->get;
}




void requiem_option_set_set_callback(requiem_option_t *opt,
                                     int (*set)(requiem_option_t *opt, const char *optarg, requiem_string_t *out, void *context))
{
        opt->set = set;
}



requiem_option_set_callback_t requiem_option_get_set_callback(requiem_option_t *opt)
{
        return opt->set;
}



void requiem_option_set_destroy_callback(requiem_option_t *opt,
                                         requiem_option_destroy_callback_t destroy)
{
        opt->destroy = destroy;
        opt->type |= REQUIEM_OPTION_TYPE_DESTROY;
}



requiem_option_destroy_callback_t requiem_option_get_destroy_callback(requiem_option_t *opt)
{
        return opt->destroy;
}



char requiem_option_get_shortname(requiem_option_t *opt)
{
        return opt->shortopt;
}



const char *requiem_option_get_longname(requiem_option_t *opt)
{
        return opt->longopt;
}



void requiem_option_set_value(requiem_option_t *opt, const char *value)
{
        if ( opt->value )
                free(opt->value);

        opt->value = strdup(value);
}



requiem_list_t *requiem_option_get_optlist(requiem_option_t *opt)
{
        return &opt->optlist;
}



requiem_option_t *requiem_option_get_next(requiem_option_t *start, requiem_option_t *cur)
{
        requiem_list_t *tmp = (cur) ? &cur->_list : NULL;

        requiem_list_for_each_continue(&start->optlist, tmp)
                return requiem_linked_object_get_object(tmp);

        return NULL;
}



requiem_bool_t requiem_option_has_optlist(requiem_option_t *opt)
{
        return ! requiem_list_is_empty(&opt->optlist);
}



const char *requiem_option_get_value(requiem_option_t *opt)
{
        return opt->value;
}



void _requiem_option_set_private_data(requiem_option_t *opt, void *data)
{
        opt->private_data = data;
}



void *_requiem_option_get_private_data(requiem_option_t *opt)
{
        return opt->private_data;
}



void requiem_option_set_data(requiem_option_t *opt, void *data)
{
        opt->data = data;
}



void *requiem_option_get_data(requiem_option_t *opt)
{
        return opt->data;
}



int requiem_option_invoke_set(requiem_option_t *opt, const char *value, requiem_string_t *err, void **context)
{
        int ret;

        ret = check_option(opt, value, err);
        if ( ret < 0 )
                return ret;

        requiem_log_debug(3, "opt=%s value=%s\n", opt->longopt, value ? value : "");

        return do_set(opt, value, err, context);
}



int requiem_option_invoke_commit(requiem_option_t *opt, const char *ctname, requiem_string_t *value, void *context)
{
        int ret;
        requiem_option_context_t *oc = NULL;

        if ( ! opt->commit )
                return 0;

        if ( opt->default_context )
                context = opt->default_context;

        if ( opt->type & REQUIEM_OPTION_TYPE_CONTEXT ) {
                oc = requiem_option_search_context(opt, ctname);
                if ( ! oc )
                        return option_ret_error(REQUIEM_ERROR_GENERIC, value,
                                                "could not find option with context %s[%s]", opt->longopt, ctname);
                context = oc->data;
        }

        ret = opt->commit(opt, value, context);
        if ( ret < 0 && requiem_string_is_empty(value) )
                ret = option_ret_error(requiem_error_get_code(ret), value,
                                       "could not find option with context %s[%s]", opt->longopt, ctname);

        return ret;
}



int requiem_option_invoke_destroy(requiem_option_t *opt, const char *ctname, requiem_string_t *value, void *context)
{
        int ret;
        requiem_option_context_t *oc = NULL;

        if ( ! opt->destroy )
                return option_ret_error(REQUIEM_ERROR_GENERIC, value, "%s does not support destruction", opt->longopt);

        if ( opt->default_context )
                context = opt->default_context;

        if ( opt->type & REQUIEM_OPTION_TYPE_CONTEXT ) {
                oc = requiem_option_search_context(opt, ctname);
                if ( ! oc )
                        return option_ret_error(REQUIEM_ERROR_GENERIC, value,
                                                "could not find option with context %s[%s]", opt->longopt, ctname);

                context = oc->data;
        }

        ret = opt->destroy(opt, value, context);
        if ( ret < 0 && requiem_string_is_empty(value) )
                return option_ret_error(REQUIEM_ERROR_GENERIC, value, "destruction for %s[%s] failed", opt->longopt, ctname);

        if ( oc )
                requiem_option_context_destroy(oc);

        return 0;
}



int requiem_option_invoke_get(requiem_option_t *opt, const char *ctname, requiem_string_t *value, void *context)
{
        requiem_option_context_t *oc;

        if ( ! opt->get ) {
                requiem_string_sprintf(value, "%s doesn't support value retrieval", opt->longopt);
                return -1;
        }

        if ( opt->default_context )
                context = opt->default_context;

        if ( opt->type & REQUIEM_OPTION_TYPE_CONTEXT ) {
                oc = requiem_option_search_context(opt, ctname);
                if ( ! oc ) {
                        requiem_string_sprintf(value, "could not find option with context %s[%s]",
                                               opt->longopt, ctname);
                        return -1;
                }

                context = oc->data;
        }

        return opt->get(opt, value, context);
}




int requiem_option_new(requiem_option_t *parent, requiem_option_t **retopt)
{
        requiem_option_t *new;

        if ( ! parent ) {
                if ( ! root_optlist ) {

                        root_optlist = calloc(1, sizeof(*root_optlist));
                        if ( ! root_optlist )
                                return requiem_error_from_errno(errno);

                        root_optlist->parent = parent;
                        requiem_list_init(&root_optlist->optlist);
                        requiem_list_init(&root_optlist->context_list);
                        requiem_list_init(&root_optlist->_list);
                }

                parent = root_optlist;
        }

        new = *retopt = calloc(1, sizeof(**retopt));
        if ( ! new )
                return requiem_error_from_errno(errno);

        new->parent = parent;
        requiem_list_init(&new->optlist);
        requiem_list_init(&new->context_list);
        requiem_linked_object_add_tail(&parent->optlist, (requiem_linked_object_t *) new);

        return 0;
}



int requiem_option_new_root(requiem_option_t **retopt)
{
        int ret;
        requiem_option_t *new;

        ret = requiem_option_new(NULL, &new);
        if ( ret < 0 )
                return ret;

        new->longopt = NULL;
        new->type = REQUIEM_OPTION_TYPE_ROOT;

        if ( retopt )
                *retopt = new;

        return 0;
}



void requiem_option_set_longopt(requiem_option_t *opt, const char *longopt)
{
        opt->longopt = longopt;
}



const char *requiem_option_get_longopt(requiem_option_t *opt)
{
        return opt->longopt;
}



void requiem_option_set_description(requiem_option_t *opt, const char *description)
{
        opt->description = description;
}



const char *requiem_option_get_description(requiem_option_t *opt)
{
        return opt->description;
}



void requiem_option_set_type(requiem_option_t *opt, requiem_option_type_t type)
{
        opt->type = type;
}


requiem_option_type_t requiem_option_get_type(requiem_option_t *opt)
{
        return opt->type;
}



void requiem_option_set_has_arg(requiem_option_t *opt, requiem_option_argument_t has_arg)
{
        opt->has_arg = has_arg;
}



requiem_option_argument_t requiem_option_get_has_arg(requiem_option_t *opt)
{
        return opt->has_arg;
}



void requiem_option_set_help(requiem_option_t *opt, const char *help)
{
        opt->help = help;
}



const char *requiem_option_get_help(requiem_option_t *opt)
{
        return opt->help;
}



void requiem_option_set_input_validation_regex(requiem_option_t *opt, const char *regex)
{
        opt->input_validation_regex = regex;
}



const char *requiem_option_get_input_validation_regex(requiem_option_t *opt)
{
        return opt->input_validation_regex;
}



void requiem_option_set_input_type(requiem_option_t *opt, requiem_option_input_type_t input_type)
{
        opt->input_type = input_type;
}



requiem_option_input_type_t requiem_option_get_input_type(requiem_option_t *opt)
{
        return opt->input_type;
}



requiem_option_t *requiem_option_get_parent(requiem_option_t *opt)
{
        return opt->parent;
}



void requiem_option_set_default_context(requiem_option_t *opt, void *data)
{
        opt->default_context = data;
}



int requiem_option_new_context(requiem_option_t *opt, requiem_option_context_t **ctx, const char *name, void *data)
{
        requiem_option_context_t *new;

        new = malloc(sizeof(*new));
        if ( ! new )
                return requiem_error_from_errno(errno);

        if ( ! name || ! *name )
                name = DEFAULT_INSTANCE_NAME;

        new->data = data;

        new->name = strdup(name);
        if ( ! new->name ) {
                free(new);
                return requiem_error_from_errno(errno);
        }

        if ( ! opt )
                requiem_list_init(&new->list);
        else {
                opt->type |= REQUIEM_OPTION_TYPE_CONTEXT;
                requiem_list_add_tail(&opt->context_list, &new->list);
        }

        *ctx = new;

        return 0;
}


void requiem_option_context_set_data(requiem_option_context_t *oc, void *data)
{
        oc->data = data;
}



void *requiem_option_context_get_data(requiem_option_context_t *oc)
{
        return oc->data;
}



void requiem_option_context_destroy(requiem_option_context_t *oc)
{
        if ( ! requiem_list_is_empty(&oc->list) )
                requiem_list_del(&oc->list);

        if ( oc->name )
                free(oc->name);

        free(oc);
}



requiem_option_t *requiem_option_search(requiem_option_t *parent, const char *name,
                                        requiem_option_type_t type, requiem_bool_t walk_children)
{
        return search_option(parent ? parent : root_optlist, name, type, walk_children);
}



requiem_option_context_t *requiem_option_search_context(requiem_option_t *opt, const char *name)
{
        int ret;
        requiem_list_t *tmp;
        requiem_option_context_t *ptr;

        if ( ! name || ! *name )
                name = DEFAULT_INSTANCE_NAME;

        requiem_list_for_each(&opt->context_list, tmp) {

                ptr = requiem_list_entry(tmp, requiem_option_context_t, list);

                ret = strcasecmp(ptr->name, name);
                if ( ret == 0 )
                        return ptr;
        }

        return NULL;
}
