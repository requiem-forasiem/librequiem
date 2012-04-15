/*****
*
* Copyright (C) 2004,2005,2006,2007 PreludeIDS Technologies. All Rights Reserved.
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
#include <stdlib.h>
#include <unistd.h>
#include <gnutls/gnutls.h>
#include <gcrypt.h>

#include "glthread/thread.h"
#include "glthread/lock.h"

#include "requiem.h"
#include "idmef-path.h"
#include "requiem-option.h"
#include "requiem-log.h"
#include "requiem-timer.h"
#include "variable.h"
#include "tls-auth.h"


int _requiem_internal_argc = 0;
char *_requiem_prefix = NULL;
char *_requiem_internal_argv[1024];

char _requiem_init_cwd[PATH_MAX];
static int librequiem_refcount = 0;
extern requiem_option_t *_requiem_generic_optlist;
extern gl_lock_t _criteria_parse_mutex;



static void tls_log_func(int level, const char *data)
{
        requiem_log(REQUIEM_LOG_INFO, "%s", data);
}

static int gcry_requiem_mutex_init(void **retval)
{
        int ret;
        gl_lock_t *lock;

        *retval = lock = malloc(sizeof(*lock));
        if ( ! lock )
                return ENOMEM;

        ret = glthread_lock_init(lock);
        if ( ret < 0 )
                free(lock);

        return ret;
}


static int gcry_requiem_mutex_destroy(void **lock)
{
        return glthread_lock_destroy(*lock);
}



static int gcry_requiem_mutex_lock(void **lock)
{
        return glthread_lock_lock((gl_lock_t *) *lock);
}


static int gcry_requiem_mutex_unlock(void **lock)
{
        return glthread_lock_unlock((gl_lock_t *) *lock);
}


static struct gcry_thread_cbs gcry_threads_requiem = {
        GCRY_THREAD_OPTION_USER,
        NULL,
        gcry_requiem_mutex_init,
        gcry_requiem_mutex_destroy,
        gcry_requiem_mutex_lock,
        gcry_requiem_mutex_unlock,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL
};


static void slice_arguments(int *argc, char **argv)
{
        int i;
        char *ptr;
        requiem_option_t *rootopt, *opt, *bkp = NULL;

        _requiem_client_register_options();

        _requiem_internal_argc = 0;
        _requiem_internal_argv[0] = NULL;

        if ( ! argc || ! argv || *argc < 1 )
                return;

        rootopt = _requiem_generic_optlist;
        _requiem_internal_argv[_requiem_internal_argc++] = argv[0];

        for ( i = 0; i < *argc && (size_t) _requiem_internal_argc + 1 < sizeof(_requiem_internal_argv) / sizeof(char *); i++ ) {

                ptr = argv[i];
                if ( *ptr != '-' )
                        continue;

                while ( *ptr == '-' ) ptr++;

                opt = requiem_option_search(rootopt, ptr, REQUIEM_OPTION_TYPE_CLI, FALSE);
                if ( ! opt ) {
                        if ( bkp )
                                rootopt = bkp;
                        continue;
                }

                if ( requiem_option_has_optlist(opt) ) {
                        rootopt = opt;
                        bkp = _requiem_generic_optlist;
                }

                _requiem_internal_argv[_requiem_internal_argc++] = argv[i];

                if ( (i + 1) == *argc )
                        break;

                if ( requiem_option_get_has_arg(opt) == REQUIEM_OPTION_ARGUMENT_NONE )
                        continue;

                if ( *argv[i + 1] == '-' )
                        continue;

                _requiem_internal_argv[_requiem_internal_argc++] = argv[i + 1];
        }
}


/**
 * requiem_init:
 * @argc: Address of the argc parameter of your main() function.
 * @argv: Address of the argv parameter of your main() function.
 *
 * Call this function before using any other Requiem functions in your applications.
 * It will initialize everything needed to operate the library and parses some standard
 * command line options. @argc and @argv are adjusted accordingly so your own code will
 * never see those standard arguments.
 *
 * Returns: 0 on success, a negative value if an error occured.
 */
int requiem_init(int *argc, char **argv)
{
        int ret;
        const char *env;

        if ( librequiem_refcount++ > 0 )
                return 0;

        env = getenv("LIBREQUIEM_DEBUG");
        if ( env )
                requiem_log_set_debug_level(atoi(env));

        env = getenv("LIBREQUIEM_TLS_DEBUG");
        if ( env ) {
                gnutls_global_set_log_level(atoi(env));
                gnutls_global_set_log_function(tls_log_func);
        }

        env = getenv("LIBREQUIEM_LOGFILE");
        if ( env )
                requiem_log_set_logfile(env);

        env = getenv("LIBREQUIEM_PREFIX");
        if ( env )
                _requiem_prefix = strdup(env);

        env = getenv("LIBREQUIEM_ABORT");
        if ( env ) {
                if ( *env )
                        _requiem_log_set_abort_level_from_string(env);
                else
                        _requiem_log_set_abort_level(REQUIEM_LOG_CRIT);
        }

        requiem_thread_init(NULL);

        if ( ! getcwd(_requiem_init_cwd, sizeof(_requiem_init_cwd)) )
                _requiem_init_cwd[0] = 0;

        ret = _requiem_timer_init();
        if ( ret < 0 )
                return ret;

        ret = glthread_atfork(requiem_fork_prepare, requiem_fork_parent, requiem_fork_child);
        if ( ret != 0 )
                return requiem_error_from_errno(ret);

        slice_arguments(argc, argv);

        ret = gcry_control(GCRYCTL_SET_THREAD_CBS, &gcry_threads_requiem);
        if ( ret < 0 )
                return requiem_error_verbose(REQUIEM_ERROR_TLS,
                                             "gcrypt initialization failed: %s", gcry_strerror(ret));

        ret = gnutls_global_init();
        if ( ret < 0 )
                return requiem_error_verbose(REQUIEM_ERROR_TLS,
                                             "TLS initialization failed: %s", gnutls_strerror(ret));

        return 0;
}



/**
 * requiem_deinit:
 *
 * Call this function if you're done using the library and want to free global
 * shared ressource allocated by librequiem.
 */
void requiem_deinit(void)
{
        requiem_list_t *iter = NULL;
        requiem_plugin_generic_t *plugin;

        if ( --librequiem_refcount != 0 )
                return;

        while ( (plugin = requiem_plugin_get_next(NULL, &iter)) )
                requiem_plugin_unload(plugin);

        _idmef_path_cache_destroy();
        requiem_option_destroy(NULL);
        variable_unset_all();

        tls_auth_deinit();
        gnutls_global_deinit();

        _requiem_thread_deinit();
}



/**
 * requiem_check_version:
 * @req_version: The minimum acceptable version number.
 *
 * If @req_version is NULL this function will return the version of the library.
 * Otherwise, @req_version will be compared to the current library version. If
 * the library version is higher or equal, this function will return the current
 * library version. Otherwise, NULL is returned.
 *
 * Returns: The current library version, or NULL if @req_version doesn't match.
 */
const char *requiem_check_version(const char *req_version)
{
        int ret;
        int major, minor, micro, patch = 0;
        int rq_major, rq_minor, rq_micro, rq_patch = 0;

        if ( ! req_version )
                return VERSION;

        ret = sscanf(VERSION, "%d.%d.%d.%d", &major, &minor, &micro, &patch);
        if ( ret < 3 )
                return NULL;

        ret = sscanf(req_version, "%d.%d.%d.%d", &rq_major, &rq_minor, &rq_micro, &rq_patch);
        if ( ret < 3 )
                return NULL;

        if ( major > rq_major
             || (major == rq_major && minor > rq_minor)
             || (major == rq_major && minor == rq_minor && micro > rq_micro)
             || (major == rq_major && minor == rq_minor && micro == rq_micro && patch >= rq_patch) ) {
                return VERSION;
        }

        return NULL;
}



void requiem_fork_prepare(void)
{
#ifdef HAVE_PTHREAD_ATFORK
        return;
#endif

        _requiem_async_fork_prepare();
        _requiem_timer_fork_prepare();

        _idmef_path_cache_lock();
        gl_lock_lock(_criteria_parse_mutex);
}


void requiem_fork_parent(void)
{
#ifdef HAVE_PTHREAD_ATFORK
        return;
#endif

        _requiem_async_fork_parent();
        _requiem_timer_fork_parent();

        _idmef_path_cache_unlock();
        gl_lock_unlock(_criteria_parse_mutex);
}


void requiem_fork_child(void)
{
#ifdef HAVE_PTHREAD_ATFORK
        return;
#endif

        _requiem_async_fork_child();
        _requiem_timer_fork_child();

        _idmef_path_cache_reinit();
        gl_lock_init(_criteria_parse_mutex);
}
