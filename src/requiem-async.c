/*****
*
* Copyright (C) 2001-2005,2006,2007 PreludeIDS Technologies. All Rights Reserved.
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
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <assert.h>

#if TIME_WITH_SYS_TIME
# include <sys/time.h>
# include <time.h>
#else
# if HAVE_SYS_TIME_H
#  include <sys/time.h>
# else
#  include <time.h>
# endif
#endif

#include "glthread/thread.h"
#include "glthread/lock.h"
#include "glthread/cond.h"

#include "requiem-list.h"
#include "requiem-inttypes.h"
#include "requiem-linked-object.h"
#include "requiem-timer.h"
#include "requiem-log.h"
#include "requiem-io.h"
#include "requiem-async.h"


static REQUIEM_LIST(joblist);

static requiem_async_flags_t async_flags = 0;
static requiem_bool_t stop_processing = FALSE;


static gl_thread_t thread;
static gl_cond_t cond = gl_cond_initializer;
static gl_lock_t mutex = gl_lock_initializer;

static volatile sig_atomic_t is_initialized = FALSE;



static int timespec_elapsed(struct timespec *end, struct timespec *start)
{
        int diff = end->tv_sec - start->tv_sec;

        if ( end->tv_nsec < start->tv_nsec )
                diff -= 1;

        return diff;
}


static requiem_bool_t timespec_expired(struct timespec *end, struct timespec *start)
{
        return ( timespec_elapsed(end, start) ) ? TRUE : FALSE;
}


static inline struct timespec *get_timespec(struct timespec *ts)
{
        struct timeval now;

        gettimeofday(&now, NULL);

        ts->tv_sec = now.tv_sec;
        ts->tv_nsec = now.tv_usec * 1000;

        return ts;
}



static int wait_timer_and_data(requiem_async_flags_t *flags)
{
        int ret;
        struct timespec ts;
        static struct timespec last_wakeup;
        requiem_bool_t no_job_available = TRUE;

        get_timespec(&last_wakeup);
        last_wakeup.tv_sec--;

        while ( no_job_available ) {
                ret = 0;

                gl_lock_lock(mutex);

                ts.tv_sec = last_wakeup.tv_sec + 1;
                ts.tv_nsec = last_wakeup.tv_nsec;

                while ( (no_job_available = requiem_list_is_empty(&joblist)) &&
                        ! stop_processing && async_flags == *flags && ret != ETIMEDOUT ) {
                        ret = glthread_cond_timedwait(&cond, &mutex, &ts);
                }

                if ( no_job_available && stop_processing ) {
                        gl_lock_unlock(mutex);
                        return -1;
                }

                *flags = async_flags;
                gl_lock_unlock(mutex);

                if ( ret == ETIMEDOUT || timespec_expired(get_timespec(&ts), &last_wakeup) ) {
                        requiem_timer_wake_up();
                        last_wakeup.tv_sec = ts.tv_sec;
                        last_wakeup.tv_nsec = ts.tv_nsec;
                }
        }

        return 0;
}




static int wait_data(requiem_async_flags_t *flags)
{
        gl_lock_lock(mutex);

        while ( requiem_list_is_empty(&joblist) && ! stop_processing && async_flags == *flags )
                gl_cond_wait(cond, mutex);

        if ( requiem_list_is_empty(&joblist) && stop_processing ) {
                gl_lock_unlock(mutex);
                return -1;
        }

        *flags = async_flags;
        gl_lock_unlock(mutex);

        return 0;
}



static requiem_async_object_t *get_next_job(void)
{
        requiem_list_t *tmp;
        requiem_async_object_t *obj = NULL;

        gl_lock_lock(mutex);

        requiem_list_for_each(&joblist, tmp) {
                obj = requiem_linked_object_get_object(tmp);
                requiem_linked_object_del((requiem_linked_object_t *) obj);
                break;
        }

        gl_lock_unlock(mutex);

        return obj;
}



static void *async_thread(void *arg)
{
        int ret;
        sigset_t set;
        requiem_async_object_t *obj;
        requiem_async_flags_t nflags = async_flags;

        ret = sigfillset(&set);
        if ( ret < 0 ) {
                requiem_log(REQUIEM_LOG_ERR, "sigfillset error: %s.\n", strerror(errno));
                return NULL;
        }

        ret = glthread_sigmask(SIG_BLOCK, &set, NULL);
        if ( ret < 0 ) {
                requiem_log(REQUIEM_LOG_ERR, "pthread_sigmask error: %s.\n", strerror(errno));
                return NULL;
        }

        while ( 1 ) {

                if ( nflags & REQUIEM_ASYNC_FLAGS_TIMER )
                        ret = wait_timer_and_data(&nflags);
                else
                        ret = wait_data(&nflags);

                if ( ret < 0 ) {
                        /*
                         * On some implementation (namely, recent Linux + glibc version),
                         * calling pthread_exit() from a shared library and joining the thread from
                         * an atexit callback result in a deadlock.
                         *
                         * Appear to be related to:
                         * http://sources.redhat.com/bugzilla/show_bug.cgi?id=654
                         *
                         * Simply returning from the thread seems to fix this problem.
                         */
                        break;
                }

                while ( (obj = get_next_job()) )
                        obj->_async_func(obj, obj->_async_data);
        }

        return NULL;
}



static int do_init_async(void)
{
        int ret;

        ret = glthread_create(&thread, async_thread, NULL);
        if ( ret != 0 ) {
                requiem_log(REQUIEM_LOG_ERR, "error creating asynchronous thread: %s.\n", strerror(ret));
                return ret;
        }

        /*
         * There is a problem with OpenBSD, where using atexit() from a multithread
         * application result in a deadlock. No workaround has been found at the moment.
         *
         */
#if ! defined(__OpenBSD__)
        return atexit(requiem_async_exit);
#else
        return 0;
#endif
}



/**
 * requiem_async_set_flags:
 * @flags: flags you want to set
 *
 * Sets flags to the asynchronous subsystem.
 *
 */
void requiem_async_set_flags(requiem_async_flags_t flags)
{
        gl_lock_lock(mutex);

        async_flags = flags;
        gl_cond_signal(cond);

        gl_lock_unlock(mutex);
}



/**
 * requiem_async_get_flags:
 *
 * Retrieves flags from the asynchronous subsystem
 *
 * Returns: asynchronous flags
 */
requiem_async_flags_t requiem_async_get_flags(void)
{
        return async_flags;
}



/**
 * requiem_async_init:
 *
 * Initialize the asynchronous subsystem.
 *
 * Returns: 0 on success, -1 if an error occured.
 */
int requiem_async_init(void)
{
        if ( ! is_initialized ) {
                is_initialized = TRUE;
                stop_processing = FALSE;

                return do_init_async();
        }

        return 0;
}



/**
 * requiem_async_add:
 * @obj: Pointer to a #requiem_async_t object.
 *
 * Adds @obj to the asynchronous processing list.
 */
void requiem_async_add(requiem_async_object_t *obj)
{
        gl_lock_lock(mutex);

        requiem_linked_object_add_tail(&joblist, (requiem_linked_object_t *) obj);
        gl_cond_signal(cond);

        gl_lock_unlock(mutex);
}



/**
 * requiem_async_del:
 * @obj: Pointer to a #requiem_async_t object.
 *
 * Deletes @obj from the asynchronous processing list.
 */
void requiem_async_del(requiem_async_object_t *obj)
{
        gl_lock_lock(mutex);
        requiem_linked_object_del((requiem_linked_object_t *) obj);
        gl_lock_unlock(mutex);
}



void requiem_async_exit(void)
{
        requiem_bool_t has_job;

        if ( ! is_initialized )
                return;

        gl_lock_lock(mutex);

        stop_processing = TRUE;
        gl_cond_signal(cond);
        has_job = ! requiem_list_is_empty(&joblist);

        gl_lock_unlock(mutex);

        if ( has_job )
                requiem_log(REQUIEM_LOG_INFO, "Waiting for asynchronous operation to complete.\n");

        gl_thread_join(thread, NULL);
        gl_cond_destroy(cond);
        gl_lock_destroy(mutex);

        is_initialized = FALSE;
}



void _requiem_async_fork_prepare(void)
{
        gl_lock_lock(mutex);
}



void _requiem_async_fork_parent(void)
{
        gl_lock_unlock(mutex);
}



void _requiem_async_fork_child(void)
{
        is_initialized = FALSE;
        requiem_list_init(&joblist);
        gl_lock_init(mutex);
        gl_cond_init(cond);
}
