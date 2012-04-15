/*****
*
* Copyright (C) 2002, 2003, 2004, 2005 PreludeIDS Technologies. All Rights Reserved.
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

#ifndef _LIBREQUIEM_COMMON_H
#define _LIBREQUIEM_COMMON_H

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include "idmef.h"
#include "requiem-msg.h"
#include "requiem-inttypes.h"
#include "requiem-log.h"
#include <sys/types.h>

#ifdef WIN32
# include <winsock2.h>
#else
# include <sys/socket.h>
# include <netinet/in.h>
#endif

#include <time.h>

#ifdef __cplusplus
 extern "C" {
#endif

#define requiem_return_val_if_fail(cond, val) do {                               \
        if ( ! (cond) ) {                                                        \
                requiem_log(REQUIEM_LOG_CRIT, "assertion '%s' failed\n", #cond); \
                return val;                                                      \
        }                                                                        \
} while(0)


#define requiem_return_if_fail(cond) do {                                        \
        if ( ! (cond) ) {                                                        \
                requiem_log(REQUIEM_LOG_CRIT, "assertion '%s' failed\n", #cond); \
                return;                                                          \
        }                                                                        \
} while(0)


int requiem_parse_address(const char *str, char **addr, unsigned int *port);

uint64_t requiem_hton64(uint64_t val);

uint32_t requiem_htonf(float fval);

time_t requiem_timegm(struct tm *tm);

int requiem_get_gmt_offset(long *gmt_offset);

int requiem_get_gmt_offset_from_tm(struct tm *tm, long *gmtoff);

int requiem_get_gmt_offset_from_time(const time_t *utc, long *gmtoff);

int requiem_read_multiline(FILE *fd, unsigned int *line, char *buf, size_t size);

int requiem_read_multiline2(FILE *fd, unsigned int *line, requiem_string_t *out);

void *requiem_sockaddr_get_inaddr(struct sockaddr *sa);

void *_requiem_realloc(void *ptr, size_t size);

int _requiem_get_file_name_and_path(const char *str, char **name, char **path);

requiem_msg_priority_t _idmef_impact_severity_to_msg_priority(idmef_impact_severity_t severity);

int _idmef_message_assign_missing(requiem_client_t *client, idmef_message_t *msg);

int _requiem_load_file(const char *filename, unsigned char **fdata, size_t *outsize);

void _requiem_unload_file(unsigned char *fdata, size_t size);

#ifdef __cplusplus
 }
#endif

#endif /* _LIBREQUIEM_COMMON_H */
