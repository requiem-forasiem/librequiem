/*****
*
* Copyright (C) 2004, 2005 PreludeIDS Technologies. All Rights Reserved.
* Author: Yoann Vandoorselaere <yoannv@gmail.com>
*
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

#ifndef _LIBREQUIEM_CLIENT_PROFILE_H
#define _LIBREQUIEM_CLIENT_PROFILE_H

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <unistd.h>
#include <sys/types.h>

#include "requiem-config.h"
#include "requiem-inttypes.h"

#ifdef __cplusplus
 extern "C" {
#endif


#ifdef HAVE_UID_T
typedef uid_t requiem_uid_t;
#else
typedef int requiem_uid_t;
#endif

#ifdef HAVE_GID_T
typedef gid_t requiem_gid_t;
#else
typedef int requiem_gid_t;
#endif


typedef struct requiem_client_profile requiem_client_profile_t;

int _requiem_client_profile_init(requiem_client_profile_t *cp);

int _requiem_client_profile_new(requiem_client_profile_t **ret);

int requiem_client_profile_new(requiem_client_profile_t **ret, const char *name);

requiem_client_profile_t *requiem_client_profile_ref(requiem_client_profile_t *cp);

void requiem_client_profile_destroy(requiem_client_profile_t *cp);

void requiem_client_profile_get_config_filename(const requiem_client_profile_t *cp, char *buf, size_t size);

void requiem_client_profile_get_default_config_dirname(const requiem_client_profile_t *cp, char *buf, size_t size);

void requiem_client_profile_get_analyzerid_filename(const requiem_client_profile_t *cp, char *buf, size_t size);

void requiem_client_profile_get_tls_key_filename(const requiem_client_profile_t *cp, char *buf, size_t size);

void requiem_client_profile_get_tls_server_ca_cert_filename(const requiem_client_profile_t *cp, char *buf, size_t size);

void requiem_client_profile_get_tls_server_keycert_filename(const requiem_client_profile_t *cp, char *buf, size_t size);

void requiem_client_profile_get_tls_server_crl_filename(const requiem_client_profile_t *cp, char *buf, size_t size);

void requiem_client_profile_get_tls_client_keycert_filename(const requiem_client_profile_t *cp, char *buf, size_t size);

void requiem_client_profile_get_tls_client_trusted_cert_filename(const requiem_client_profile_t *cp, char *buf, size_t size);

void requiem_client_profile_get_backup_dirname(const requiem_client_profile_t *cp, char *buf, size_t size);

void requiem_client_profile_get_profile_dirname(const requiem_client_profile_t *cp, char *buf, size_t size);

void requiem_client_profile_set_uid(requiem_client_profile_t *cp, requiem_uid_t uid);

requiem_uid_t requiem_client_profile_get_uid(const requiem_client_profile_t *cp);

void requiem_client_profile_set_gid(requiem_client_profile_t *cp, requiem_uid_t gid);

requiem_gid_t requiem_client_profile_get_gid(const requiem_client_profile_t *cp);

int requiem_client_profile_set_name(requiem_client_profile_t *cp, const char *name);

const char *requiem_client_profile_get_name(const requiem_client_profile_t *cp);

uint64_t requiem_client_profile_get_analyzerid(const requiem_client_profile_t *cp);

void requiem_client_profile_set_analyzerid(requiem_client_profile_t *cp, uint64_t analyzerid);

int requiem_client_profile_get_credentials(requiem_client_profile_t *cp, void **credentials);

int requiem_client_profile_set_prefix(requiem_client_profile_t *cp, const char *prefix);

void requiem_client_profile_get_prefix(const requiem_client_profile_t *cp, char *buf, size_t size);

#ifdef __cplusplus
 }
#endif

#endif
