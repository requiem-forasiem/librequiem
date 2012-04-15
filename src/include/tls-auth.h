/*****
*
* Copyright (C) 2004,2005 PreludeIDS Technologies. All Rights Reserved.
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

#ifndef _LIBREQUIEM_TLS_AUTH_H
#define _LIBREQUIEM_TLS_AUTH_H

#include "requiem-io.h"
#include "requiem-connection.h"


int tls_auth_connection(requiem_client_profile_t *cp, requiem_io_t *io, int crypt,
                        uint64_t *peer_analyzerid, requiem_connection_permission_t *permission);

int tls_auth_init(requiem_client_profile_t *cp, gnutls_certificate_credentials *cred);

int tls_auth_init_priority(const char *tlsopts);

void tls_auth_deinit(void);

#endif
