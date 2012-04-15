/*****
*
* Copyright (C) 2008 PreludeIDS Technologies. All Rights Reserved.
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

#include <list>

#include "requiem.h"
#include "requiem-connection-pool.h"

#include "requiem-connection-pool.hxx"
#include "requiem-client.hxx"
#include "requiem-error.hxx"

using namespace Requiem;


Connection::~Connection()
{
        if ( _con )
                requiem_connection_destroy(_con);
}


Connection::Connection()
{
        _con = NULL;
}


Connection::Connection(const Connection &con)
{
        _con = (con._con) ? requiem_connection_ref(con._con) : NULL;
}


Connection::Connection(const char *addr)
{
        int ret;

        ret = requiem_connection_new(&_con, addr);
        if ( ret < 0 )
                throw RequiemError(ret);
}


Connection::Connection(requiem_connection_t *con, bool own_data)
{
        _con = con;
}


requiem_connection_t *Connection::GetConnection()
{
        return _con;
}


void Connection::Close()
{
        requiem_connection_close(_con);
}


void Connection::Connect(ClientProfile &cp, int permission)
{
        int ret;

        ret = requiem_connection_connect(_con, cp, (requiem_connection_permission_t) permission);
        if ( ret < 0 )
                throw RequiemError(ret);
}


void Connection::SetState(int state)
{
        requiem_connection_set_state(_con, (requiem_connection_state_t) state);
}


int Connection::GetState()
{
        return requiem_connection_get_state(_con);
}


void Connection::SetData(void *data)
{
        requiem_connection_set_data(_con, data);
}


void *Connection::GetData()
{
        return requiem_connection_get_data(_con);
}


int Connection::GetPermission()
{
        return requiem_connection_get_permission(_con);
}


void Connection::SetPeerAnalyzerid(uint64_t analyzerid)
{
        requiem_connection_set_peer_analyzerid(_con, analyzerid);
}


uint64_t Connection::GetPeerAnalyzerid()
{
        return requiem_connection_get_peer_analyzerid(_con);
}


const char *Connection::GetLocalAddr()
{
        return requiem_connection_get_local_addr(_con);
}


unsigned int Connection::GetLocalPort()
{
        return requiem_connection_get_local_port(_con);
}


const char *Connection::GetPeerAddr()
{
        return requiem_connection_get_peer_addr(_con);
}


unsigned int Connection::GetPeerPort()
{
        return requiem_connection_get_peer_port(_con);
}


int Connection::GetFd()
{
        return requiem_io_get_fd(requiem_connection_get_fd(_con));
}


Requiem::IDMEF Connection::RecvIDMEF()
{
        int ret;
        idmef_message_t *idmef;

        ret = requiem_connection_recv_idmef(_con, &idmef);
        if ( ret < 0 )
                throw RequiemError(ret);

        return IDMEF(idmef);
}


bool Connection::IsAlive()
{
        return requiem_connection_is_alive(_con);
}

Connection &Connection::operator=(const Connection &con)
{
        if ( this != &con && _con != con._con ) {
                if ( _con )
                        requiem_connection_destroy(_con);

                _con = (con._con) ? requiem_connection_ref(con._con) : NULL;
        }

        return *this;
}


Connection::operator requiem_connection_t *()
{
        return _con;
}
