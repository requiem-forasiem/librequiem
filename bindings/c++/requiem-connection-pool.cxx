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

#include <vector>

#include "requiem.h"
#include "requiem-connection-pool.h"

#include "requiem-connection-pool.hxx"
#include "requiem-client.hxx"
#include "requiem-error.hxx"

using namespace Requiem;


ConnectionPool::~ConnectionPool()
{
        if ( _pool )
                requiem_connection_pool_destroy(_pool);
}


ConnectionPool::ConnectionPool()
{
        _pool = NULL;
}


ConnectionPool::ConnectionPool(requiem_connection_pool_t *pool)
{
        _pool = pool;
}


ConnectionPool::ConnectionPool(const ConnectionPool &con)
{
        _pool = (con._pool) ? requiem_connection_pool_ref(con._pool) : NULL;
}


ConnectionPool::ConnectionPool(ClientProfile &cp, int permission)
{
        int ret;

        ret = requiem_connection_pool_new(&_pool, cp, (requiem_connection_permission_t) permission);
        if ( ret < 0 )
                throw RequiemError(ret);
}



void ConnectionPool::Init()
{
        int ret;

        ret = requiem_connection_pool_init(_pool);
        if ( ret < 0 )
                throw RequiemError(ret);
}


std::vector<Requiem::Connection> ConnectionPool::GetConnectionList()
{
        std::vector<Requiem::Connection> clist;
        requiem_connection_t *con;
        requiem_list_t *head, *tmp;

        head = requiem_connection_pool_get_connection_list(_pool);

        requiem_list_for_each(head, tmp) {
                con = (requiem_connection_t *) requiem_linked_object_get_object(tmp);
                clist.push_back(Connection(requiem_connection_ref(con)));
        }

        return clist;
}


void ConnectionPool::AddConnection(Connection con)
{
        requiem_connection_pool_add_connection(_pool, requiem_connection_ref(con));
}


void ConnectionPool::DelConnection(Connection con)
{
        requiem_connection_pool_del_connection(_pool, con);
}


void ConnectionPool::SetConnectionDead(Connection &con)
{
        requiem_connection_pool_set_connection_dead(_pool, con);
}


void ConnectionPool::SetConnectionAlive(Connection &con)
{
        requiem_connection_pool_set_connection_alive(_pool, con);
}


void ConnectionPool::SetConnectionString(const char *str)
{
        int ret;

        ret = requiem_connection_pool_set_connection_string(_pool, str);
        if ( ret < 0 )
                throw RequiemError(ret);
}


const char *ConnectionPool::GetConnectionString()
{
        return requiem_connection_pool_get_connection_string(_pool);
}


int ConnectionPool::GetFlags()
{
        return requiem_connection_pool_get_flags(_pool);
}


void ConnectionPool::SetFlags(int flags)
{
        requiem_connection_pool_set_flags(_pool, (requiem_connection_pool_flags_t) flags);
}


void ConnectionPool::SetRequiredPermission(int permission)
{
        requiem_connection_pool_set_required_permission(_pool, (requiem_connection_permission_t) permission);
}


void ConnectionPool::SetData(void *data)
{
        requiem_connection_pool_set_data(_pool, data);
}


void *ConnectionPool::GetData()
{
        return requiem_connection_pool_get_data(_pool);
}


ConnectionPool &ConnectionPool::operator=(const ConnectionPool &pool)
{
        if ( this != &pool && _pool != pool._pool ) {
                if ( _pool )
                        requiem_connection_pool_destroy(_pool);

                _pool = (pool._pool) ? requiem_connection_pool_ref(pool._pool) : NULL;
        }

        return *this;
}


ConnectionPool::operator requiem_connection_pool_t *()
{
        return _pool;
}
