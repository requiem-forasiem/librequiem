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

#ifndef _LIBREQUIEM_REQUIEM_CONNECTION_POOL_HXX
#define _LIBREQUIEM_REQUIEM_CONNECTION_POOL_HXX

#include "requiem.h"
#include "requiem-client-profile.hxx"
#include "requiem-connection.hxx"

namespace Requiem {
        class ConnectionPool {
            private:
                requiem_connection_pool_t *_pool;

            public:
                ~ConnectionPool();
                ConnectionPool();
                ConnectionPool(requiem_connection_pool_t *pool);
                ConnectionPool(const ConnectionPool &pool);
                ConnectionPool(Requiem::ClientProfile &cp, int permission);

                void Init();

                void SetConnectionString(const char *str);
                const char *GetConnectionString();
                std::vector<Requiem::Connection> GetConnectionList();

                void SetFlags(int flags);
                int GetFlags();

                void SetData(void *data);
                void *GetData();

                void AddConnection(Requiem::Connection con);
                void DelConnection(Requiem::Connection con);

                void SetConnectionAlive(Requiem::Connection &con);
                void SetConnectionDead(Requiem::Connection &con);

                void SetRequiredPermission(int permission);
                ConnectionPool &operator=(const ConnectionPool &pool);
                operator requiem_connection_pool_t *();
        };
};

#endif /* __REQUIEM_CONNECTION_POOL__ */
