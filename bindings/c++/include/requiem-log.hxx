/*****
*
* Copyright (C) 2009 PreludeIDS Technologies. All Rights Reserved.
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

#ifndef _LIBREQUIEM_REQUIEM_LOG_HXX
#define _LIBREQUIEM_REQUIEM_LOG_HXX

#include "requiem.h"
#include "idmef-path.h"

#if (defined _WIN32 || defined __WIN32__) && !defined __CYGWIN__
# undef ERROR
#endif

namespace Requiem {
        class RequiemLog {
            public:
                enum LogLevelEnum {
                        DEBUG    = REQUIEM_LOG_DEBUG,
                        INFO     = REQUIEM_LOG_INFO,
                        WARNING  = REQUIEM_LOG_WARN,
                        ERROR    = REQUIEM_LOG_ERR,
                        CRITICAL = REQUIEM_LOG_CRIT
                };

                enum LogFlagsEnum {
                        QUIET    = REQUIEM_LOG_FLAGS_QUIET,
                        SYSLOG   = REQUIEM_LOG_FLAGS_SYSLOG
                };

                static void SetLevel(int level);
                static void SetDebugLevel(int level);
                static void SetFlags(int flags);
                static int GetFlags(void);
                static void SetLogfile(const char *filename);
                static void SetCallback(void (*log_cb)(int level, const char *log));
        };
};

#endif
