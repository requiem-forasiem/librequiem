/* strsource.c - Describing an error source.
   Copyright (C) 2003 g10 Code GmbH

   This file is part of libgpg-error.
 
   libgpg-error is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public License
   as published by the Free Software Foundation; either version 2.1 of
   the License, or (at your option) any later version.
 
   libgpg-error is distributed in the hope that it will be useful, but
   WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.
 
   You should have received a copy of the GNU Lesser General Public
   License along with libgpg-error; if not, write to the Free
   Software Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
   02111-1307, USA.  */


#include "config.h"

#include "requiem-error.h"
#include "gettext.h"
#include "err-sources.h"

/* Return a pointer to a string containing a description of the error
   source in the error value ERR.  */
const char *requiem_strsource(requiem_error_t err)
{
        requiem_error_source_t source = requiem_error_get_source(err);
        return dgettext(PACKAGE, msgstr + msgidx[msgidxof((int) source)]);
}
