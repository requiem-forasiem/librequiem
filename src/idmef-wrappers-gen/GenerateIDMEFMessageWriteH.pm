# Copyright (C) 2003, 2004, 2005 PreludeIDS Technologies. All Rights Reserved.
# Author: Nicolas Delon 
#
# This file is part of the Requiem library.
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2, or (at your option)
# any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; see the file COPYING.  If not, write to
# the Free Software Foundation, 675 Mass Ave, Cambridge, MA 02139, USA.

package GenerateIDMEFMessageWriteH;

use Generate;
@ISA = qw/Generate/;

use strict;
use IDMEFTree;

sub     header
{
     my $self = shift;

     $self->output("
/*****
*
* Copyright (C) 2001, 2002, 2003, 2004, 2005 PreludeIDS Technologies. All Rights Reserved.
* Author: Yoann Vandoorselaere <yoannv\@gmail.com>
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

/* Auto-generated by the GenerateIDMEFMessageWriteH package */

#ifndef _LIBREQUIEM_IDMEF_MESSAGE_WRITE_H
#define _LIBREQUIEM_IDMEF_MESSAGE_WRITE_H

#include \"requiem-inttypes.h\"
#include \"idmef-time.h\"
#include \"requiem-string.h\"
#include \"requiem-msgbuf.h\"

#ifdef __cplusplus
 extern \"C\" {
#endif

");
}

sub     footer
{
    my  $self = shift;

    $self->output("

#ifdef __cplusplus
 }
#endif

#endif /* _LIBREQUIEM_IDMEF_MESSAGE_WRITE_H */
");
}

sub     struct
{
    my  $self = shift;
    my  $tree = shift;
    my  $struct = shift;

    $self->output("int idmef_$struct->{short_typename}_write($struct->{typename} *$struct->{short_typename}, requiem_msgbuf_t *msg);\n");
}

1;
