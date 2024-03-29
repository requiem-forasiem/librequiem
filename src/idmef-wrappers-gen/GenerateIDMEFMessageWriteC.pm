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

package GenerateIDMEFMessageWriteC;

use Generate;
@ISA = qw/Generate/;

use strict;
use IDMEFTree;

sub        header
{
     my        $self = shift;

     $self->output("
/*****
*
* Copyright (C) 2001,2002,2003,2004,2005 PreludeIDS Technologies. All Rights Reserved.
* Author: Yoann Vandoorselaere <yoannv\@gmail.com>
* Author: Nicolas Delon 
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

/* Auto-generated by the GenerateIDMEFMessageWriteC package */

#include \"config.h\"

#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include \"requiem-inttypes.h\"
#include \"requiem-list.h\"
#include \"requiem-log.h\"
#include \"requiem-io.h\"
#include \"requiem-ident.h\"
#include \"requiem-message-id.h\"
#include \"idmef-message-id.h\"
#include \"idmef.h\"
#include \"idmef-tree-wrap.h\"
#include \"idmef-message-write.h\"
#include \"requiem-client.h\"
#include \"common.h\"



/*
 * If you wonder why we do this, and why life is complicated,
 * then wonder why the hell the guys that wrote IDMEF choose to use XML.
 * XML is dog slow. And XML'll never achieve performance needed for real time IDS.
 *
 * Here we are trying to communicate using a home made, binary version of IDMEF.
 */


static inline int requiem_string_write(requiem_string_t *string, requiem_msgbuf_t *msg, uint8_t tag)
\{
        if ( ! string || requiem_string_is_empty(string) )
                return 0;

        return requiem_msgbuf_set(msg, tag, requiem_string_get_len(string) + 1, requiem_string_get_string(string));
\}



static inline int uint64_write(uint64_t data, requiem_msgbuf_t *msg, uint8_t tag)
\{
        uint64_t dst;

        dst = requiem_hton64(data);

        return requiem_msgbuf_set(msg, tag, sizeof(dst), &dst);
\}



static inline int uint32_write(uint32_t data, requiem_msgbuf_t *msg, uint8_t tag)
\{
        data = htonl(data);
        return requiem_msgbuf_set(msg, tag, sizeof(data), &data);
\}



static inline int int32_write(uint32_t data, requiem_msgbuf_t *msg, uint8_t tag)
\{
        return uint32_write(data, msg, tag);
\}



static inline int uint8_write(uint8_t data, requiem_msgbuf_t *msg, uint8_t tag)
\{
        return requiem_msgbuf_set(msg, tag, sizeof (data), &data);
\}



static inline int uint16_write(uint16_t data, requiem_msgbuf_t *msg, uint8_t tag)
\{
        data = htons(data);
        return requiem_msgbuf_set(msg, tag, sizeof(data), &data);
\}



static inline int float_write(float data, requiem_msgbuf_t *msg, uint8_t tag)
\{
        uint32_t tmp = requiem_htonf(data);
        return requiem_msgbuf_set(msg, tag, sizeof(tmp), &tmp);
\}


static inline int idmef_time_write(idmef_time_t *data, requiem_msgbuf_t *msg, uint8_t tag)
\{
        uint32_t tmp;
        unsigned char buf[12];

        if ( ! data )
                return 0;

        tmp = htonl(idmef_time_get_sec(data));
        memcpy(buf, &tmp, sizeof(tmp));

        tmp = htonl(idmef_time_get_usec(data));
        memcpy(buf + 4, &tmp, sizeof(tmp));

        tmp = htonl(idmef_time_get_gmt_offset(data));
        memcpy(buf + 8, &tmp, sizeof(tmp));

        return requiem_msgbuf_set(msg, tag, sizeof (buf), buf);
\}



static inline int idmef_data_write(idmef_data_t *data, requiem_msgbuf_t *msg, uint8_t tag)
\{
        int ret;
        idmef_data_type_t type;

        if ( ! data )
                return 0;

        type = idmef_data_get_type(data);
        if ( type == IDMEF_DATA_TYPE_UNKNOWN )
                return 0;

        ret = uint32_write(idmef_data_get_type(data), msg, tag);
        if ( ret < 0 )
                return ret;

        switch ( type ) \{
        case IDMEF_DATA_TYPE_CHAR:
        case IDMEF_DATA_TYPE_BYTE:
                ret = uint8_write(* (const uint8_t *) idmef_data_get_data(data), msg, tag);
                break;

        case IDMEF_DATA_TYPE_UINT32:
                ret = uint32_write(idmef_data_get_uint32(data), msg, tag);
                break;

        case IDMEF_DATA_TYPE_UINT64:
                ret = uint64_write(idmef_data_get_uint64(data), msg, tag);
                break;

        case IDMEF_DATA_TYPE_FLOAT:
                ret = float_write(idmef_data_get_uint64(data), msg, tag);
                break;

        case IDMEF_DATA_TYPE_CHAR_STRING: case IDMEF_DATA_TYPE_BYTE_STRING:
                ret = requiem_msgbuf_set(msg, tag, idmef_data_get_len(data), idmef_data_get_data(data));
                break;

        case IDMEF_DATA_TYPE_UNKNOWN:
                /* nop */;
        \}

        return ret;
\}

");
}

sub        struct_field_normal
{
    my        $self = shift;
    my        $tree = shift;
    my        $struct = shift;
    my        $field = shift;
    my        $type = shift || $field->{short_typename};
    my        $function;

    $function = "${type}_write";

    if ( $field->{metatype} & &METATYPE_OPTIONAL_INT ) {
        $self->output("
        {
                $field->{typename} *tmp;

                tmp = idmef_$struct->{short_typename}_get_$field->{name}($struct->{short_typename});
                if ( tmp ) \{
                        ret = $function(*tmp, msg, IDMEF_MSG_",  uc($struct->{short_typename}), "_", uc($field->{name}), ");
                        if ( ret < 0 )
                                return ret;");

        if ( $field->{typename} eq "idmef_impact_severity_t" ) {
            $self->output("
                        requiem_msg_set_priority(requiem_msgbuf_get_msg(msg),
                                                 _idmef_impact_severity_to_msg_priority(*tmp));");
        }

        $self->output("
                \}
        \}\n");
    } else {
        $self->output(" " x 8,
                      "ret = $function(idmef_$struct->{short_typename}_get_$field->{name}($struct->{short_typename}), ",
                      "msg, IDMEF_MSG_",  uc($struct->{short_typename}), "_", uc($field->{name}),
                      ");\n",
                      " " x 8, "if ( ret < 0 )\n",
                      " " x 16, "return ret;\n\n");

    }
}

sub        struct_field_struct
{
    my        $self = shift;
    my        $tree = shift;
    my        $struct = shift;
    my        $field = shift;

    $self->output(" " x 8,
                  "ret = idmef_$field->{short_typename}_write(idmef_$struct->{short_typename}_get_$field->{name}($struct->{short_typename}), msg);\n",
                  " " x 8, "if ( ret < 0 )\n", " " x 16, "return ret;\n");
}

sub        struct_field_list
{
    my        $self = shift;
    my        $tree = shift;
    my        $struct = shift;
    my        $field = shift;

    $self->output("\n");
    $self->output(" " x 8, "{\n");
    $self->output(" " x 16, "$field->{typename} *$field->{short_name} = NULL;", "\n\n");
    $self->output(" " x 16, "while ( ($field->{short_name} = idmef_$struct->{short_typename}_get_next_$field->{short_name}($struct->{short_typename}, $field->{short_name})) ) {", "\n");

    if ( $field->{metatype} & &METATYPE_PRIMITIVE ) {
        $self->output(" " x 24,
                      "ret = $field->{short_typename}_write($field->{short_name}, msg, ",
                      "IDMEF_MSG_", uc($struct->{short_typename}), "_", uc($field->{short_name}), ");\n",
                      " " x 24, "if ( ret < 0 )\n", " " x 32, "return ret;\n");

    } else {
        $self->output(" " x 24, "ret = idmef_$field->{short_typename}_write($field->{short_name}, msg);\n",
                      " " x 24, "if ( ret < 0 )\n", " " x 32, "return ret;\n");
    }

    $self->output(" " x 16, "}\n");
    $self->output(" " x 8, "}\n");
    $self->output("\n");
}

sub        struct_field_union
{
    my        $self = shift;
    my        $tree = shift;
    my        $struct = shift;
    my        $field = shift;

    $self->output("\n");
    $self->output(" " x 8, "switch ( idmef_$struct->{short_typename}_get_$field->{var}($struct->{short_typename}) ) {", "\n\n");

    foreach my $member ( @{$field->{member_list}} ) {
        $self->output(" " x 16, "case $member->{value}:", "\n");
        $self->output(" " x 24, "ret = idmef_$member->{short_typename}_write(idmef_$struct->{short_typename}_get_$member->{name}($struct->{short_typename}), msg);", "\n");
        $self->output(" " x 24, "break;", "\n\n");
    }

    $self->output(" " x 16, "default:", "\n",
                  " " x 24, "/* nop */;", "\n\n");
    $self->output(" " x 8, "}\n");
}

sub        pre_declared
{
    my        $self = shift;
    my        $tree = shift;
    my        $struct = shift;

    $self->output("int idmef_$struct->{short_typename}_write($struct->{typename} *, requiem_msgbuf_t *);", "\n\n");
}

sub        struct
{
    my        $self = shift;
    my        $tree = shift;
    my        $struct = shift;

    $self->output("
/**
 * idmef_$struct->{short_typename}_write:
 * \@$struct->{short_typename}: Pointer to a #$struct->{typename} object.
 * \@msg: Pointer to a #requiem_msgbuf_t object, where the message should be written.
 *
 * Write \@$struct->{short_typename} within \@msg message buffer. The buffer is
 * associated with a #requiem_io_t file descriptor where the data will be written.
 *
 * Returns: 0 on success, a negative value if an error occured.
 */
int idmef_$struct->{short_typename}_write($struct->{typename} *$struct->{short_typename}, requiem_msgbuf_t *msg)\n\{\n", " " x 8, "int ret;\n");

    $self->output(" " x 8, "if ( ! $struct->{short_typename} )", "\n",
                  " " x 16, "return 0;",
                  "\n\n");

    if ( $struct->{typename} eq "idmef_heartbeat_t" ) {
        $self->output(" " x 8, "requiem_msg_set_priority(requiem_msgbuf_get_msg(msg), REQUIEM_MSG_PRIORITY_HIGH);\n\n");
    }

    if ( ! $struct->{toplevel} ) {
        $self->output(" " x 8, "ret = requiem_msgbuf_set(msg, ", "IDMEF_MSG_" . uc($struct->{short_typename}) . "_TAG", ", 0, NULL);\n",
" " x 8, "if ( ret < 0 )\n", " " x 16, "return ret;\n");
    }

    foreach my $field ( @{ $struct->{field_list} } ) {

        if ( $field->{metatype} & &METATYPE_NORMAL ) {

            if ( $field->{metatype} & &METATYPE_PRIMITIVE ) {
                $self->struct_field_normal($tree, $struct, $field);

            } elsif ( $field->{metatype} & &METATYPE_STRUCT ) {
                $self->struct_field_struct($tree, $struct, $field);

            } elsif ( $field->{metatype} & &METATYPE_ENUM ) {
                $self->struct_field_normal($tree, $struct, $field, "uint32");
            }

        } elsif ( $field->{metatype} & &METATYPE_LIST ) {
            $self->struct_field_list($tree, $struct, $field);

        } elsif ( $field->{metatype} & &METATYPE_UNION ) {
            $self->struct_field_union($tree, $struct, $field);
        }
    }

    $self->output(" " x 8, "return requiem_msgbuf_set(msg, IDMEF_MSG_END_OF_TAG, 0, NULL);\n");
    $self->output("\}\n\n\n");
}

1;
