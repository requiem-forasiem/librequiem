/*****
*
* Copyright (C) 2001, 2002, 2003, 2004, 2005 PreludeIDS Technologies. All Rights Reserved.
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

#ifndef _LIBREQUIEM_REQUIEM_IO_H
#define _LIBREQUIEM_REQUIEM_IO_H

#ifdef __cplusplus
  extern "C" {
#endif

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdio.h>
#include <unistd.h>
#include "requiem-inttypes.h"


typedef struct requiem_io requiem_io_t;

/*
 * Object creation / destruction functions.
 */
int requiem_io_new(requiem_io_t **ret);

void requiem_io_destroy(requiem_io_t *pio);

void requiem_io_set_file_io(requiem_io_t *pio, FILE *fd);

void requiem_io_set_tls_io(requiem_io_t *pio, void *tls);

void requiem_io_set_sys_io(requiem_io_t *pio, int fd);

int requiem_io_set_buffer_io(requiem_io_t *pio);


/*
 *
 */
void requiem_io_set_fdptr(requiem_io_t *pio, void *ptr);
void requiem_io_set_write_callback(requiem_io_t *pio, ssize_t (*write)(requiem_io_t *io, const void *buf, size_t count));
void requiem_io_set_read_callback(requiem_io_t *pio, ssize_t (*read)(requiem_io_t *io, void *buf, size_t count));
void requiem_io_set_pending_callback(requiem_io_t *pio, ssize_t (*pending)(requiem_io_t *io));


/*
 * IO operations.
 */
int requiem_io_close(requiem_io_t *pio);

ssize_t requiem_io_read(requiem_io_t *pio, void *buf, size_t count);

ssize_t requiem_io_read_wait(requiem_io_t *pio, void *buf, size_t count);

ssize_t requiem_io_read_delimited(requiem_io_t *pio, unsigned char **buf);


ssize_t requiem_io_write(requiem_io_t *pio, const void *buf, size_t count);

ssize_t requiem_io_write_delimited(requiem_io_t *pio, const void *buf, uint16_t count);


ssize_t requiem_io_forward(requiem_io_t *dst, requiem_io_t *src, size_t count);

int requiem_io_get_fd(requiem_io_t *pio);

void *requiem_io_get_fdptr(requiem_io_t *pio);

ssize_t requiem_io_pending(requiem_io_t *pio);

requiem_bool_t requiem_io_is_error_fatal(requiem_io_t *pio, int error);

#ifdef __cplusplus
  }
#endif

#endif /* _LIBREQUIEM_REQUIEM_IO_H */
