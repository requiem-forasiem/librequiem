/*****
*
* Copyright (C) 2004-2005,2006,2007 PreludeIDS Technologies. All Rights Reserved.
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

/*
 * This code include an heavily modified version of the requiem-strbuf
 * API made by Krzysztof Zaraska, that is now part of requiem-string.
 */

#include "config.h"
#include "libmissing.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <assert.h>

#include "common.h"
#include "requiem-log.h"
#include "requiem-inttypes.h"
#include "requiem-string.h"


#define REQUIEM_ERROR_SOURCE_DEFAULT REQUIEM_ERROR_SOURCE_STRING
#include "requiem-error.h"


#define CHUNK_SIZE 1024


/*
 * String structure may be free'd
 */
#define REQUIEM_STRING_OWN_STRUCTURE  0x1

/*
 * String data may be free'd
 */
#define REQUIEM_STRING_OWN_DATA       0x2


/*
 * Whether we can reallocate this string
 */
#define REQUIEM_STRING_CAN_REALLOC    0x4




#if ! defined (REQUIEM_VA_COPY)

# if defined (__GNUC__) && defined (__PPC__) && (defined (_CALL_SYSV) || defined (_WIN32))
#  define REQUIEM_VA_COPY(ap1, ap2)     (*(ap1) = *(ap2))

# elif defined (REQUIEM_VA_COPY_AS_ARRAY)
#  define REQUIEM_VA_COPY(ap1, ap2)     memmove ((ap1), (ap2), sizeof(va_list))

# else /* va_list is a pointer */
#  define REQUIEM_VA_COPY(ap1, ap2)     ((ap1) = (ap2))

# endif
#endif


#define STRING_RETURN_IF_INVALID(str, len) do {                                                                \
        requiem_return_val_if_fail((len + 1) > len,                                                            \
                                    requiem_error_verbose(REQUIEM_ERROR_INVAL_LENGTH,                          \
                                                          "string length warning: wrap around would occur"));  \
                                                                                                               \
        requiem_return_val_if_fail(str[len] == 0,                                                              \
                                   requiem_error_verbose(REQUIEM_ERROR_STRING_NOT_NULL_TERMINATED,             \
                                                         "string warning: not nul terminated"));               \
} while(0)


static int string_buf_alloc(requiem_string_t *string, size_t len)
{
        /*
         * include room for terminating \0.
         */
        string->data.rwbuf = malloc(len + 1);
        if ( ! string->data.rwbuf )
                return requiem_error_from_errno(errno);

        string->index = len;
        string->size = len + 1;

        return 0;
}



static void string_buf_copy(requiem_string_t *string, const char *buf, size_t len)
{
        assert(len < string->size);

        memcpy(string->data.rwbuf, buf, len);
        string->data.rwbuf[len] = '\0';
}



static int allocate_more_chunk_if_needed(requiem_string_t *s, size_t needed_len)
{
        char *ptr;
        size_t len;

        if ( needed_len )
                len = MAX(needed_len - (s->size - s->index), CHUNK_SIZE);
        else
                len = CHUNK_SIZE;

        if ( s->size + len < s->size )
                return requiem_error(REQUIEM_ERROR_INVAL_LENGTH);

        if ( s->flags & REQUIEM_STRING_CAN_REALLOC ) {

                ptr = _requiem_realloc(s->data.rwbuf, s->size + len);
                if ( ! ptr )
                        return requiem_error_from_errno(errno);
        }

        else {
                ptr = malloc(s->size + len);
                if ( ! ptr )
                        return requiem_error_from_errno(errno);

                if ( s->data.robuf )
                        memcpy(ptr, s->data.robuf, s->index + 1);

                s->flags |= REQUIEM_STRING_CAN_REALLOC|REQUIEM_STRING_OWN_DATA;
        }

        s->size += len;
        s->data.rwbuf = ptr;

        return 0;
}



/**
 * requiem_string_new:
 * @string: Pointer where to store the created #requiem_string_t.
 *
 * Create a new #requiem_string_t object, and store in in @string.
 *
 * Returns: 0 on success, or a negative value if an error occured.
 */
int requiem_string_new(requiem_string_t **string)
{
        *string = calloc(1, sizeof(**string));
        if ( ! *string )
                return requiem_error_from_errno(errno);

        (*string)->refcount = 1;
        requiem_list_init(&(*string)->list);
        (*string)->flags = REQUIEM_STRING_OWN_STRUCTURE;

        return 0;
}




/**
 * requiem_string_ref:
 * @string: Pointer to a #requiem_string_t object to reference.
 *
 * Increase @string reference count.
 *
 * Returns: @string.
 */
requiem_string_t *requiem_string_ref(requiem_string_t *string)
{
        requiem_return_val_if_fail(string, NULL);

        string->refcount++;
        return string;
}



/**
 * requiem_string_new_dup_fast:
 * @string: Pointer where to store the created #requiem_string_t object.
 * @str: Initial string value.
 * @len: Lenght of @str.
 *
 * Create a new #requiem_string_t object with a copy of @str as it's
 * initial value.  The copy is owned by the @string and will be freed
 * upon requiem_string_destroy().
 *
 * Returns: 0 on success, a negative value if an error occured.
 */
int requiem_string_new_dup_fast(requiem_string_t **string, const char *str, size_t len)
{
        int ret;

        requiem_return_val_if_fail(str, requiem_error(REQUIEM_ERROR_ASSERTION));
        STRING_RETURN_IF_INVALID(str, len);

        ret = requiem_string_new(string);
        if ( ret < 0 )
                return ret;

        ret = string_buf_alloc(*string, len);
        if ( ret < 0 )
                return ret;

        string_buf_copy(*string, str, len);
        (*string)->flags |= REQUIEM_STRING_OWN_DATA|REQUIEM_STRING_CAN_REALLOC;

        return 0;
}



/**
 * requiem_string_new_dup:
 * @string: Pointer where to store the created #requiem_string_t object.
 * @str: Initial string value.
 *
 * Create a new #requiem_string_t object with a copy of @str as it's
 * initial value. The copy is owned by the @string and will be freed
 * upon requiem_string_destroy().
 *
 * Returns: 0 on success, a negative value if an error occured.
 */
int requiem_string_new_dup(requiem_string_t **string, const char *str)
{
        requiem_return_val_if_fail(str, requiem_error(REQUIEM_ERROR_ASSERTION));
        return requiem_string_new_dup_fast(string, str, strlen(str));
}



/**
 * requiem_string_new_nodup_fast:
 * @string: Pointer where to store the created #requiem_string_t object.
 * @str: Initial string value.
 * @len: Lenght of @str.
 *
 * Create a new #requiem_string_t object with a reference to @str as
 * initial value.  @str is owned by @string and will be freed upon
 * requiem_string_destroy().
 *
 * Returns: 0 on success, a negative value if an error occured.
 */
int requiem_string_new_nodup_fast(requiem_string_t **string, char *str, size_t len)
{
        int ret;

        requiem_return_val_if_fail(str, requiem_error(REQUIEM_ERROR_ASSERTION));

        STRING_RETURN_IF_INVALID(str, len);

        ret = requiem_string_new(string);
        if ( ret < 0 )
                return ret;

        (*string)->index = len;
        (*string)->size = len + 1;
        (*string)->data.rwbuf = str;
        (*string)->flags |= REQUIEM_STRING_OWN_DATA|REQUIEM_STRING_CAN_REALLOC;

        return 0;
}



/**
 * requiem_string_new_nodup:
 * @string: Pointer where to store the created #requiem_string_t object.
 * @str: Initial string value.
 *
 * Create a new #requiem_string_t object with a reference to @str as
 * initial value.  @str is owned by @string and will be freed upon
 * requiem_string_destroy().
 *
 * Returns: 0 on success, a negative value if an error occured.
 */
int requiem_string_new_nodup(requiem_string_t **string, char *str)
{
        requiem_return_val_if_fail(str, requiem_error(REQUIEM_ERROR_ASSERTION));
        return requiem_string_new_nodup_fast(string, str, strlen(str));
}



/**
 * requiem_string_new_ref_fast:
 * @string: Pointer where to store the created #requiem_string_t object.
 * @str: Initial string value.
 * @len: Length of @str.
 *
 * Create a new #requiem_string_t object with a reference to @str as
 * initial value. @str won't be freed upon requiem_string_destroy().
 *
 * Returns: 0 on success, a negative value if an error occured.
 */
int requiem_string_new_ref_fast(requiem_string_t **string, const char *buf, size_t len)
{
        int ret;

        requiem_return_val_if_fail(buf, requiem_error(REQUIEM_ERROR_ASSERTION));
        STRING_RETURN_IF_INVALID(buf, len);

        ret = requiem_string_new(string);
        if ( ret < 0 )
                return ret;

        (*string)->index = len;
        (*string)->size = len + 1;
        (*string)->data.robuf = buf;

        return 0;
}



/**
 * requiem_string_new_ref:
 * @string: Pointer where to store the created #requiem_string_t object.
 * @str: Initial string value.
 *
 * Create a new #requiem_string_t object with a reference to @str as
 * initial value. @str won't be freed upon requiem_string_destroy().
 *
 * Returns: 0 on success, a negative value if an error occured.
 */
int requiem_string_new_ref(requiem_string_t **string, const char *str)
{
        requiem_return_val_if_fail(str, requiem_error(REQUIEM_ERROR_ASSERTION));
        return requiem_string_new_ref_fast(string, str, strlen(str));
}



/**
 * requiem_string_set_dup_fast:
 * @string: Pointer to a #requiem_string_t object.
 * @buf: String to store in @string.
 * @len: Lenght of @buf.
 *
 * Store a copy of the string pointed by @buf in @string.
 * The @buf copy will be freed upon requiem_string_destroy().
 *
 * Returns: 0 on success, or a negative value if an error occured.
 */
int requiem_string_set_dup_fast(requiem_string_t *string, const char *buf, size_t len)
{
        int ret;

        requiem_return_val_if_fail(string, requiem_error(REQUIEM_ERROR_ASSERTION));
        requiem_return_val_if_fail(buf, requiem_error(REQUIEM_ERROR_ASSERTION));
        STRING_RETURN_IF_INVALID(buf, len);

        requiem_string_destroy_internal(string);

        ret = string_buf_alloc(string, len);
        if ( ret < 0 )
                return ret;

        string_buf_copy(string, buf, len);
        string->flags |= REQUIEM_STRING_OWN_DATA|REQUIEM_STRING_CAN_REALLOC;

        return 0;
}



/**
 * requiem_string_set_dup:
 * @string: Pointer to a #requiem_string_t object.
 * @buf: String to store in @string.
 *
 * Store a copy of the string pointed by @buf in @string.
 * The @buf copy will be freed upon requiem_string_destroy().
 *
 * Returns: 0 on success, or a negative value if an error occured.
 */
int requiem_string_set_dup(requiem_string_t *string, const char *buf)
{
        requiem_return_val_if_fail(string, requiem_error(REQUIEM_ERROR_ASSERTION));
        requiem_return_val_if_fail(buf, requiem_error(REQUIEM_ERROR_ASSERTION));
        return requiem_string_set_dup_fast(string, buf, strlen(buf));
}



/**
 * requiem_string_set_nodup_fast:
 * @string: Pointer to a #requiem_string_t object.
 * @buf: String to store in @string.
 * @len: Lenght of @buf.
 *
 * Store a reference to the string pointed by @buf in @string.
 * The referenced @buf will be freed upon requiem_string_destroy().
 *
 * Returns: 0 on success, or a negative value if an error occured.
 */
int requiem_string_set_nodup_fast(requiem_string_t *string, char *buf, size_t len)
{
        requiem_return_val_if_fail(string, requiem_error(REQUIEM_ERROR_ASSERTION));
        requiem_return_val_if_fail(buf, requiem_error(REQUIEM_ERROR_ASSERTION));
        STRING_RETURN_IF_INVALID(buf, len);

        requiem_string_destroy_internal(string);

        string->index = len;
        string->size = len + 1;
        string->data.rwbuf = buf;

        string->flags |= REQUIEM_STRING_OWN_DATA|REQUIEM_STRING_CAN_REALLOC;

        return 0;
}




/**
 * requiem_string_set_nodup:
 * @string: Pointer to a #requiem_string_t object.
 * @buf: String to store in @string.
 *
 * Store a reference to the string pointed by @buf in @string.
 * The referenced @buf will be freed upon requiem_string_destroy().
 *
 * Returns: 0 on success, or a negative value if an error occured.
 */
int requiem_string_set_nodup(requiem_string_t *string, char *buf)
{
        requiem_return_val_if_fail(string, requiem_error(REQUIEM_ERROR_ASSERTION));
        requiem_return_val_if_fail(buf, requiem_error(REQUIEM_ERROR_ASSERTION));

        return requiem_string_set_nodup_fast(string, buf, strlen(buf));
}



/**
 * requiem_string_set_ref_fast:
 * @string: Pointer to a #requiem_string_t object.
 * @buf: String to store in @string.
 * @len: Lenght of @buf.
 *
 * Store a reference to the string pointed by @buf in @string.
 * The referenced @buf value won't be modified or freed.
 *
 * Returns: 0 on success, or a negative value if an error occured.
 */
int requiem_string_set_ref_fast(requiem_string_t *string, const char *buf, size_t len)
{
        requiem_return_val_if_fail(string, requiem_error(REQUIEM_ERROR_ASSERTION));
        requiem_return_val_if_fail(buf, requiem_error(REQUIEM_ERROR_ASSERTION));
        STRING_RETURN_IF_INVALID(buf, len);

        requiem_string_destroy_internal(string);

        string->index = len;
        string->size = len + 1;
        string->data.robuf = buf;

        string->flags &= ~(REQUIEM_STRING_OWN_DATA|REQUIEM_STRING_CAN_REALLOC);

        return 0;
}



/**
 * requiem_string_set_ref:
 * @string: Pointer to a #requiem_string_t object.
 * @buf: String to store in @string.
 *
 * Store a reference to the string pointed by @buf in @string.
 * The referenced @buf value won't be modified or freed.
 *
 * Returns: 0 on success, or a negative value if an error occured.
 */
int requiem_string_set_ref(requiem_string_t *string, const char *buf)
{
        requiem_return_val_if_fail(string, requiem_error(REQUIEM_ERROR_ASSERTION));
        requiem_return_val_if_fail(buf, requiem_error(REQUIEM_ERROR_ASSERTION));

        return requiem_string_set_ref_fast(string, buf, strlen(buf));
}




/**
 * requiem_string_copy_ref:
 * @src: Pointer to a #requiem_string_t object to copy data from.
 * @dst: Pointer to a #requiem_string_t object to copy data to.
 *
 * Reference @src content within @dst.
 * The referenced content won't be modified or freed.
 *
 * Returns: 0 on success, or a negative value if an error occured.
 */
int requiem_string_copy_ref(const requiem_string_t *src, requiem_string_t *dst)
{
        requiem_return_val_if_fail(src, requiem_error(REQUIEM_ERROR_ASSERTION));
        requiem_return_val_if_fail(dst, requiem_error(REQUIEM_ERROR_ASSERTION));

        requiem_string_destroy_internal(dst);

        dst->size = src->size;
        dst->index = src->index;
        dst->data.robuf = src->data.robuf;
        dst->flags &= ~(REQUIEM_STRING_OWN_DATA|REQUIEM_STRING_CAN_REALLOC);

        return 0;
}



/**
 * requiem_string_copy_dup:
 * @src: Pointer to a #requiem_string_t object to copy data from.
 * @dst: Pointer to a #requiem_string_t object to copy data to.
 *
 * Copy @src content within @dst.
 * The content is owned by @src and independent of @dst.
 *
 * Returns: 0 on success, or a negative value if an error occured.
 */
int requiem_string_copy_dup(const requiem_string_t *src, requiem_string_t *dst)
{
        requiem_return_val_if_fail(src, requiem_error(REQUIEM_ERROR_ASSERTION));
        requiem_return_val_if_fail(dst, requiem_error(REQUIEM_ERROR_ASSERTION));

        requiem_string_destroy_internal(dst);

        dst->size = src->size;
        dst->index = src->index;
        dst->flags |= REQUIEM_STRING_OWN_DATA|REQUIEM_STRING_CAN_REALLOC;

        if ( src->size ) {
                dst->data.rwbuf = malloc(src->size);
                if ( ! dst->data.rwbuf )
                        return requiem_error_from_errno(errno);

                string_buf_copy(dst, src->data.robuf, src->index);
        }

        return 0;
}



/**
 * requiem_string_clone:
 * @src: Pointer to an existing #requiem_string_t object.
 * @dst: Pointer to an address where to store the created #requiem_string_t object.
 *
 * Clone @src within a new #requiem_string_t object stored into @dst.
 * Data carried by @dst and @src are independant.
 *
 * Returns: 0 on success, or a negative value if an error occured.
 */
int requiem_string_clone(const requiem_string_t *src, requiem_string_t **dst)
{
        int ret;

        requiem_return_val_if_fail(src, requiem_error(REQUIEM_ERROR_ASSERTION));

        ret = requiem_string_new(dst);
        if ( ret < 0 )
                return ret;

        (*dst)->size = src->size;
        (*dst)->index = src->index;
        (*dst)->flags |= REQUIEM_STRING_OWN_DATA|REQUIEM_STRING_CAN_REALLOC;

        if ( src->size ) {
                (*dst)->data.rwbuf = malloc(src->size);
                if ( ! (*dst)->data.rwbuf ) {
                        requiem_string_destroy(*dst);
                        return requiem_error_from_errno(errno);
                }

                string_buf_copy(*dst, src->data.robuf, src->index);
        }

        return 0;
}



/**
 * requiem_string_get_len:
 * @string: Pointer to a #requiem_string_t object.
 *
 * Return the length of the string carried by @string object.
 *
 * Returns: The length of the string owned by @string.
 */
size_t requiem_string_get_len(const requiem_string_t *string)
{
        requiem_return_val_if_fail(string, 0);
        return string->index;
}



/**
 * requiem_string_get_string_or_default:
 * @string: Pointer to a #requiem_string_t object.
 * @def: Default value to a return in case @string is empty.
 *
 * Return the string carried on by @string object, or @def if it is empty.
 * There should be no operation done on the returned string since it is still
 * owned by @string.
 *
 * Returns: The string owned by @string or @def.
 */
const char *requiem_string_get_string_or_default(const requiem_string_t *string, const char *def)
{
        requiem_return_val_if_fail(string, NULL);
        return string->data.robuf ? string->data.robuf : def;
}



/**
 * requiem_string_get_string:
 * @string: Pointer to a #requiem_string_t object.
 *
 * Return the string carried on by @string object.
 * There should be no operation done on the returned string since
 * it is still owned by @string.
 *
 * Returns: The string owned by @string if any.
 */
const char *requiem_string_get_string(const requiem_string_t *string)
{
        requiem_return_val_if_fail(string, NULL);
        return string->data.robuf;
}




/**
 * requiem_string_get_string_released:
 * @string: Pointer to a #requiem_string_t object.
 * @outptr: Pointer to an address where to store the released string.
 *
 * Get @string content, and release it so that further operation on
 * @string won't modify the returned content.
 *
 * Returns: 0 on success, or a negative value if an error occured.
 */
int requiem_string_get_string_released(requiem_string_t *string, char **outptr)
{
        requiem_return_val_if_fail(string, requiem_error(REQUIEM_ERROR_ASSERTION));
        *outptr = NULL;

        if ( ! string->index )
                return 0;

        if ( ! (string->flags & REQUIEM_STRING_CAN_REALLOC) ) {
                *outptr = strdup(string->data.robuf);
                return (*outptr) ? 0 : requiem_error_from_errno(errno);
        }

        if ( string->index + 1 <= string->index )
                return requiem_error(REQUIEM_ERROR_INVAL_LENGTH);

        *outptr = _requiem_realloc(string->data.rwbuf, string->index + 1);
        if ( ! *outptr )
                return requiem_error_from_errno(errno);

        string->size = 0;
        string->index = 0;
        string->data.rwbuf = NULL;

        return 0;
}




/**
 * requiem_string_is_empty:
 * @string: Pointer to a #requiem_string_t object.
 *
 * Check whether @string is empty.
 *
 * Returns: TRUE if @string is empty, FALSE otherwise.
 */
requiem_bool_t requiem_string_is_empty(const requiem_string_t *string)
{
        requiem_return_val_if_fail(string, TRUE);
        return (string->index == 0) ? TRUE : FALSE;
}



/*
 *  This function cannot be declared static because its invoked
 *  from idmef-tree-wrap.c
 */
void requiem_string_destroy_internal(requiem_string_t *string)
{
        requiem_return_if_fail(string);

        if ( (string->flags & REQUIEM_STRING_OWN_DATA) && string->data.rwbuf )
                free(string->data.rwbuf);

        string->data.rwbuf = NULL;
        string->index = string->size = 0;

        /*
         * free() should be done by the caller
         */
}



/**
 * requiem_string_destroy:
 * @string: Pointer to a #requiem_string_t object.
 *
 * Decrease refcount and destroy @string.
 * @string content content is destroyed if applicable (dup and nodup,
 * or a referenced string that have been modified.
 */
void requiem_string_destroy(requiem_string_t *string)
{
        requiem_return_if_fail(string);

        if ( --string->refcount )
                return;

        if ( ! requiem_list_is_empty(&string->list) )
                requiem_list_del_init(&string->list);

        requiem_string_destroy_internal(string);

        if ( string->flags & REQUIEM_STRING_OWN_STRUCTURE )
                free(string);
}




/**
 * requiem_string_vprintf:
 * @string: Pointer to a #requiem_string_t object.
 * @fmt: Format string to use.
 * @ap: Variable argument list.
 *
 * Produce output according to @fmt, storing argument provided in @ap
 * variable argument list, and write the output to the given @string.
 * See sprintf(3) for more information on @fmt format.
 *
 * Returns: The number of characters written, or a negative value if an error occured.
 */
int requiem_string_vprintf(requiem_string_t *string, const char *fmt, va_list ap)
{
        int ret;
        va_list bkp;

        requiem_return_val_if_fail(string, requiem_error(REQUIEM_ERROR_ASSERTION));
        requiem_return_val_if_fail(fmt, requiem_error(REQUIEM_ERROR_ASSERTION));

        if ( ! (string->flags & REQUIEM_STRING_CAN_REALLOC) ) {

                ret = allocate_more_chunk_if_needed(string, 0);
                if ( ret < 0 )
                        return ret;
        }

        REQUIEM_VA_COPY(bkp, ap);
        ret = vsnprintf(string->data.rwbuf + string->index, string->size - string->index, fmt, ap);

        /*
         * From sprintf(3) on GNU/Linux:
         *
         * snprintf  and vsnprintf do not write more than
         * size bytes (including the trailing '\0'), and return -1 if
         * the  output  was truncated due to this limit.  (Thus until
         * glibc 2.0.6. Since glibc 2.1 these  functions  follow  the
         * C99  standard and return the number of characters (exclud-
         * ing the trailing '\0') which would have  been  written  to
         * the final string if enough space had been available.)
         */
        if ( ret >= 0 && (size_t) ret < string->size - string->index ) {
                string->index += ret;
                goto end;
        }

        ret = allocate_more_chunk_if_needed(string, (ret < 0) ? 0 : ret + 1);
        if ( ret < 0 )
                goto end;

        ret = requiem_string_vprintf(string, fmt, bkp);

 end:
        va_end(bkp);
        return ret;
}




/**
 * requiem_string_sprintf:
 * @string: Pointer to a #requiem_string_t object.
 * @fmt: Format string to use.
 * @...: Variable argument list.
 *
 * Produce output according to @fmt, and write output to the given
 * @string. See snprintf(3) to learn more about @fmt format.
 *
 * Returns: The number of characters written, or a negative value if an error occured.
 */
int requiem_string_sprintf(requiem_string_t *string, const char *fmt, ...)
{
        int ret;
        va_list ap;

        requiem_return_val_if_fail(string, requiem_error(REQUIEM_ERROR_ASSERTION));
        requiem_return_val_if_fail(fmt, requiem_error(REQUIEM_ERROR_ASSERTION));

        va_start(ap, fmt);
        ret = requiem_string_vprintf(string, fmt, ap);
        va_end(ap);

        return ret;
}



/**
 * requiem_string_cat:
 * @dst: Pointer to a #requiem_string_t object.
 * @str: Pointer to a string.
 * @len: Length of @str to copy.
 *
 * The requiem_string_ncat() function appends @len characters from @str to
 * the @dst #requiem_string_t object over-writing the `\0' character at the
 * end of @dst, and then adds a termi-nating `\0' character.
 *
 * Returns: @len, or a negative value if an error occured.
 */
int requiem_string_ncat(requiem_string_t *dst, const char *str, size_t len)
{
        int ret;

        requiem_return_val_if_fail(dst, requiem_error(REQUIEM_ERROR_ASSERTION));
        requiem_return_val_if_fail(str, requiem_error(REQUIEM_ERROR_ASSERTION));

        if ( dst->flags & REQUIEM_STRING_CAN_REALLOC && len < (dst->size - dst->index) ) {

                memcpy(dst->data.rwbuf + dst->index, str, len);

                dst->index += len;
                dst->data.rwbuf[dst->index] = '\0';

                return len;
        }

        if ( len + 1 < len )
                return requiem_error(REQUIEM_ERROR_INVAL_LENGTH);

        ret = allocate_more_chunk_if_needed(dst, len + 1);
        if ( ret < 0 )
                return ret;

        return requiem_string_ncat(dst, str, len);
}



/**
 * requiem_string_cat:
 * @dst: Pointer to a #requiem_string_t object.
 * @str: Pointer to a string.
 *
 * The requiem_string_cat() function appends the @str string to the @dst
 * requiem_string_t object over-writing the `\0' character at the end of
 * @dst, and then adds a termi-nating `\0' character.
 *
 * Returns: @len, or a negative value if an error occured.
 */
int requiem_string_cat(requiem_string_t *dst, const char *str)
{
        requiem_return_val_if_fail(dst, requiem_error(REQUIEM_ERROR_ASSERTION));
        requiem_return_val_if_fail(str, requiem_error(REQUIEM_ERROR_ASSERTION));

        return requiem_string_ncat(dst, str, strlen(str));
}




/**
 * requiem_string_clear:
 * @string: Pointer to a #requiem_string_t object.
 *
 * Reset @string content to zero.
 */
void requiem_string_clear(requiem_string_t *string)
{
        requiem_return_if_fail(string);

        string->index = 0;

        if ( string->data.rwbuf && string->flags & REQUIEM_STRING_OWN_DATA )
                *(string->data.rwbuf) = '\0';

        else string->data.rwbuf = NULL;
}



/**
 * requiem_string_compare:
 * @str1: Pointer to a #requiem_string_t object to compare with @str2.
 * @str2: Pointer to a #requiem_string_t object to compare with @str1.
 *
 * Returns: 0 if @str1 and @str2 value are equal, a negative value otherwise.
 */
int requiem_string_compare(const requiem_string_t *str1, const requiem_string_t *str2)
{
        if ( ! str1 && ! str2 )
                return 0;

        else if ( ! str1 || ! str2 )
                return -1;

        else if ( str1->index != str2->index )
                return -1;

        if ( str1->index == 0 )
                return 0;

        return strcmp(str1->data.robuf, str2->data.robuf);
}
