#include "config.h"

#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <gettext.h>
#include <errno.h>

#include "requiem.h"
#include "requiem-log.h"
#include "requiem-error.h"

#include "code-to-errno.h"
#include "code-from-errno.h"


#define REQUIEM_ERROR_CODE_DIM     65536
#define REQUIEM_ERROR_SOURCE_DIM     256

#define REQUIEM_ERROR_SOURCE_SHIFT    23
#define REQUIEM_ERROR_VERBOSE_SHIFT   22

#define REQUIEM_ERROR_CODE_MASK       (REQUIEM_ERROR_CODE_DIM - 1)
#define REQUIEM_ERROR_SOURCE_MASK     (REQUIEM_ERROR_SOURCE_DIM - 1)
#define REQUIEM_ERROR_VERBOSE_MASK    (1)


/**
 * requiem_error_make:
 * @source: Error source.
 * @code: Error code.
 *
 * Create a new #requiem_error_t error using @source and @code.
 *
 * Returns: The created #requiem_error_t integer.
 */
requiem_error_t requiem_error_make(requiem_error_source_t source, requiem_error_code_t code)
{
        return (code == REQUIEM_ERROR_NO_ERROR) ? code : -((source << REQUIEM_ERROR_SOURCE_SHIFT) | code);
}


/**
 * requiem_error_make_from_errno:
 * @source: Error source.
 * @err: errno value.
 *
 * Create a new #requiem_error_t error using @source and @errno.
 *
 * Returns: The created #requiem_error_t integer.
 */
requiem_error_t requiem_error_make_from_errno(requiem_error_source_t source, int err)
{
        requiem_error_code_t code = requiem_error_code_from_errno(err);
        return requiem_error_make(source, code);
}



/**
 * requiem_error_verbose_make_v:
 * @source: Error source.
 * @code: Error code.
 * @fmt: Format string.
 * @ap: Argument list.
 *
 * Create a new error using @source and @code, using the detailed error message
 * specified within @fmt.
 *
 * Returns: The created #requiem_error_t integer.
 */
requiem_error_t requiem_error_verbose_make_v(requiem_error_source_t source,
                                             requiem_error_code_t code, const char *fmt, va_list ap)
{
        int ret;
        requiem_string_t *str;

        ret = requiem_string_new(&str);
        if ( ret < 0 )
                return ret;

        ret = requiem_string_vprintf(str, fmt, ap);
        if ( ret < 0 ) {
                requiem_string_destroy(str);
                return ret;
        }

        ret = _requiem_thread_set_error(requiem_string_get_string(str));
        requiem_string_destroy(str);

        if ( ret < 0 )
                return ret;

        ret = requiem_error_make(source, code);
        ret = -ret;
        ret |= (1 << REQUIEM_ERROR_VERBOSE_SHIFT);

        return -ret;
}



/**
 * requiem_error_verbose_make:
 * @source: Error source.
 * @code: Error code.
 * @fmt: Format string.
 * @...: Argument list.
 *
 * Create a new error using @source and @code, using the detailed error message
 * specified within @fmt.
 *
 * Returns: The created #requiem_error_t integer.
 */
requiem_error_t requiem_error_verbose_make(requiem_error_source_t source,
                                           requiem_error_code_t code, const char *fmt, ...)
{
        int ret;
        va_list ap;

        va_start(ap, fmt);
        ret = requiem_error_verbose_make_v(source, code, fmt, ap);
        va_end(ap);

        return ret;
}


/**
 * requiem_error_get_code:
 * @error: A #requiem_error_t return value.
 *
 * Returns: the #requiem_code_t code contained within the @requiem_error_t integer.
 */
requiem_error_code_t requiem_error_get_code(requiem_error_t error)
{
        error = -error;
        return (requiem_error_code_t) (error & REQUIEM_ERROR_CODE_MASK);
}


/**
 * requiem_error_get_source:
 * @error: A #requiem_error_t return value.
 *
 * Returns: the #requiem_source_t source contained within the @requiem_error_t integer.
 */
requiem_error_source_t requiem_error_get_source(requiem_error_t error)
{
        error = -error;
        return (requiem_error_source_t) ((error >> REQUIEM_ERROR_SOURCE_SHIFT) & REQUIEM_ERROR_SOURCE_MASK);
}


/**
 * requiem_error_is_verbose:
 * @error: A #requiem_error_t return value.
 *
 * Returns: #REQUIEM_BOOL_TRUE if there is a detailed message for this error, #REQUIEM_BOOL_FALSE otherwise.
 */
requiem_bool_t requiem_error_is_verbose(requiem_error_t error)
{
        error = -error;
        return ((error >> REQUIEM_ERROR_VERBOSE_SHIFT) & REQUIEM_ERROR_VERBOSE_MASK) ? REQUIEM_BOOL_TRUE : REQUIEM_BOOL_FALSE;
}


/**
 * requiem_error_code_from_errno:
 * @err: errno value.
 *
 * Returns: the #requiem_error_code_t value corresponding to @err.
 */
requiem_error_code_t requiem_error_code_from_errno(int err)
{
        int idx;

        if ( ! err )
                return REQUIEM_ERROR_NO_ERROR;

        idx = errno_to_idx(err);
        if ( idx < 0 )
                return REQUIEM_ERROR_UNKNOWN_ERRNO;

        return REQUIEM_ERROR_SYSTEM_ERROR | err_code_from_index[idx];
}


/**
 * requiem_error_code_to_errno:
 * @code: Error code.
 *
 * Returns: the errno value corresponding to @code.
 */
int requiem_error_code_to_errno(requiem_error_code_t code)
{
        if ( ! (code & REQUIEM_ERROR_SYSTEM_ERROR) )
                return 0;

        code &= ~REQUIEM_ERROR_SYSTEM_ERROR;

        if ( code < sizeof(err_code_to_errno) / sizeof(err_code_to_errno[0]) )
                return err_code_to_errno[code];
        else
                return 0;
}



/**
 * requiem_perror:
 * @error: A #requiem_error_t return value.
 * @fmt: Format string.
 * @...: Argument list.
 *
 * Print the error to stderr, or to syslog() in case stderr is unavailable.
 */
void requiem_perror(requiem_error_t error, const char *fmt, ...)
{
        va_list ap;
        char buf[1024];

        va_start(ap, fmt);
        vsnprintf(buf, sizeof(buf), fmt, ap);
        va_end(ap);

        if ( requiem_error_get_source(error) )
                requiem_log(REQUIEM_LOG_WARN, "%s: %s: %s.\n", requiem_strsource(error), buf, requiem_strerror(error));
        else
                requiem_log(REQUIEM_LOG_WARN, "%s: %s.\n", buf, requiem_strerror(error));
}
