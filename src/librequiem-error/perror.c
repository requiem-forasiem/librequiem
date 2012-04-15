#include <stdio.h>
#include <stdarg.h>

#include "requiem-log.h"
#include "requiem-error.h"


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
