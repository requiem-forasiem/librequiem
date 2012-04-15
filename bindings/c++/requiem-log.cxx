#include <requiem.h>

#include <requiem-log.hxx>


using namespace Requiem;

void RequiemLog::SetLevel(int level)
{
        requiem_log_set_level((requiem_log_t) level);
}


void RequiemLog::SetDebugLevel(int level)
{
        requiem_log_set_debug_level(level);
}


void RequiemLog::SetFlags(int flags)
{
        requiem_log_set_flags((requiem_log_flags_t) flags);
}


int RequiemLog::GetFlags()
{
        return requiem_log_get_flags();
}


void RequiemLog::SetLogfile(const char *filename)
{
        requiem_log_set_logfile(filename);
}


void RequiemLog::SetCallback(void (*log_cb)(int level, const char *log))
{

        requiem_log_set_callback((void (*)(requiem_log_t level, const char *log)) log_cb);
}
