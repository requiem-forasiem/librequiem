#include "config.h"

#include <stdlib.h>
#include <unistd.h>
#include <assert.h>
#include "requiem.h"

#include "glthread/lock.h"


struct asyncobj {
        REQUIEM_ASYNC_OBJECT;
        int myval;
};


static int async_done = 0;
static int timer_count = 0;
static gl_lock_t lock = gl_lock_initializer;


static void timer_cb(void *data)
{
        gl_lock_lock(lock);
        timer_count++;
        requiem_timer_reset(data);
        gl_lock_unlock(lock);
}


static void async_func(void *obj, void *data)
{
        struct asyncobj *ptr = obj;

        gl_lock_lock(lock);
        async_done = 1;
        assert(ptr->myval == 10);
        gl_lock_unlock(lock);
}


int main(void)
{
        requiem_timer_t timer;
        struct asyncobj myobj;

        assert(requiem_init(NULL, NULL) == 0);
        assert(requiem_async_init() == 0);
        requiem_async_set_flags(REQUIEM_ASYNC_FLAGS_TIMER);

        requiem_timer_set_expire(&timer, 1);
        requiem_timer_set_data(&timer, &timer);
        requiem_timer_set_callback(&timer, timer_cb);
        requiem_timer_init(&timer);

        sleep(3);

        gl_lock_lock(lock);
        assert(timer_count >= 2);
        gl_lock_unlock(lock);

        myobj.myval = 10;
        requiem_async_set_callback((requiem_async_object_t *) &myobj, async_func);
        requiem_async_add((requiem_async_object_t *) &myobj);

        requiem_async_exit();
        assert(async_done);

        exit(0);
}
