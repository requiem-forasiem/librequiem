#include "config.h"

#include <stdlib.h>
#include <assert.h>
#include "requiem.h"

#define TEST_COUNT 10
#define TEST_STR "abcdefghijklmnopqrstuvwxyz"


static void create_str(requiem_string_t **str)
{
        size_t i;

        assert(requiem_string_new(str) == 0);
        assert(requiem_string_is_empty(*str) == TRUE);

        for ( i = 0; i < TEST_COUNT; i++ ) {
                assert(requiem_string_cat(*str, TEST_STR) >= 0);
        }

        assert(requiem_string_get_len(*str) == (TEST_COUNT * (sizeof(TEST_STR) - 1)));
}


int main(void)
{
        requiem_string_t *str1, *str2;

        create_str(&str1);
        assert(requiem_string_clone(str1, &str2) == 0);
        assert(requiem_string_compare(str1, str2) == 0);

        assert(requiem_string_cat(str2, "won't match") >= 0);
        assert(requiem_string_compare(str1, str2) != 0);

        requiem_string_destroy(str1);
        requiem_string_destroy(str2);

        exit(0);
}
