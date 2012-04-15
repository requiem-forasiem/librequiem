#include "config.h"

#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "requiem.h"


int main(int argc, char **argv)
{
        int ret;
        requiem_client_t *client;

        assert(requiem_init(&argc, argv) == 0);
        assert(requiem_client_new(&client, "Client that does not exist") == 0);
        assert((ret = requiem_client_start(client)) < 0);
        assert(requiem_error_get_code(ret) == REQUIEM_ERROR_PROFILE);

        requiem_client_destroy(client, REQUIEM_CLIENT_EXIT_STATUS_FAILURE);
        requiem_deinit();

        return 0;
}
