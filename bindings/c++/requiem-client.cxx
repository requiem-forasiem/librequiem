#include "idmef.hxx"
#include "requiem-error.hxx"
#include "requiem-client.hxx"
#include "requiem-client-profile.hxx"


using namespace Requiem;


Client::Client(const char *profile)
        : _recv_timeout(-1)
{
        int ret;

        ret = requiem_client_new(&_client, profile);
        if ( ret < 0 )
                throw RequiemError(ret);

        _profile = requiem_client_get_profile(_client);
        _pool = ConnectionPool(requiem_connection_pool_ref(requiem_client_get_connection_pool(_client)));
}


Client::Client(const Client &client)
{
        _client = (client._client) ? requiem_client_ref(client._client) : NULL;
}


Client::~Client()
{
        _profile = NULL;
        requiem_client_destroy(_client, REQUIEM_CLIENT_EXIT_STATUS_SUCCESS);
}


void Client::Start()
{
        int ret;

        Init();

        ret = requiem_client_start(_client);
        if ( ret < 0 )
                throw RequiemError(ret);
}


void Client::Init()
{
        int ret;

        ret = requiem_client_init(_client);
        if ( ret < 0 )
                throw RequiemError(ret);

        _profile = requiem_client_get_profile(_client);
}


requiem_client_t *Client::GetClient()
{
        return _client;
}


void Client::SendIDMEF(const IDMEF &message)
{
        requiem_client_send_idmef(_client, message);
}


int Client::RecvIDMEF(Requiem::IDMEF &idmef, int timeout)
{
        int ret;
        idmef_message_t *idmef_p;

        ret = requiem_client_recv_idmef(_client, timeout, &idmef_p);
        if ( ret < 0 )
                throw RequiemError(ret);

        else if ( ret == 0 )
                return 0;

        idmef = IDMEF(idmef_p);

        return 1;
}


int Client::GetFlags()
{
        return requiem_client_get_flags(_client);
}


void Client::SetFlags(int flags)
{
        int ret;

        ret = requiem_client_set_flags(_client, (requiem_client_flags_t) flags);
        if ( ret < 0 )
                throw RequiemError(ret);
}


int Client::GetRequiredPermission()
{
        return requiem_client_get_required_permission(_client);
}


void Client::SetRequiredPermission(int permission)
{
        requiem_client_set_required_permission(_client, (requiem_connection_permission_t) permission);
}


const char *Client::GetConfigFilename()
{
        return requiem_client_get_config_filename(_client);
}


void Client::SetConfigFilename(const char *name)
{
        int ret;

        ret = requiem_client_set_config_filename(_client, name);
        if ( ret < 0 )
                throw RequiemError(ret);
}


ConnectionPool &Client::GetConnectionPool()
{
        return _pool;
}


void Client::SetConnectionPool(ConnectionPool pool)
{
        _pool = pool;
        requiem_client_set_connection_pool(_client, requiem_connection_pool_ref(pool));
}


Client &Client::operator << (IDMEF &idmef)
{
        SendIDMEF(idmef);
        return *this;
}


Client &Client::operator >> (IDMEF &idmef)
{
        int ret;

        ret = RecvIDMEF(idmef, _recv_timeout);
        if ( ret <= 0 )
                throw RequiemError(ret);

        return *this;
}

Client &Client::SetRecvTimeout(Client &c, int timeout)
{
        c._recv_timeout = timeout;
        return c;
}


Client &Client::operator=(const Client &c)
{
        if ( this != &c && _client != c._client ) {
                if ( _client )
                        requiem_client_destroy(_client, REQUIEM_CLIENT_EXIT_STATUS_SUCCESS);

                _client = (c._client) ? requiem_client_ref(c._client) : NULL;
        }

        return *this;
}
