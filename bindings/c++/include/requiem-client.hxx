#ifndef _LIBREQUIEM_REQUIEM_CLIENT_HXX
#define _LIBREQUIEM_REQUIEM_CLIENT_HXX

#include "idmef.hxx"
#include "requiem-connection-pool.hxx"
#include "requiem-client-profile.hxx"


namespace Requiem {
        class IDMEF;

        class Client : public ClientProfile {
            private:
                requiem_client_t *_client;
                ConnectionPool _pool;

            protected:
                int _recv_timeout;

            public:
                enum ClientFlagsEnum {
                        ASYNC_SEND  = REQUIEM_CLIENT_FLAGS_ASYNC_SEND,
                        FLAGS_ASYNC_SEND   = REQUIEM_CLIENT_FLAGS_ASYNC_SEND,
                        ASYNC_TIMER = REQUIEM_CLIENT_FLAGS_ASYNC_TIMER,
                        FLAGS_ASYNC_TIMER  = REQUIEM_CLIENT_FLAGS_ASYNC_TIMER,
                        HEARTBEAT   = REQUIEM_CLIENT_FLAGS_HEARTBEAT,
                        FLAGS_HEARTBEAT   = REQUIEM_CLIENT_FLAGS_HEARTBEAT,
                        CONNECT     = REQUIEM_CLIENT_FLAGS_CONNECT,
                        FLAGS_CONNECT     = REQUIEM_CLIENT_FLAGS_CONNECT,
                        AUTOCONFIG  = REQUIEM_CLIENT_FLAGS_AUTOCONFIG,
                        FLAGS_AUTOCONFIG = REQUIEM_CLIENT_FLAGS_AUTOCONFIG,
                };

                enum ConnectionPermissionEnum {
                        IDMEF_READ  = REQUIEM_CONNECTION_PERMISSION_IDMEF_READ,
                        PERMISSION_IDMEF_READ = REQUIEM_CONNECTION_PERMISSION_IDMEF_READ,
                        ADMIN_READ  = REQUIEM_CONNECTION_PERMISSION_ADMIN_READ,
                        PERMISSION_ADMIN_READ  = REQUIEM_CONNECTION_PERMISSION_ADMIN_READ,
                        IDMEF_WRITE = REQUIEM_CONNECTION_PERMISSION_IDMEF_WRITE,
                        PERMISSION_IDMEF_WRITE  = REQUIEM_CONNECTION_PERMISSION_IDMEF_WRITE,
                        ADMIN_WRITE = REQUIEM_CONNECTION_PERMISSION_ADMIN_WRITE,
                        PERMISSION_ADMIN_WRITE  = REQUIEM_CONNECTION_PERMISSION_ADMIN_WRITE,
                };

                ~Client();
                Client(const char *profile);
                Client(const Client &client);

                void Start();
                void Init();

                requiem_client_t *GetClient();

                void SendIDMEF(const Requiem::IDMEF &message);
                int RecvIDMEF(Requiem::IDMEF &idmef, int timeout=-1);

                int GetFlags();
                void SetFlags(int flags);

                int GetRequiredPermission();
                void SetRequiredPermission(int permission);

                const char *GetConfigFilename();
                void SetConfigFilename(const char *name);

                Requiem::ConnectionPool &GetConnectionPool();
                void SetConnectionPool(Requiem::ConnectionPool pool);

                Client &operator << (Requiem::IDMEF &idmef);
                Client &operator >> (Requiem::IDMEF &idmef);
                Client &operator=(const Client &p);

                static Client &SetRecvTimeout(Client &c, int timeout);
        };
};

#endif
