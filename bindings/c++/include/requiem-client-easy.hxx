#ifndef _LIBREQUIEM_REQUIEM_CLIENT_EASY_HXX
#define _LIBREQUIEM_REQUIEM_CLIENT_EASY_HXX

#include "requiem.h"
#include "idmef.hxx"
#include "requiem-client.hxx"


namespace Requiem {
        class ClientEasy : public Client {
            private:
                void setup_analyzer(idmef_analyzer *analyzer,
                                    const char *_model,
                                    const char *_class,
                                    const char *_manufacturer,
                                    const char *version);

            public:
                ClientEasy(const char *profile,
                           int permission = Client::IDMEF_WRITE,
                           const char *_model = "Unknown model",
                           const char *_class = "Unknown class",
                           const char *_manufacturer = "Unknown manufacturer",
                           const char *_version = "Unknown version");
        };
};

#endif
