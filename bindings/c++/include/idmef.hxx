#ifndef _LIBREQUIEM_IDMEF_HXX
#define _LIBREQUIEM_IDMEF_HXX

#include <string>
#include <iostream>
#include "idmef-value.hxx"
#include "idmef-time.hxx"

namespace Requiem
{
        class IDMEF;
}

std::ostream & operator <<(std::ostream &os, const Requiem::IDMEF &idmef);
std::istream & operator >>(std::istream &is, Requiem::IDMEF &idmef);

namespace Requiem {
        class Client;

        class IDMEF {
                friend std::ostream & ::operator <<(std::ostream &os, const IDMEF &idmef);
                friend std::istream & ::operator >>(std::istream &is, IDMEF &idmef);

            protected:
                idmef_message_t *_message;

            public:
                ~IDMEF();
                IDMEF();
                IDMEF(const IDMEF &idmef);
                IDMEF(idmef_message_t *message);

                void Set(const char *path, std::vector<Requiem::IDMEFValue> value);
                void Set(const char *path, Requiem::IDMEFValue *value);
                void Set(const char *path, Requiem::IDMEFValue &value);
                void Set(const char *path, Requiem::IDMEFTime &value);
                void Set(const char *path, const char *value);
                void Set(const char *path, std::string value);
                void Set(const char *path, int8_t value);
                void Set(const char *path, uint8_t value);
                void Set(const char *path, int16_t value);
                void Set(const char *path, uint16_t value);
                void Set(const char *path, int32_t value);
                void Set(const char *path, uint32_t value);
                void Set(const char *path, int64_t value);
                void Set(const char *path, uint64_t value);
                void Set(const char *path, float value);
                void Set(const char *path, double value);
                Requiem::IDMEFValue Get(const char *path);

#ifndef SWIG
                size_t _genericWrite(int (write_cb)(requiem_msgbuf_t *msgbuf, requiem_msg_t *msg), void *fd_data) const;
                void _genericRead(ssize_t (read_cb)(requiem_io_t *fd, void *buf, size_t size), void *fd_data);
#endif

                IDMEF Clone(const IDMEF &idmef);
                const std::string ToString() const;

                operator const std::string() const;
                operator idmef_message_t *() const;
                IDMEF &operator = (const IDMEF &idmef);
        };
};

#endif /* __LIBREQUIEM_IDMEF_HXX */
