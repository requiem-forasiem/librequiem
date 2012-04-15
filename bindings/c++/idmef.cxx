#include <iostream>

#include <string.h>
#include <requiem.h>
#include <idmef-path.h>
#include <idmef-message-print.h>

#include "requiem-error.hxx"
#include "idmef-path.hxx"
#include "idmef.hxx"


using namespace Requiem;


IDMEF::IDMEF() : _message(NULL)
{
        int ret;

        ret = idmef_message_new(&_message);
        if ( ret < 0 )
                throw RequiemError(ret);
}


IDMEF::IDMEF(const IDMEF &idmef)
{
        _message = (idmef._message) ? idmef_message_ref(idmef._message) : NULL;
}


IDMEF::IDMEF(idmef_message_t *message)
{
        _message = message;
}


IDMEF::~IDMEF()
{
        if ( _message )
                idmef_message_destroy(_message);
}


void IDMEF::Set(const char *path, std::vector<IDMEFValue> value)
{
        IDMEFPath(path).Set(*this, value);
}


void IDMEF::Set(const char *path, IDMEFValue *value)
{
        IDMEFPath(path).Set(*this, value);
}


void IDMEF::Set(const char *path, IDMEFValue &value)
{
        IDMEFPath(path).Set(*this, &value);
}


void IDMEF::Set(const char *path, std::string value)
{
        IDMEFPath(path).Set(*this, value);
}


void IDMEF::Set(const char *path, const char *value)
{
        IDMEFPath(path).Set(*this, value);
}


void IDMEF::Set(const char *path, int8_t value)
{
        IDMEFPath(path).Set(*this, value);
}


void IDMEF::Set(const char *path, uint8_t value)
{
        IDMEFPath(path).Set(*this, value);
}


void IDMEF::Set(const char *path, int16_t value)
{
        IDMEFPath(path).Set(*this, value);
}


void IDMEF::Set(const char *path, uint16_t value)
{
        IDMEFPath(path).Set(*this, value);
}


void IDMEF::Set(const char *path, int32_t value)
{
        IDMEFPath(path).Set(*this, value);
}


void IDMEF::Set(const char *path, uint32_t value)
{
        IDMEFPath(path).Set(*this, value);
}


void IDMEF::Set(const char *path, int64_t value)
{
        IDMEFPath(path).Set(*this, value);
}


void IDMEF::Set(const char *path, uint64_t value)
{
        IDMEFPath(path).Set(*this, value);
}


void IDMEF::Set(const char *path, float value)
{
        IDMEFPath(path).Set(*this, value);
}


void IDMEF::Set(const char *path, double value)
{
        IDMEFPath(path).Set(*this, value);
}


void IDMEF::Set(const char *path, IDMEFTime &value)
{
        IDMEFPath(path).Set(*this, value);
}


IDMEFValue IDMEF::Get(const char *path)
{
        return IDMEFPath(path).Get(*this);
}


IDMEF IDMEF::Clone(const IDMEF &idmef)
{
        int ret;
        idmef_message_t *clone;

        ret = idmef_message_clone(idmef._message, &clone);
        if ( ret < 0 )
                throw RequiemError(ret);

        return IDMEF(clone);
}


const std::string IDMEF::ToString() const
{
        int ret;
        std::string str;
        requiem_io_t *fd;

        ret = requiem_io_new(&fd);
        if ( ret < 0 )
                throw RequiemError(ret);

        requiem_io_set_buffer_io(fd);
        idmef_message_print(_message, fd);

        str.assign((const char *) requiem_io_get_fdptr(fd), requiem_io_pending(fd));

        requiem_io_close(fd);
        requiem_io_destroy(fd);

        return str;
}



static int ostream_write(requiem_msgbuf_t *fd, requiem_msg_t *msg)
{
        std::ostream *os = (std::ostream *) requiem_msgbuf_get_data(fd);

        os->write((const char *)requiem_msg_get_message_data(msg), requiem_msg_get_len(msg));
        requiem_msg_recycle(msg);

        return 0;
}


static ssize_t istream_read(requiem_io_t *fd, void *buf, size_t size)
{
        std::istream *is = (std::istream *) requiem_io_get_fdptr(fd);

        is->read((char *) buf, size);
        return is->gcount();
}



void IDMEF::_genericRead(ssize_t (read_cb)(requiem_io_t *fd, void *buf, size_t size), void *fd_data)
{
        int ret;
        requiem_io_t *fd;
        requiem_msg_t *msg = NULL;

        ret = requiem_io_new(&fd);
        if ( ret < 0 )
                throw RequiemError(ret);

        requiem_io_set_fdptr(fd, fd_data);
        requiem_io_set_read_callback(fd, read_cb);

        ret = requiem_msg_read(&msg, fd);
        requiem_io_destroy(fd);
        if ( ret < 0 )
                throw RequiemError(ret);

        ret = idmef_message_read(this->_message, msg);
        if ( ret < 0 ) {
                requiem_msg_destroy(msg);
                throw RequiemError(ret);
        }

        idmef_message_set_pmsg(this->_message, msg);
}


std::istream &operator >>(std::istream &is, Requiem::IDMEF &idmef)
{
        idmef._genericRead(istream_read, &is);
        return is;
}



size_t IDMEF::_genericWrite(int (write_cb)(requiem_msgbuf_t *msgbuf, requiem_msg_t *msg), void *fd_data) const
{
        int ret;
        requiem_msgbuf_t *fd;

        ret = requiem_msgbuf_new(&fd);
        if ( ret < 0 )
                throw RequiemError(ret);

        requiem_msgbuf_set_data(fd, fd_data);
        requiem_msgbuf_set_callback(fd, write_cb);

        ret = idmef_message_write(this->_message, fd);
        if ( ret < 0 ) {
                requiem_msgbuf_destroy(fd);
                throw RequiemError(ret);
        }

        requiem_msgbuf_destroy(fd);
        return ret;
}


std::ostream &operator <<(std::ostream &os, const IDMEF &idmef)
{
        idmef._genericWrite(ostream_write, &os);
        return os;
}


IDMEF::operator const std::string() const
{
        return ToString();
}


IDMEF::operator idmef_message_t *() const
{
        return _message;
}


IDMEF &IDMEF::operator = (const IDMEF &idmef)
{
        if ( this != &idmef && _message != idmef._message ) {
                if ( _message )
                        idmef_message_destroy(_message);

                _message = (idmef._message) ? idmef_message_ref(idmef._message) : NULL;
        }

        return *this;
}
