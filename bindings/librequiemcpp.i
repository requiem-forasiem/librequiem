%module RequiemEasy

%include "std_string.i"
%include "std_vector.i"
%include "exception.i"

%{
#include <list>
#include <sstream>

#ifndef SWIGPYTHON
# include "config.h"
# include "glthread/thread.h"
#endif

#include "requiem.hxx"
#include "requiem-log.hxx"
#include "requiem-error.hxx"
#include "requiem-connection.hxx"
#include "requiem-connection-pool.hxx"
#include "requiem-client-profile.hxx"
#include "requiem-client.hxx"
#include "requiem-client-easy.hxx"
#include "idmef-criteria.hxx"
#include "idmef-value.hxx"
#include "idmef-path.hxx"
#include "idmef-time.hxx"
#include "idmef.hxx"

using namespace Requiem;
%}


typedef char int8_t;
typedef unsigned char uint8_t;

typedef short int16_t;
typedef unsigned short uint16_t;

typedef int int32_t;
typedef unsigned int uint32_t;

typedef long long int64_t;
typedef unsigned long long uint64_t;

%ignore requiem_error_t;
typedef signed int requiem_error_t;


#ifdef SWIGPERL
%include perl/librequiemcpp-perl.i
#endif

#ifdef SWIGPYTHON
%include librequiemcpp-python.i
#endif

#ifdef SWIGRUBY
%include librequiemcpp-ruby.i
#endif

#ifdef SWIGLUA
%include librequiemcpp-lua.i
#endif

%catches(Requiem::RequiemError);

%ignore operator <<(std::ostream &os, const Requiem::IDMEF &idmef);
%ignore operator >>(std::istream &is, const Requiem::IDMEF &idmef);


%template() std::vector<std::string>;
%template() std::vector<Requiem::IDMEFValue>;
%template() std::vector<Requiem::Connection>;


%fragment("IDMEFValue_to_SWIG", "header", fragment="IDMEFValueList_to_SWIG", fragment="SWIG_From_float") {


int IDMEFValue_to_SWIG(const IDMEFValue &result, TARGET_LANGUAGE_OUTPUT_TYPE ret)
{
        std::stringstream s;
        idmef_value_t *value = result;
        idmef_value_type_id_t type = result.GetType();

        if ( type == IDMEF_VALUE_TYPE_STRING ) {
                requiem_string_t *str = idmef_value_get_string(value);
                *ret = SWIG_FromCharPtrAndSize(requiem_string_get_string(str), requiem_string_get_len(str));
        }

        else if ( type == IDMEF_VALUE_TYPE_INT8 )
                *ret = SWIG_From_int(idmef_value_get_int8(value));

        else if ( type == IDMEF_VALUE_TYPE_UINT8 )
                *ret = SWIG_From_unsigned_SS_int(idmef_value_get_uint8(value));

        else if ( type == IDMEF_VALUE_TYPE_INT16 )
                *ret = SWIG_From_int(idmef_value_get_int16(value));

        else if ( type == IDMEF_VALUE_TYPE_UINT16 )
                *ret = SWIG_From_unsigned_SS_int(idmef_value_get_uint16(value));

        else if ( type == IDMEF_VALUE_TYPE_INT32 )
                *ret = SWIG_From_int(idmef_value_get_int32(value));

        else if ( type == IDMEF_VALUE_TYPE_UINT32 )
                *ret = SWIG_From_unsigned_SS_int(idmef_value_get_uint32(value));

        else if ( type == IDMEF_VALUE_TYPE_INT64 )
                *ret = SWIG_From_long_SS_long(idmef_value_get_int64(value));

        else if ( type == IDMEF_VALUE_TYPE_UINT64 )
                *ret = SWIG_From_unsigned_SS_long_SS_long(idmef_value_get_uint64(value));

        else if ( type == IDMEF_VALUE_TYPE_FLOAT )
                *ret = SWIG_From_float(idmef_value_get_float(value));

        else if ( type == IDMEF_VALUE_TYPE_DOUBLE )
                *ret = SWIG_From_double(idmef_value_get_double(value));

        else if ( type == IDMEF_VALUE_TYPE_ENUM ) {
                const char *s = idmef_class_enum_to_string(idmef_value_get_class(value), idmef_value_get_enum(value));
                *ret = SWIG_FromCharPtr(s);
        }

        else if ( type == IDMEF_VALUE_TYPE_TIME ) {
                IDMEFTime time = result;
                *ret = SWIG_NewPointerObj(new IDMEFTime(time), SWIGTYPE_p_Requiem__IDMEFTime, 1);
        }

        else if ( type == IDMEF_VALUE_TYPE_LIST )
                *ret = IDMEFValueList_to_SWIG(result);

        else if ( type == IDMEF_VALUE_TYPE_DATA ) {
                idmef_data_t *d = idmef_value_get_data(value);
                idmef_data_type_t t = idmef_data_get_type(d);

                if ( t == IDMEF_DATA_TYPE_CHAR ||
                     t == IDMEF_DATA_TYPE_BYTE || t == IDMEF_DATA_TYPE_BYTE_STRING )
                        *ret = SWIG_FromCharPtrAndSize((const char *)idmef_data_get_data(d), idmef_data_get_len(d));

                else if ( t == IDMEF_DATA_TYPE_CHAR_STRING )
                        *ret = SWIG_FromCharPtrAndSize((const char *)idmef_data_get_data(d), idmef_data_get_len(d) - 1);

                else if ( t == IDMEF_DATA_TYPE_FLOAT )
                        *ret = SWIG_From_float(idmef_data_get_float(d));

                else if ( t == IDMEF_DATA_TYPE_UINT32 )
                        *ret = SWIG_From_unsigned_SS_int(idmef_data_get_uint32(d));

                else if ( t == IDMEF_DATA_TYPE_UINT64 )
                        *ret = SWIG_From_unsigned_SS_long_SS_long(idmef_data_get_uint64(d));
        }

        else if ( type == IDMEF_VALUE_TYPE_CLASS )
                *ret = SWIG_NewPointerObj(new IDMEFValue(idmef_value_ref(value)), SWIGTYPE_p_Requiem__IDMEFValue, 1);

        else return -1;

        return 0;
}
}

%ignore Requiem::IDMEFValue::operator int8_t() const;
%ignore Requiem::IDMEFValue::operator uint8_t() const;
%ignore Requiem::IDMEFValue::operator int16_t() const;
%ignore Requiem::IDMEFValue::operator uint16_t() const;
%ignore Requiem::IDMEFValue::operator int32_t() const;
%ignore Requiem::IDMEFValue::operator uint32_t() const;
%ignore Requiem::IDMEFValue::operator int64_t() const;
%ignore Requiem::IDMEFValue::operator uint64_t() const;
%ignore Requiem::IDMEFValue::operator float() const;
%ignore Requiem::IDMEFValue::operator double() const;
%ignore Requiem::IDMEFValue::operator const char*() const;
%ignore Requiem::IDMEFValue::operator std::vector<IDMEFValue>() const;
%ignore Requiem::IDMEFValue::operator Requiem::IDMEFTime() const;

/*
 * Force SWIG to use the IDMEFValue * version of the Set() function,
 * so that the user might provide NULL IDMEFValue.
 */
%ignore Requiem::IDMEF::Set(char const *, Requiem::IDMEFValue &value);
%ignore Requiem::IDMEFPath::Set(Requiem::IDMEF &, Requiem::IDMEFValue &);

%ignore idmef_path_t;
%ignore idmef_criteria_t;
%ignore requiem_client_t;
%ignore requiem_client_profile_t;
%ignore requiem_connection_t;
%ignore requiem_connection_pool_t;
%ignore operator requiem_connection_t *();
%ignore operator requiem_connection_pool_t *();
%ignore operator idmef_message_t *() const;
%ignore operator idmef_time_t *() const;
%ignore operator idmef_value_t *() const;
%ignore operator requiem_client_profile_t *() const;

%include requiem.hxx
%include requiem-log.hxx
%include requiem-error.hxx
%include requiem-connection.hxx
%include requiem-connection-pool.hxx
%include requiem-client-profile.hxx
%include requiem-client.hxx
%include requiem-client-easy.hxx
%include idmef-criteria.hxx
%include idmef-value.hxx
%include idmef-path.hxx
%include idmef-time.hxx
%include idmef.hxx
