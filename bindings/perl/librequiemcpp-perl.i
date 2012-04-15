# Exception map
%typemap(throws) Requiem::RequiemError %{
        SWIG_exception(SWIG_RuntimeError, $1.what());
%};


# Conversion not allowed
%ignore *::operator =;
%ignore *::operator int() const;
%ignore *::operator long() const;
%ignore *::operator int32_t() const;
%ignore *::operator uint32_t() const;
%ignore *::operator int64_t() const;
%ignore *::operator uint64_t() const;
%ignore *::operator float() const;
%ignore *::operator double() const;
%ignore *::operator Requiem::IDMEFTime() const;
%ignore *::operator const std::string() const;
%ignore *::operator const char *() const;


%header %{
#define TARGET_LANGUAGE_OUTPUT_TYPE SV **
int IDMEFValue_to_SWIG(const IDMEFValue &result, TARGET_LANGUAGE_OUTPUT_TYPE ret);
%}

%fragment("IDMEFValueList_to_SWIG", "header") {
SV *IDMEFValueList_to_SWIG(const Requiem::IDMEFValue &value)
{
        int j = 0, ret;
        std::vector<Requiem::IDMEFValue> result = value;
        std::vector<Requiem::IDMEFValue>::const_iterator i;

        AV *myav;
        SV *svret, **svs = new SV*[result.size()];

        for ( i = result.begin(); i != result.end(); i++ ) {
                ret = IDMEFValue_to_SWIG(*i, &svs[j++]);
                if ( ret < 0 )
                        return NULL;
        }

        myav = av_make(result.size(), svs);
        delete[] svs;

        svret = newRV_noinc((SV*) myav);
        sv_2mortal(svret);

        return svret;
}
}

/* tell squid not to cast void * value */
%typemap(in) void *nocast_p {
        $1 = $input;
}

%fragment("TransitionFunc", "header") {
static SV *__requiem_log_func;
static gl_thread_t __initial_thread;


static void _cb_perl_log(int level, const char *str)
{
        if ( (gl_thread_t) gl_thread_self() != __initial_thread )
                return;

        dSP;
        ENTER;
        SAVETMPS;

        PUSHMARK(SP);
        XPUSHs(SWIG_From_int(level));
        XPUSHs(SWIG_FromCharPtr(str));
        PUTBACK;

        perl_call_sv(__requiem_log_func, G_VOID);

        FREETMPS;
        LEAVE;
}


static int _cb_perl_write(requiem_msgbuf_t *fd, requiem_msg_t *msg)
{
        int ret;
        PerlIO *io = (PerlIO *) requiem_msgbuf_get_data(fd);

        ret = PerlIO_write(io, (const char *) requiem_msg_get_message_data(msg), requiem_msg_get_len(msg));
        if ( ret != requiem_msg_get_len(msg) )
                return requiem_error_from_errno(errno);

        requiem_msg_recycle(msg);

        return 0;
}


static ssize_t _cb_perl_read(requiem_io_t *fd, void *buf, size_t size)
{
        int ret;
        PerlIO *io = (PerlIO *) requiem_io_get_fdptr(fd);

        ret = PerlIO_read(io, buf, size);
        if ( ret < 0 )
                ret = requiem_error_from_errno(errno);

        else if ( ret == 0 )
                ret = requiem_error(REQUIEM_ERROR_EOF);

        return ret;
}
};

%typemap(in, fragment="TransitionFunc") void (*log_cb)(int level, const char *log) {
        if ( __requiem_log_func )
                SvREFCNT_dec(__requiem_log_func);

        __requiem_log_func = $input;
        SvREFCNT_inc($input);

        $1 = _cb_perl_log;
};

%extend Requiem::IDMEF {
        void Write(void *nocast_p) {
                PerlIO *io = IoIFP(sv_2io((SV *) nocast_p));
                self->_genericWrite(_cb_perl_write, io);
        }

        void Read(void *nocast_p) {
                PerlIO *io = IoIFP(sv_2io((SV *) nocast_p));
                self->_genericRead(_cb_perl_read, io);
        }
}


%typemap(out, fragment="IDMEFValue_to_SWIG") Requiem::IDMEFValue {
        int ret;

        if ( $1.IsNull() ) {
                SvREFCNT_inc (& PL_sv_undef);
                $result = &PL_sv_undef;
        } else {
                SV *mysv;

                ret = IDMEFValue_to_SWIG($1, &mysv);
                if ( ret < 0 ) {
                        std::stringstream s;
                        s << "IDMEFValue typemap does not handle value of type '" << idmef_value_type_to_string($1.GetType()) << "'";
                        SWIG_exception_fail(SWIG_ValueError, s.str().c_str());
                }

                $result = mysv;
        }

        argvi++;
};


%init {
        STRLEN len;
        char **argv;
        int j, argc = 1, ret;
        AV *pargv = get_av("ARGV", FALSE);

        __initial_thread = (gl_thread_t) gl_thread_self();

        ret = av_len(pargv);
        if ( ret >= 0 )
                argc += ret + 1;

        if ( argc + 1 < 0 )
                throw RequiemError("Invalide argc length");

        argv = (char **) malloc((argc + 1) * sizeof(char *));
        if ( ! argv )
                throw RequiemError("Allocation failure");

        argv[0] = SvPV(get_sv("0", FALSE), len);

        for ( j = 0; j < ret + 1; j++ )
                argv[j + 1] = SvPV(*av_fetch(pargv, j, FALSE), len);

        argv[j + 1] = NULL;

        ret = requiem_init(&argc, argv);
        if ( ret < 0 ) {
                free(argv);
                throw RequiemError(ret);
        }

        free(argv);
}
