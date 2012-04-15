AM_CPPFLAGS = @PCFLAGS@ -I$(top_builddir)/src/include -I$(top_srcdir)/src/include -I$(top_builddir)/libmissing -I$(top_srcdir)/libmissing -I$(top_builddir)/src/librequiem-error @LIBREQUIEM_CFLAGS@ @LIBGNUTLS_CFLAGS@ @REQUIEM_ADMIN_CFLAGS@ 

bin_PROGRAMS = requiem-admin
bin_SCRIPTS = requiem-adduser

requiem_admin_LDADD = $(top_builddir)/src/config-engine.lo \
			$(top_builddir)/src/variable.lo \
		        $(top_builddir)/src/librequiem.la \
			@REQUIEM_ADMIN_LIBS@ \
			../libmissing/libmissing.la $(GETADDRINFO_LIB) $(HOSTENT_LIB) $(LTLIBINTL) $(LTLIBTHREAD) $(SERVENT_LIB)


requiem_admin_SOURCES = 		\
	requiem-admin.c		\
	server.c			\
	tls-register.c			

noinst_HEADERS = tls-register.h server.h

-include $(top_srcdir)/git.mk
