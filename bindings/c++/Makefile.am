if HAVE_EASY_BINDINGS

SUBDIRS = include

lib_LTLIBRARIES = librequiemcpp.la
librequiemcpp_ladir = ${prefix}/lib
librequiemcpp_la_SOURCES = \
	requiem-error.cxx \
	idmef.cxx \
	idmef-criteria.cxx \
	idmef-path.cxx \
	idmef-time.cxx \
	idmef-value.cxx \
	requiem.cxx	\
	requiem-client.cxx \
	requiem-client-easy.cxx \
	requiem-client-profile.cxx \
	requiem-connection.cxx	\
	requiem-connection-pool.cxx \
	requiem-log.cxx

librequiemcpp_la_LDFLAGS = -no-undefined -version-info @LIBREQUIEMCPP_SONAME@
librequiemcpp_la_LIBADD  = $(top_builddir)/src/.libs/librequiem.la
librequiemcpp_la_CPPFLAGS = -I$(top_builddir) -I$(top_builddir)/src/include -I$(top_srcdir)/src/include -I$(top_builddir)/src/librequiem-error -I$(top_builddir)/bindings/c++/include -I$(top_srcdir)/bindings/c++/include 

endif

-include $(top_srcdir)/git.mk
