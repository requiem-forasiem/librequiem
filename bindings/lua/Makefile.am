if HAVE_EASY_BINDINGS

EXTRA_DIST = librequiemcpp-lua.i RequiemEasy.cxx

if HAVE_LUA

AM_CPPFLAGS = -I@top_srcdir@ -I@top_builddir@/src/include -I@top_srcdir@/src/include -I@top_builddir@/src/librequiem-error -I@top_srcdir@/bindings/c++/include @LUA_CFLAGS@ -I@top_srcdir@/libmissing -I@top_builddir@/libmissing

RequiemEasy_la_LDFLAGS = -module -avoid-version @LUA_LIBS@
RequiemEasy_la_LIBADD = $(top_builddir)/bindings/c++/.libs/librequiemcpp.la
RequiemEasy_la_SOURCES = RequiemEasy.cxx
RequiemEasydir = $(libdir)
RequiemEasy_LTLIBRARIES = RequiemEasy.la

RequiemEasy.cxx: $(top_srcdir)/bindings/c++/include/*.hxx $(top_srcdir)/bindings/librequiemcpp.i librequiemcpp-lua.i 
if HAVE_SWIG
	$(SWIG) -c++ -I$(top_srcdir)/bindings -I$(top_srcdir)/bindings/c++/include -I$(top_srcdir)/src/include -I$(top_srcdir)/src/librequiem-error -lua -o $@ librequiemcpp.i
endif


endif

endif

-include $(top_srcdir)/git.mk
