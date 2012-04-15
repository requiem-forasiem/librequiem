if HAVE_EASY_BINDINGS
if HAVE_RUBY

EXTRA_DIST = librequiemcpp-ruby.i RequiemEasy.cxx

rbexec_LTLIBRARIES = RequiemEasy.la
RequiemEasy_la_CPPFLAGS = $(RUBY_INCLUDES) $(RUBY_CCFLAGS) -I@top_builddir@ -I$(top_srcdir)/src/include -I$(top_builddir)/src/include -I@top_builddir@/src/librequiem-error -I$(top_srcdir)/bindings/c++/include -I@top_srcdir@/libmissing -I@top_builddir@/libmissing
RequiemEasy_la_LDFLAGS = -module -avoid-version
RequiemEasy_la_LIBADD = $(top_builddir)/bindings/c++/.libs/librequiemcpp.la $(RUBY_LIBS)
nodist_RequiemEasy_la_SOURCES = RequiemEasy.cxx

RequiemEasy.cxx: $(top_srcdir)/bindings/c++/include/*.hxx $(top_srcdir)/bindings/librequiemcpp.i librequiemcpp-ruby.i 
if HAVE_SWIG
	$(SWIG) -c++ -I$(top_srcdir)/bindings -I$(top_srcdir)/bindings/c++/include -I$(top_srcdir)/src/include -I$(top_srcdir)/src/librequiem-error -ruby -o $@ $(top_srcdir)/bindings/librequiemcpp.i
endif

endif
endif

-include $(top_srcdir)/git.mk
