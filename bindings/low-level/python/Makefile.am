if HAVE_PYTHON

EXTRA_DIST = librequiem-python.i requiem.py _requiem.c

all-am: python-build

python-build: _requiem.c
	CC="$(BINDINGS_CC)" $(PYTHON) setup.py build

install-exec-hook:
	$(PYTHON) setup.py install `test -n "$(DESTDIR)" && echo --root $(DESTDIR)`

uninstall-hook: 
	$(PYTHON) setup.py uninstall `test -n "$(DESTDIR)" && echo --root $(DESTDIR)`

clean-local:
	$(PYTHON) setup.py clean -a

_requiem.c: $(top_srcdir)/bindings/low-level/librequiem.i librequiem-python.i
if HAVE_SWIG
	$(SWIG) -I$(top_srcdir)/bindings -I$(top_srcdir)/src/include -I$(top_srcdir)/src/librequiem-error -o $@ -python -noproxy -interface _requiem -module _requiem $(top_srcdir)/bindings/low-level/librequiem.i
endif

endif

-include $(top_srcdir)/git.mk
