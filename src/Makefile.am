MAINTAINERCLEANFILES = $(srcdir)/Makefile.in
EXTRA_DIST = Makefile.mak engine_pkcs11.def 

engines_LTLIBRARIES = engine_pkcs11.la

OPENSSL_EXTRA_CFLAGS = \
	-DOPENSSL_THREADS -D_REENTRANT -DDSO_DLFCN -DHAVE_DLFCN_H \
	-DOPENSSL_NO_KRB5 -DL_ENDIAN -DTERMIO -DENGINE_DYNAMIC_SUPPORT \
	-DSHA1_ASM -DMD5_ASM -DRMD160_ASM

engine_pkcs11_la_SOURCES = \
	hw_pkcs11.c engine_pkcs11.c engine_pkcs11.h  \
	engine_pkcs11.exports
if WIN32
nodist_engine_pkcs11_la_SOURCES = versioninfo.rc
endif
engine_pkcs11_la_CFLAGS = $(AM_CFLAGS) $(OPENSSL_EXTRA_CFLAGS) $(OPENSSL_CFLAGS) \
	$(LIBP11_CFLAGS)
engine_pkcs11_la_LIBADD = $(ENGINE_LINK) $(OPENSSL_LIBS) $(LIBP11_LIBS)
engine_pkcs11_la_LDFLAGS = $(AM_LDFLAGS) $(OPENSSL_EXTRA_LDFLAGS) \
	-module -avoid-version \
	-export-symbols "$(srcdir)/engine_pkcs11.exports" \
	-no-undefined

install-data-hook:
	rm -f "$(DESTDIR)$(enginesdir)/engine_pkcs11.la"
	rm -f "$(DESTDIR)$(enginesdir)/engine_pkcs11.a"
	rm -f "$(DESTDIR)$(enginesdir)/engine_pkcs11.dll.a"

RCCOMPILE = $(RC) $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) \
	$(AM_CPPFLAGS) $(CPPFLAGS)
LTRCCOMPILE = $(LIBTOOL) --mode=compile --tag=RC $(RCCOMPILE)

.rc.lo:
	$(LTRCCOMPILE) -i "$<" -o "$@"

.rc.o:
	$(RCCOMPILE) -i "$<" -o "$@"

