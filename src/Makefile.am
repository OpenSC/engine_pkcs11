MAINTAINERCLEANFILES = \
	$(srcdir)/Makefile.in $(srcdir)/versioninfo.rc
EXTRA_DIST = Makefile.mak versioninfo.rc.in

engines_LTLIBRARIES = libpkcs11.la

OPENSSL_EXTRA_CFLAGS = \
	-DOPENSSL_THREADS -D_REENTRANT -DDSO_DLFCN -DHAVE_DLFCN_H \
	-DOPENSSL_NO_KRB5 -DL_ENDIAN -DTERMIO -DENGINE_DYNAMIC_SUPPORT \
	-DSHA1_ASM -DMD5_ASM -DRMD160_ASM

libpkcs11_la_SOURCES = \
	hw_pkcs11.c engine_pkcs11.c engine_pkcs11.h  \
	engine_pkcs11.exports
if WIN32
libpkcs11_la_SOURCES += versioninfo.rc
else
dist_noinst_DATA = versioninfo.rc
endif
libpkcs11_la_CFLAGS = $(AM_CFLAGS) $(OPENSSL_EXTRA_CFLAGS) $(OPENSSL_CFLAGS) \
	$(LIBP11_CFLAGS)
libpkcs11_la_LIBADD = $(ENGINE_LINK) $(OPENSSL_LIBS) $(LIBP11_LIBS)
libpkcs11_la_LDFLAGS = $(AM_LDFLAGS) $(OPENSSL_EXTRA_LDFLAGS) \
	-module -shared -avoid-version \
	-export-symbols "$(srcdir)/engine_pkcs11.exports" \
	-no-undefined

RCCOMPILE = $(RC) $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) \
	$(AM_CPPFLAGS) $(CPPFLAGS)
LTRCCOMPILE = $(LIBTOOL) --mode=compile --tag=RC $(RCCOMPILE)

.rc.lo:
	$(LTRCCOMPILE) -i "$<" -o "$@"

.rc.o:
	$(RCCOMPILE) -i "$<" -o "$@"

# vim: set noexpandtab:
