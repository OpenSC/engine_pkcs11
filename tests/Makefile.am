EXTRA_DIST = common.sh engines.cnf.in

AM_CFLAGS = $(OPENSSL_CFLAGS)
AM_CPPFLAGS = \
	-I$(top_srcdir)/ \
	-I$(top_builddir)/

AM_LDFLAGS = -no-install
LDADD = $(OPENSSL_LIBS)

evp_sign_SOURCES = evp-sign.c

check_PROGRAMS = evp-sign
dist_check_SCRIPTS = softhsm
dist_check_DATA = cert.der key.der pubkey.der

TESTS = $(dist_check_SCRIPTS)

TESTS_ENVIRONMENT =						\
	LC_ALL="C"						\
	EXEEXT=$(EXEEXT)					\
	top_builddir="$(top_builddir)"				\
	srcdir="$(srcdir)"

# vim: set noexpandtab:
