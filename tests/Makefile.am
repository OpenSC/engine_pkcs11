EXTRA_DIST = cert.der key.der common.sh engines.cnf.in

AM_CFLAGS = $(OPENSSL_CFLAGS)
AM_CPPFLAGS = \
	-I$(top_srcdir)/ \
	-I$(top_builddir)/

AM_LDFLAGS = -no-install
LDADD = $(OPENSSL_LIBS)

evp_sign_SOURCES = evp-sign.c

check_PROGRAMS = evp-sign
dist_check_SCRIPTS = softhsm

TESTS = $(dist_check_SCRIPTS)

TESTS_ENVIRONMENT =						\
	LC_ALL="C"						\
	EXEEXT=$(EXEEXT)					\
	top_builddir="$(top_builddir)"				\
	srcdir="$(srcdir)"

