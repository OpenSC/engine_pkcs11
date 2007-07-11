dnl -*- mode: m4; -*-
dnl Process this file with autoconf to produce a configure script.

# Require autoconf 2.52
AC_PREREQ(2.52)

AC_INIT(engine_pkcs11, [0.1.4-svn])

AM_INIT_AUTOMAKE
AM_CONFIG_HEADER(config.h)

AC_CONFIG_SRCDIR(src/engine_pkcs11.c)


AC_CANONICAL_HOST
AC_PROG_CC
AC_C_BIGENDIAN

dnl Options
AM_MAINTAINER_MODE

dnl Checks for programs.
AC_PROG_CPP
AC_PROG_INSTALL
AC_PROG_LN_S
AC_PROG_MAKE_SET

dnl Add libtool support.
AM_PROG_LIBTOOL
dnl Automatically update the libtool script if it becomes out-of-date.
#AC_SUBST(LIBTOOL_DEPS)

dnl Checks for header files.
AC_HEADER_STDC
AC_HEADER_SYS_WAIT
AC_CHECK_HEADERS([errno.h fcntl.h malloc.h stdlib.h inttypes.h string.h strings.h sys/time.h unistd.h locale.h getopt.h dlfcn.h utmp.h])

PKG_CHECK_MODULES([LIBP11], [libp11 >= 0.2.1])

dnl The big mess with OpenSSL
saved_LIBS="$LIBS"
saved_LDFLAGS="$LDFLAGS"
saved_CPPFLAGS="$CPPFLAGS"

SSL_MSG="no"
ssldir=""

AC_ARG_WITH(openssl,
	AC_HELP_STRING([--with-openssl=PATH], [use OpenSSL in PATH]),
	[
		# Disable OpenSSL support
		if test "x$withval" = "xno" ; then
			SSL_MSG="no (disabled)"
			break;
		fi

		# ok we got a directory, so only check in that dir.
		LIBCRYPTO="-lcrypto"
		CPPFLAGS="$saved_CPPFLAGS"
		LDFLAGS="$saved_LDFLAGS"
		LIBS="$LIBCRYPTO $saved_LIBS"
		LDFLAGS="-L$withval/lib $saved_LDFLAGS"
		if test ! -z "$need_dash_r" ; then
			LDFLAGS="-R$withval/lib $LDFLAGS"
		fi
		CPPFLAGS="-I$withval/include $saved_CPPFLAGS"

		AC_TRY_RUN(
			[
#include <string.h>
#include <openssl/rand.h>
int main(void)
{
	char a[2048];
	memset(a, 0, sizeof(a));
	RAND_add(a, sizeof(a), sizeof(a));
	return(RAND_status() <= 0);
}
			],
			[
				SSL_MSG="yes"
				ssldir="$withval"
				break
			])
			],[

	# we didn't get a directory, so we start searching for openssl
	for tryssldir in $commondir /usr /usr/local/openssl /usr/lib/openssl /usr/local/ssl /usr/lib/ssl /usr/local /usr/pkg /opt /opt/openssl; do
		# Skip directories if they don't exist
		if test ! -d "$tryssldir/" ; then
			continue;
		fi

		LIBCRYPTO="-lcrypto"
		CPPFLAGS="$saved_CPPFLAGS"
		LDFLAGS="$saved_LDFLAGS"
		LIBS="$saved_LIBS $LIBCRYPTO"

		if test "x$tryssldir" != "x/usr"; then
			LDFLAGS="-L$tryssldir/lib $saved_LDFLAGS"
			if test ! -z "$need_dash_r" ; then
				LDFLAGS="-R$tryssldir/lib $LDFLAGS"
			fi
			CPPFLAGS="-I$tryssldir/include $saved_CPPFLAGS"
		fi

		# Basic test to check for compatible version and correct linking
		# *does not* test for RSA - that comes later.
		AC_TRY_RUN(
			[
#include <string.h>
#include <openssl/rand.h>
int main(void)
{
	char a[2048];
	memset(a, 0, sizeof(a));
	RAND_add(a, sizeof(a), sizeof(a));
	return(RAND_status() <= 0);
}
			],
			[
				SSL_MSG="yes"
				ssldir=$tryssldir
				break;
			],
			[
				SSL_MSG="no"
				LIBS="$saved_LIBS"
				LDFLAGS="$saved_LDFLAGS"
				CPPFLAGS="$saved_CPPFLAGS"
			])
	done
	])
LIBS="$saved_LIBS"
AC_SUBST(LIBCRYPTO)
AM_CONDITIONAL(HAVE_SSL, test "x$SSL_MSG" = "xyes")

if test "x$SSL_MSG" = "xyes" ; then
  AC_DEFINE(HAVE_OPENSSL, 1, [Have OpenSSL libraries])
else
  LIBCRYPTO=""
fi

# ok, we checked for basic ssl support.
# if it is not available, we can skip the rest of
# the test. also we have $ssldir set to the location
# of the openssl libs.

ENGINE_MSG="no"
if test "x$SSL_MSG" = "xyes"; then
	# engine has to be there and working
	LIBS="$saved_LIBS $LIBCRYPTO $LIBDL"
	AC_TRY_RUN(
	[
#include <string.h>
#include <openssl/opensslv.h>
#include <openssl/engine.h>
#include <openssl/rand.h>
int main(void)
{
	char a[2048];
	ENGINE *e;

	e = ENGINE_new();
	ENGINE_load_dynamic();
	if (!e) return 1;
	memset(a, 0, sizeof(a));
	RAND_add(a, sizeof(a), sizeof(a));
	return(RAND_status() <= 0);
}
	],
	[
		ENGINE_MSG=yes
		ENGINE_LINK="$LIBCRYPTO"
	],
	[
		ENGINE_MSG=no
	])
fi
LIBS="$saved_LIBS"
AC_SUBST(ENGINE_LINK)
AM_CONDITIONAL(HAVE_ENGINE, test "x$ENGINE_MSG" = "xyes")

# ok, now we might (or not) have ssl and an engine.
# still room for "improvements", i.e. hacks to work
# with old engines.

SSLHACK_MSG=no
if test "x$SSL_MSG" = "xyes" -a "x$ENGINE_MSG" = "xyes"; then
	# latest openssl version with engine
	# properly integrated?
	AC_MSG_CHECKING([for openssl version])
	AC_TRY_RUN(
	[
#include <stdlib.h>
#include <string.h>
#include <openssl/opensslv.h>

int main(void)
{
	if(OPENSSL_VERSION_NUMBER >= 0x0090704fL) {
		exit(0);
	} else {
		exit(1);
	}
}
	],
	[
		AC_MSG_RESULT([good, 0.9.7d or later])
		OLD_OPENSSL=no
	],
	[
		AC_MSG_RESULT([not so good, 0.9.7d or later would be better])
		OLD_OPENSSL=yes
	])

	if test "x$OLD_OPENSSL" = "xyes"; then
		# openssl found, but version less than 0.9.7d
		# linking libcrypto.a statically possible?

		LIBS="$saved_LIBS $ssldir/lib/libcrypto.a $LIBDL"
		AC_TRY_RUN(
		[
#include <string.h>
#include <openssl/opensslv.h>
#include <openssl/engine.h>
#include <openssl/rand.h>
int main(void)
{
	char a[2048];
	ENGINE *e;

	e = ENGINE_new();
	ENGINE_load_dynamic();
	if (!e) return 1;
	memset(a, 0, sizeof(a));
	RAND_add(a, sizeof(a), sizeof(a));
	return(RAND_status() <= 0);
}
		],
		[
			SSLHACK_MSG=yes
			ENGINE_LINK="$ssldir/lib/libcrypto.a"
		])
		LIBS="$saved_LIBS"
	fi
fi

# now - last part to do: check if we gain anything from
# funny parameters to link openssl with.

saved_LDFLAGS="$LDFLAGS"
if test "x$ENGINE_MSG" = "xyes" ; then
  for openssl_ldflag in "-Wl,-Bsymbolic" "-G -Wl,-Bsymbolic" "-shared -G -Wl,-Bsymbolic" "-Wl,-all_load"; do
	AC_MSG_CHECKING([whether we can use $openssl_ldflag])
	LDFLAGS="$saved_LDFLAGS $openssl_ldflag"
	AC_TRY_LINK(,[return 1],ac_cv_use_openssl_flag="yes",ac_cv_use_openssl_flag="no")
	AC_MSG_RESULT($ac_cv_use_openssl_flag)
	if test "$ac_cv_use_openssl_flag" = "yes"; then
		OPENSSL_LDFLAGS="$openssl_ldflag"
		break;
	fi
  done
fi
LDFLAGS="$saved_LDFLAGS"
AC_SUBST(OPENSSL_LDFLAGS)

AC_OUTPUT([
Makefile
aclocal/Makefile
doc/Makefile
src/Makefile
])

echo ""
echo "Engine_pkcs11 has been configured with the following options"

echo ""
echo "OpenSSL support:          ${SSL_MSG}"
echo "        with engine:      ${ENGINE_MSG}"
echo "        with sslhack:     ${SSLHACK_MSG}"
echo ""
