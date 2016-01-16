
AC_PREREQ(2.60)

define([PACKAGE_VERSION_MAJOR], [0])
define([PACKAGE_VERSION_MINOR], [2])
define([PACKAGE_VERSION_FIX], [1])
define([PACKAGE_SUFFIX], [_git])

AC_INIT([engine_pkcs11],[PACKAGE_VERSION_MAJOR.PACKAGE_VERSION_MINOR.PACKAGE_VERSION_FIX[]PACKAGE_SUFFIX])
AC_CONFIG_AUX_DIR([.])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIR([m4])
AM_INIT_AUTOMAKE

ENGINE_PKCS11_VERSION_MAJOR="PACKAGE_VERSION_MAJOR"
ENGINE_PKCS11_VERSION_MINOR="PACKAGE_VERSION_MINOR"
ENGINE_PKCS11_VERSION_FIX="PACKAGE_VERSION_FIX"

AC_CONFIG_SRCDIR([src/engine_pkcs11.c])

AC_CANONICAL_HOST
AC_PROG_CC
PKG_PROG_PKG_CONFIG
AC_C_BIGENDIAN

AC_ARG_WITH(
	[cygwin-native],
	[AS_HELP_STRING([--with-cygwin-native],[compile native win32])],
	,
	[with_cygwin_native="no"]
)

dnl Check for some target-specific stuff
test -z "${WIN32}" && WIN32="no"
test -z "${CYGWIN}" && CYGWIN="no"
case "${host}" in
	*-mingw*|*-winnt*)
		WIN32="yes"
		CPPFLAGS="${CPPFLAGS} -DWIN32_LEAN_AND_MEAN"
		WIN_LIBPREFIX="lib"
	;;
	*-cygwin*)
		AC_MSG_CHECKING([cygwin mode to use])
		CYGWIN="yes"
		if test "${with_cygwin_native}" = "yes"; then
			AC_MSG_RESULT([Using native win32])
			CPPFLAGS="${CPPFLAGS} -DWIN32_LEAN_AND_MEAN"
			CFLAGS="${CFLAGS} -mno-cygwin"
			WIN32="yes"
		else
			AC_MSG_RESULT([Using cygwin])
			CPPFLAGS="${CPPFLAGS} -DCRYPTOKI_FORCE_WIN32"
			WIN_LIBPREFIX="cyg"
			AC_DEFINE([USE_CYGWIN], [1], [Define if you are on Cygwin])
		fi
	;;
esac

AC_ARG_ENABLE(
	[strict],
	[AS_HELP_STRING([--enable-strict],[enable strict compile mode @<:@disabled@:>@])],
	,
	[enable_strict="no"]
)

AC_ARG_ENABLE(
	[pedantic],
	[AS_HELP_STRING([--enable-pedantic],[enable pedantic compile mode @<:@disabled@:>@])],
	,
	[enable_pedantic="no"]
)

AC_ARG_WITH(
	[enginesdir],
	[AS_HELP_STRING([--with-enginesdir], [OpenSSL engines directory])],
	[enginesdir="${withval}"],
	[libcryptodir="`$PKG_CONFIG --variable=libdir --silence-errors libcrypto || \
		$PKG_CONFIG --variable=libdir openssl`"
	case "`$PKG_CONFIG --modversion --silence-errors libcrypto || \
		$PKG_CONFIG --modversion openssl`" in
	1.1.*) # Predicted engines directory prefix for OpenSSL 1.1.x
		debian_ssl_prefix="openssl-1.1.0";;
	1.0.*) # Engines directory prefix for OpenSSL 1.0.x
		debian_ssl_prefix="openssl-1.0.0";;
	*) # Engines directory prefix for OpenSSL 0.9.x
		debian_ssl_prefix="ssl";;
	esac
	if test -d "$libcryptodir/$debian_ssl_prefix/engines"; then
		# Debian-based OpenSSL package (for example Ubuntu)
		enginesdir="$libcryptodir/$debian_ssl_prefix/engines"
	else # Default OpenSSL engines directory
		enginesdir="$libcryptodir/engines"
	fi]
)

AC_ARG_WITH(
	[pkcs11-module],
	[AS_HELP_STRING([--with-pkcs11-module], [default PKCS11 module])],
	[pkcs11_module="${withval}"],
	[pkcs11_module="`$PKG_CONFIG --variable=proxy_module --silence-errors p11-kit-1`"])

dnl Checks for programs.
AC_PROG_CPP
AC_PROG_INSTALL
AC_PROG_LN_S
AC_PROG_MKDIR_P
AC_PROG_SED
AC_PROG_MAKE_SET

dnl Add libtool support.
ifdef(
	[LT_INIT],
	[
		LT_INIT([win32-dll])
		LT_LANG([Windows Resource])
	],
	[
		AC_LIBTOOL_WIN32_DLL
		AC_LIBTOOL_RC
		AC_PROG_LIBTOOL
	]
)

dnl Checks for header files.
AC_HEADER_STDC
AC_HEADER_SYS_WAIT
AC_CHECK_HEADERS([ \
	errno.h fcntl.h malloc.h stdlib.h inttypes.h \
	string.h strings.h sys/time.h unistd.h \
	locale.h getopt.h dlfcn.h utmp.h \
])

PKG_CHECK_MODULES([LIBP11], [libp11 >= 0.3.1],, [AC_MSG_ERROR([libp11 >= 0.3.1 is required])])

saved_LIBS=$LIBS
LIBS="$LIBP11_LIBS"
AC_CHECK_LIB(p11, PKCS11_ecdsa_method_free, [], [
AC_DEFINE([OPENSSL_NO_ECDSA], [], [ECDSA support was not detected in libp11])
])
LIBS=$saved_LIBS

# The "libcrypto" module is not defined in OpenSSL 0.9.7
# TODO: Deprecate OpenSSL 0.9.7 and stop checking for the "openssl" module
PKG_CHECK_MODULES(
	[OPENSSL],
	[libcrypto >= 0.9.7],
	,
	[PKG_CHECK_MODULES(
		[OPENSSL],
		[openssl >= 0.9.7],
		,
		[AC_CHECK_LIB(
			[crypto],
			[RSA_version],
			[OPENSSL_LIBS="-lcrypto"],
			[AC_MSG_ERROR([Cannot find OpenSSL])]
		)]
	)]
)

# TODO: Deprecate OpenSSL 0.9.7 and get rid of this mess

AC_MSG_CHECKING([for openssl version])
saved_CPPFLAGS="${CPPFLAGS}"
CPPFLAGS="${CPPFLAGS} ${OPENSSL_CFLAGS}"
AC_EGREP_CPP(
	[new],
	[
#include <openssl/opensslv.h>
#if OPENSSL_VERSION_NUMBER >= 0x0090704fL
new
#else
old
#endif
	],
	[
		AC_MSG_RESULT([good, 0.9.7d or later])
		old_openssl="no"
	],
	[
		AC_MSG_RESULT([not so good, 0.9.7d or later would be better])
		old_openssl="yes"
	]
)
CPPFLAGS="${saved_CPPFLAGS}"

if test "x$old_openssl" = "xyes"; then
	# openssl found, but version less than 0.9.7d
	# linking libcrypto.a statically possible?

	saved_CFLAGS="${CFLAGS}"
	saved_LIBS="${LIBS}"
	CFLAGS="${CFLAGS} ${OPENSSL_CFLAGS}"
	if echo "${OPENSSL_LIBS}" | grep -- "-L" > /dev/null; then
		OPENSSL_DIR="$(echo "${OPENSSL_LIBS}" | ${SED} 's/.*-L\([^ ]*\).*/\1/')"
	else
		OPENSSL_DIR="${usrlibdir}"
	fi
	LIBS="${LIBS} ${OPENSSL_DIR}/libcrypto.a"
	AC_CHECK_LIB(
		[dl],
		[dlopen]
	)
	AC_MSG_CHECKING([should link static openssl])
	AC_LINK_IFELSE(
		[AC_LANG_PROGRAM([[
#include <string.h>
#include <openssl/opensslv.h>
#include <openssl/engine.h>
#include <openssl/rand.h>
int test(void)
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
		]])],
		[
			AC_MSG_RESULT([yes])
			ENGINE_LINK="${OPENSSL_DIR}/libcrypto.a"
		],
		[AC_MSG_ERROR([OpenSSL is old and cannot link with its static library])]
	)
	CFLAGS="${saved_CFLAGS}"
	LIBS="${saved_LIBS}"
fi

#@alonbl: This was never actually used.
#
# now - last part to do: check if we gain anything from
# funny parameters to link openssl with.
#saved_LDFLAGS="${LDFLAGS}"
#for test_flags in "-Wl,-Bsymbolic" "-G -Wl,-Bsymbolic" "-Wl,-all_load"; do
#	AC_MSG_CHECKING([whether we can use ${test_flags}])
#	LDFLAGS="${saved_LDFLAGS} ${test_flags}"
#	AC_LINK_IFELSE(
#		[AC_LANG_PROGRAM([[
#int test()
#{
#	return 1;
#}
#		]])],
#		[result="yes"],
#		[result="no"]
#	)
#	AC_MSG_RESULT([${result}])
#	if test "${result}" = "yes"; then
#		OPENSSL_EXTRA_LDFLAGS="${test_flags}"
#		break;
#	fi
#done
#LDFLAGS="${saved_LDFLAGS}"

if test -n "${pkcs11_module}"; then
	AC_DEFINE_UNQUOTED(
		[DEFAULT_PKCS11_MODULE],
		"${pkcs11_module}",
		[PKCS11 module])
fi
AC_SUBST([enginesdir])
AC_SUBST([ENGINE_LINK])
AC_SUBST([ENGINE_PKCS11_VERSION_MAJOR])
AC_SUBST([ENGINE_PKCS11_VERSION_MINOR])
AC_SUBST([ENGINE_PKCS11_VERSION_FIX])
AC_SUBST([WIN_LIBPREFIX])
AC_SUBST([OPENSSL_EXTRA_LDFLAGS])

AM_CONDITIONAL([WIN32], [test "${WIN32}" = "yes"])
AM_CONDITIONAL([CYGWIN], [test "${CYGWIN}" = "yes"])

if test "${enable_pedantic}" = "yes"; then
	enable_strict="yes";
	CFLAGS="${CFLAGS} -pedantic"
fi
if test "${enable_strict}" = "yes"; then
	CFLAGS="${CFLAGS} -Wall -Wextra"
fi

AC_CONFIG_FILES([
	Makefile
	src/Makefile
	src/versioninfo.rc
	tests/Makefile
])
AC_OUTPUT

cat <<EOF

engine_pkcs11 has been configured with the following options:


Version:                 ${PACKAGE_VERSION}
Libraries:               $(eval eval eval echo "${libdir}")

Host:                    ${host}
Compiler:                ${CC}
Preprocessor flags:      ${CPPFLAGS}
Compiler flags:          ${CFLAGS}
Linker flags:            ${LDFLAGS}
Libraries:               ${LIBS}

enginesdir               ${enginesdir}
DEFAULT_PKCS11_MODULE    ${pkcs11_module}

LIBP11_CFLAGS:           ${LIBP11_CFLAGS}
LIBP11_LIBS:             ${LIBP11_LIBS}
OPENSSL_CFLAGS:          ${OPENSSL_CFLAGS}
OPENSSL_LIBS:            ${OPENSSL_LIBS}
OPENSSL_EXTRA_LDFLAGS:   ${OPENSSL_EXTRA_LDFLAGS}
ENGINE_LINK:             ${ENGINE_LINK}

EOF

# vim: set noexpandtab:
