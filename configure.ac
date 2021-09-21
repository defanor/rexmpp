#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT([rexmpp], [0.0.0], [defanor@uberspace.net])
AM_INIT_AUTOMAKE([-Werror -Wall])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_SRCDIR([src/rexmpp.c])
AC_CONFIG_HEADERS([src/config.h])
AC_CONFIG_FILES([Makefile src/Makefile rexmpp.pc Doxyfile])

# Checks for programs.
AC_PROG_CC
AM_PROG_AR

LT_INIT

# Checks for libraries and related parameters.

PKG_CHECK_MODULES([LIBXML], [libxml-2.0])

PKG_CHECK_MODULES([GSASL], [libgsasl])

PKG_CHECK_MODULES([NETTLE], [nettle])


# DNS: libunbound

AC_ARG_VAR([DNSSEC_TRUST_ANCHOR_FILE],
        [A DNSSEC trust anchor, containing DNSKEY in zone file format])
AS_IF([test "x$DNSSEC_TRUST_ANCHOR_FILE" == "x"],
      [DNSSEC_TRUST_ANCHOR_FILE="/usr/share/dns/root.key"])
AC_DEFINE_UNQUOTED([DNSSEC_TRUST_ANCHOR_FILE],
        "$DNSSEC_TRUST_ANCHOR_FILE",
        [A DNSSEC trust anchor, containing DNSKEY in zone file format])

PKG_CHECK_MODULES([UNBOUND], [libunbound])

# GPGME, optional

AC_ARG_WITH([gpgme],
        AS_HELP_STRING([--without-gpgme], [Don't use GPGME for OpenPGP]))
AS_IF([test "x$with_gpgme" != "xno"],
      [AM_PATH_GPGME([], [AC_DEFINE([HAVE_GPGME], [1], [GPGME is available])])])

# TLS: GnuTLS, OpenSSL, or none

AC_ARG_ENABLE([tls], AS_HELP_STRING([--disable-tls], [build without TLS support]))
AC_ARG_WITH([openssl],
        AS_HELP_STRING([--with-openssl], [use OpenSSL]))
AC_ARG_WITH([gnutls],
        AS_HELP_STRING([--with-gnutls], [use GnuTLS]))

AS_IF([test "x$with_gnutls" == "xyes"],
      [PKG_CHECK_MODULES([GNUTLS], [gnutls],
        [PKG_CHECK_MODULES([LIBDANE], [gnutls-dane],
          [AC_DEFINE([USE_GNUTLS], [1], [Use GnuTLS])])])],

      [test "x$with_openssl" == "xyes"],
      [PKG_CHECK_MODULES([OPENSSL], [openssl],
        [AC_DEFINE([USE_OPENSSL], [1], [Use OpenSSL])])],

      [test "x$enable_tls" != "xno"],
      [PKG_CHECK_MODULES([GNUTLS], [gnutls],
        [PKG_CHECK_MODULES([LIBDANE], [gnutls-dane],
          [AC_DEFINE([USE_GNUTLS], [1], [Use GnuTLS])],
          [PKG_CHECK_MODULES([OPENSSL], [openssl],
            [AC_DEFINE([USE_OPENSSL], [1], [Use OpenSSL])])])])])

# ICU, optional

AC_ARG_WITH([icu],
        AS_HELP_STRING([--without-icu], [don't use ICU for JID checks]))
AS_IF([test "x$with_icu" != "xno"],
      [PKG_CHECK_MODULES([ICU_I18N], [icu-i18n],
        AC_DEFINE([HAVE_ICU], [1], [icu-i18n is available]))])


# Checks for header files.
AC_CHECK_HEADERS([arpa/inet.h netdb.h netinet/in.h sys/socket.h syslog.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_TYPE_UINT32_T

# Checks for library functions.
AC_FUNC_MALLOC
AC_CHECK_FUNCS([gettimeofday select socket strchr strerror strtoul])

AC_OUTPUT
