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

# Checks for libraries.
PKG_CHECK_MODULES([LIBXML], [libxml-2.0])

AC_ARG_ENABLE([tls], AS_HELP_STRING([--disable-tls], [build without TLS support]))
AC_ARG_WITH([openssl],
        AS_HELP_STRING([--with-openssl], [Use OpenSSL]))
AC_ARG_WITH([gnutls],
        AS_HELP_STRING([--with-gnutls], [Use GnuTLS]))

AS_IF([test "x$with_gnutls" == "xyes"],
      [PKG_CHECK_MODULES([GNUTLS], [gnutls],
        [PKG_CHECK_MODULES([LIBDANE], [gnutls-dane],
          [AC_DEFINE([USE_GNUTLS], [1], [Use GnuTLS])])])],

      [test "x$with_openssl" == "xyes"],
      [PKG_CHECK_MODULES([OPENSSL], [openssl],
        [AC_DEFINE([USE_OPENSSL], [1], [Use OpenSSL])])],

      # Default to GnuTLS for now (check for OpenSSL if not found
      # later).
      [test "x$enable_tls" != "xno"],
      [PKG_CHECK_MODULES([GNUTLS], [gnutls],
        [PKG_CHECK_MODULES([LIBDANE], [gnutls-dane],
          [AC_DEFINE([USE_GNUTLS], [1], [Use GnuTLS])],
          [PKG_CHECK_MODULES([OPENSSL], [openssl],
            [AC_DEFINE([USE_OPENSSL], [1], [Use OpenSSL])])])])])


PKG_CHECK_MODULES([GSASL], [libgsasl])

PKG_CHECK_MODULES([UNBOUND], [libunbound])

AM_PATH_GPGME

PKG_CHECK_MODULES([ICU_I18N], [icu-i18n])

PKG_CHECK_MODULES([NETTLE], [nettle])


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
