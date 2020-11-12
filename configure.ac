#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT([rexmpp], [0.0.0], [defanor@uberspace.net])
AM_INIT_AUTOMAKE([-Werror -Wall])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_SRCDIR([src/rexmpp.c])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_FILES([Makefile src/Makefile rexmpp.pc Doxyfile])

# Checks for programs.
AC_PROG_CC
AM_PROG_AR

LT_INIT

# Checks for libraries.
PKG_CHECK_MODULES([LIBXML], [libxml-2.0])
AC_SUBST(LIBXML_CFLAGS)
AC_SUBST(LIBXML_LIBS)

PKG_CHECK_MODULES([GNUTLS], [gnutls])
AC_SUBST(GNUTLS_CFLAGS)
AC_SUBST(GNUTLS_LIBS)

PKG_CHECK_MODULES([LIBDANE], [gnutls-dane])
AC_SUBST([LIBDANE_CFLAGS])
AC_SUBST([LIBDANE_LIBS])

PKG_CHECK_MODULES([GSASL], [libgsasl])
AC_SUBST(GSASL_CFLAGS)
AC_SUBST(GSASL_LIBS)

PKG_CHECK_MODULES([CARES], [libcares])
AC_SUBST(CARES_CFLAGS)
AC_SUBST(CARES_LIBS)


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
