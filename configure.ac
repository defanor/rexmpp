#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT([rexmpp], [0.0.0], [defanor@uberspace.net])
AM_INIT_AUTOMAKE([-Werror -Wall])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_SRCDIR([src/rexmpp.c])
AC_CONFIG_HEADERS([src/config.h])
AC_CONFIG_FILES([Makefile src/Makefile tests/Makefile rexmpp.pc Doxyfile])

# Checks for programs.
AC_PROG_CC
AM_PROG_AR


# Checks for libraries and related parameters.

AC_ARG_WITH([rust],
        AS_HELP_STRING([--with-rust],
                [use available Rust implementations of modules]))
AC_ARG_WITH([expat],
        AS_HELP_STRING([--with-expat], [use libexpat instead of libxml2]))

AS_IF([test "x$with_rust" == "xyes"],
      [AC_PATH_PROG([RUSTC], [rustc], [notfound])
       AS_IF([test "x$RUSTC" == "xnotfound"], [AC_MSG_ERROR([rustc is required])])
       AC_PATH_PROG([CARGO], [cargo], [notfound])
       AS_IF([test "x$CARGO" == "xnotfound"], [AC_MSG_ERROR([cargo is required])])
       AC_DEFINE([USE_RUST], [1], [Use Rust sources over C ones])],
      [AS_IF([test "x$with_expat" == "xyes"],
         [PKG_CHECK_MODULES([EXPAT], [expat],
           [AC_DEFINE([USE_EXPAT], [1], [Use libexpat])])],
         [PKG_CHECK_MODULES([LIBXML2], [libxml-2.0],
           [AC_DEFINE([USE_LIBXML2], [1], [Use libxml2])])])])
AM_CONDITIONAL([USE_RUST], [test "x$with_rust" == "xyes"])

LT_INIT


# Cryptographic libraries, for hashing

AC_ARG_WITH([gcrypt],
  AS_HELP_STRING([--without-gcrypt], [do not use gcrypt]))
AC_ARG_WITH([nettle],
  AS_HELP_STRING([--without-nettle], [do not use nettle]))

AS_IF([test "x$with_gcrypt" != "xno"],
  [AM_PATH_LIBGCRYPT([],
    [AC_DEFINE([HAVE_GCRYPT], [1], [Libgcrypt is available])])])

AS_IF([test "x$with_gcrypt" == "xno" -a "x$with_nettle" != "xno"],
  [PKG_CHECK_MODULES([NETTLE], [nettle],
    [AC_DEFINE([HAVE_NETTLE], [1], [Libnettle is available])])])

AS_IF([test "x$with_gcrypt" == "xno" -a "x$with_nettle" == "xno"],
  [PKG_CHECK_MODULES([OPENSSL], [openssl],
    [AC_DEFINE([HAVE_OPENSSL], [1], [OpenSSL is available])])])


# libnice (+ glib) and libsrtp for media calls, optional

AC_ARG_ENABLE([calls], AS_HELP_STRING([--disable-calls],
                       [build without Jingle media call support]))
AC_ARG_WITH([opus],
        AS_HELP_STRING([--without-opus], [Do not use libopus]))
AS_IF([test "x$enable_calls" != "xno"],
      [PKG_CHECK_MODULES([NICE], [nice],
         [AC_DEFINE([HAVE_NICE], [1], [libnice is available])])
       PKG_CHECK_MODULES([GLIB], [glib-2.0],
         [AC_DEFINE([HAVE_GLIB], [1], [glib is available])])
       PKG_CHECK_MODULES([SRTP], [libsrtp2],
         [AC_DEFINE([HAVE_SRTP], [1], [libsrtp2 is available])])
       PKG_CHECK_MODULES([PORTAUDIO], [portaudio-2.0],
         [AC_DEFINE([HAVE_PORTAUDIO], [1], [portaudio-2.0 is available])])
       AS_IF([test "x$with_opus" != "xno"],
         PKG_CHECK_MODULES([OPUS], [opus],
           [AC_DEFINE([HAVE_OPUS], [1], [libopus is available])]))
       AC_DEFINE([ENABLE_CALLS], [1], [Jingle ICE-UDP DTLS-SRTP calls are enabled])])

# GSASL, optional

AC_ARG_WITH([gsasl],
        AS_HELP_STRING([--without-gsasl], [Don't use libgsasl for SASL]))
AS_IF([test "x$with_gsasl" != "xno"],
      [PKG_CHECK_MODULES([GSASL], [libgsasl], [AC_DEFINE([HAVE_GSASL], [1], [GSASL is available])])])

# DNS: libunbound or c-ares, optional

AC_ARG_VAR([DNSSEC_TRUST_ANCHOR_FILE],
        [A DNSSEC trust anchor, containing DNSKEY in zone file format])
AS_IF([test "x$DNSSEC_TRUST_ANCHOR_FILE" == "x"],
      [DNSSEC_TRUST_ANCHOR_FILE="/usr/share/dns/root.key"])
AC_DEFINE_UNQUOTED([DNSSEC_TRUST_ANCHOR_FILE],
        "$DNSSEC_TRUST_ANCHOR_FILE",
        [A DNSSEC trust anchor, containing DNSKEY in zone file format])

AC_ARG_WITH([unbound],
        AS_HELP_STRING([--without-unbound], [don't use libunbound]))
AC_ARG_WITH([cares],
        AS_HELP_STRING([--with-cares], [use c-ares]))

AS_IF([test "x$with_unbound" != "xno"],
      [PKG_CHECK_MODULES([UNBOUND], [libunbound],
        [AC_DEFINE([USE_UNBOUND], [1], [Use libunbound])])])
AS_IF([test "x$with_cares" == "xyes"],
      [PKG_CHECK_MODULES([CARES], [libcares],
        [AC_DEFINE([USE_CARES], [1], [Use c-ares])])])

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

# curl, optional

AC_ARG_WITH([curl],
        AS_HELP_STRING([--without-curl], [don't use curl for HTTP file upload]))
AS_IF([test "x$with_curl" != "xno"],
      [PKG_CHECK_MODULES([CURL], [libcurl],
        AC_DEFINE([HAVE_CURL], [1], [curl is available]))])


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
