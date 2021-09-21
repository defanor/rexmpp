AM_CFLAGS = -Werror -Wall -Wextra -pedantic -std=gnu99 \
	-Wno-pointer-sign \
	-Wno-stringop-truncation -Wno-stringop-overflow -Wno-maybe-uninitialized

# -Wno-pointer-sign is used to suppress libxml2-related warnings.
# Since we only care about UTF-8, and in almost all cases just its
# ASCII subset (comparing or setting fixed namespaces, element names,
# etc), it shouldn't matter. Later it would be nice to abstract XML
# manipulations anyway, to allow libexpat as an alternative.

# -Wno-stringop-truncation, -Wno-stringop-overflow, and
# -Wno-maybe-uninitialized are added because newer GCC versions
# started complaining about the bits that are fine, though rewriting
# those bits in a way that doesn't make GCC unhappy may be useful for
# catching actual bugs with those warnings.


lib_LTLIBRARIES = librexmpp.la

librexmpp_la_SOURCES = rexmpp_roster.h rexmpp_roster.c \
	rexmpp_tcp.h rexmpp_tcp.c \
	rexmpp_socks.h rexmpp_socks.c \
	rexmpp.h rexmpp.c \
	rexmpp_dns.h rexmpp_dns.c \
	rexmpp_tls.h rexmpp_tls.c \
	rexmpp_jid.h rexmpp_jid.c \
	rexmpp_openpgp.h rexmpp_openpgp.c \
	rexmpp_console.h rexmpp_console.c \
	rexmpp_pubsub.h rexmpp_pubsub.c
include_HEADERS = config.h rexmpp_roster.h rexmpp_tcp.h rexmpp_socks.h rexmpp.h \
	rexmpp_dns.h rexmpp_tls.h rexmpp_jid.h rexmpp_openpgp.h rexmpp_console.h \
	rexmpp_pubsub.h
librexmpp_la_CFLAGS = $(AM_CFLAGS) $(LIBXML_CFLAGS) \
	$(GNUTLS_CFLAGS) $(LIBDANE_CFLAGS) $(OPENSSL_CFLAGS) \
	$(GSASL_CFLAGS) $(UNBOUND_CFLAGS) $(GPGME_CFLAGS) \
	$(ICU_I18N_CFLAGS) $(NETTLE_CFLAGS)
librexmpp_la_LIBADD = $(LIBXML_LIBS) \
	$(GNUTLS_LIBS) $(LIBDANE_LIBS) $(OPENSSL_LIBS) \
	$(GSASL_LIBS) $(UNBOUND_LIBS) $(GPGME_LIBS) $(ICU_I18N_LIBS) \
	$(NETTLE_LIBS)
