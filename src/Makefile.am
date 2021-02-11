AM_CFLAGS = -Werror -Wall -Wextra -pedantic -std=gnu99 \
	-Wno-pointer-sign

# -Wno-pointer-sign is used to suppress libxml2-related warnings.
# Since we only care about UTF-8, and in almost all cases just its
# ASCII subset (comparing or setting fixed namespaces, element names,
# etc), it shouldn't matter. Later it would be nice to abstract XML
# manipulations anyway, to allow libexpat as an alternative.

lib_LTLIBRARIES = librexmpp.la

librexmpp_la_SOURCES = rexmpp_roster.h rexmpp_roster.c \
	rexmpp_tcp.h rexmpp_tcp.c \
	rexmpp_socks.h rexmpp_socks.c \
	rexmpp.h rexmpp.c \
	rexmpp_dns.h rexmpp_dns.c \
	rexmpp_jid.h rexmpp_jid.c \
	rexmpp_openpgp.h rexmpp_openpgp.c \
	rexmpp_console.h rexmpp_console.c
include_HEADERS = rexmpp_roster.h rexmpp_tcp.h rexmpp_socks.h rexmpp.h \
	rexmpp_dns.h rexmpp_jid.h rexmpp_openpgp.h rexmpp_console.h
librexmpp_la_CFLAGS = $(AM_CFLAGS) $(LIBXML_CFLAGS) $(GNUTLS_CFLAGS) \
	$(LIBDANE_CFLAGS) $(GSASL_CFLAGS) $(UNBOUND_CFLAGS) $(GPGME_CFLAGS)
	$(ICU_I18N_CFLAGS)
librexmpp_la_LIBADD = $(LIBXML_LIBS) $(GNUTLS_LIBS) $(LIBDANE_LIBS) \
	$(GSASL_LIBS) $(UNBOUND_LIBS) $(GPGME_LIBS) $(ICU_I18N_LIBS)
