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
	rexmpp.h rexmpp.c \
	rexmpp_dns.h rexmpp_dns.c \
	rexmpp_tls.h rexmpp_tls.c \
	rexmpp_jid.h rexmpp_jid.c \
	rexmpp_openpgp.h rexmpp_openpgp.c \
	rexmpp_console.h rexmpp_console.c \
	rexmpp_pubsub.h rexmpp_pubsub.c \
	rexmpp_http_upload.h rexmpp_http_upload.c \
	rexmpp_jingle.h rexmpp_jingle.c \
	rexmpp_base64.h rexmpp_base64.c \
	rexmpp_sasl.h rexmpp_sasl.c \
	rexmpp_xml.h rexmpp_xml.c

include_HEADERS = config.h rexmpp_roster.h rexmpp_tcp.h rexmpp_socks.h rexmpp.h \
	rexmpp_dns.h rexmpp_tls.h rexmpp_jid.h rexmpp_openpgp.h rexmpp_console.h \
	rexmpp_pubsub.h rexmpp_http_upload.h rexmpp_jingle.h rexmpp_base64.h \
	rexmpp_sasl.h rexmpp_xml.h
librexmpp_la_CFLAGS = $(AM_CFLAGS) $(LIBXML_CFLAGS) \
	$(GNUTLS_CFLAGS) $(LIBDANE_CFLAGS) $(OPENSSL_CFLAGS) \
	$(GSASL_CFLAGS) $(UNBOUND_CFLAGS) $(CARES_CFLAGS) $(GPGME_CFLAGS) \
	$(ICU_I18N_CFLAGS) $(LIBGCRYPT_CFLAGS) $(CURL_CFLAGS) \
	$(NICE_CFLAGS) $(GLIB_CFLAGS) $(SRTP_CFLAGS)
librexmpp_la_LIBADD = $(LIBXML_LIBS) \
	$(GNUTLS_LIBS) $(LIBDANE_LIBS) $(OPENSSL_LIBS) \
	$(GSASL_LIBS) $(UNBOUND_LIBS) $(CARES_LIBS) $(GPGME_LIBS) $(ICU_I18N_LIBS) \
	$(LIBGCRYPT_LIBS) $(CURL_LIBS) $(NICE_LIBS) $(GLIB_LIBS) $(SRTP_LIBS)
librexmpp_la_LDFLAGS = []

if USE_RUST
target_debug_librexmpp_rust_a_SOURCES = rexmpp_rust.rs rexmpp_socks.rs rexmpp_xml.rs
noinst_LIBRARIES = target/debug/librexmpp_rust.a
librexmpp_la_LIBADD += target/debug/librexmpp_rust.a
librexmpp_la_LDFLAGS += -L. -lpthread -ldl

target/debug/librexmpp_rust.a: $(target_debug_librexmpp_rust_a_SOURCES)
	$(CARGO) build

else
librexmpp_la_SOURCES += rexmpp_socks.h rexmpp_socks.c
endif
