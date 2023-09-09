AM_CFLAGS = -Werror -Wall -Wextra -pedantic -std=gnu99

lib_LTLIBRARIES = librexmpp.la

librexmpp_la_SOURCES = rexmpp_roster.h rexmpp_roster.c \
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
	rexmpp_xml.h rexmpp_xml.c \
	rexmpp_utf8.h

include_HEADERS = config.h rexmpp_roster.h rexmpp_tcp.h rexmpp_socks.h rexmpp.h \
	rexmpp_dns.h rexmpp_tls.h rexmpp_jid.h rexmpp_openpgp.h rexmpp_console.h \
	rexmpp_pubsub.h rexmpp_http_upload.h rexmpp_jingle.h rexmpp_base64.h \
	rexmpp_sasl.h rexmpp_xml.h rexmpp_utf8.h rexmpp_xml_parser.h
librexmpp_la_CFLAGS = $(AM_CFLAGS) $(LIBXML2_CFLAGS) $(EXPAT_CFLAGS) \
	$(GNUTLS_CFLAGS) $(LIBDANE_CFLAGS) $(OPENSSL_CFLAGS) \
	$(GSASL_CFLAGS) $(UNBOUND_CFLAGS) $(CARES_CFLAGS) $(GPGME_CFLAGS) \
	$(ICU_I18N_CFLAGS) $(LIBGCRYPT_CFLAGS) $(CURL_CFLAGS) \
	$(NICE_CFLAGS) $(GLIB_CFLAGS) $(SRTP_CFLAGS)
librexmpp_la_LIBADD = $(LIBXML2_LIBS) $(EXPAT_LIBS) \
	$(GNUTLS_LIBS) $(LIBDANE_LIBS) $(OPENSSL_LIBS) \
	$(GSASL_LIBS) $(UNBOUND_LIBS) $(CARES_LIBS) $(GPGME_LIBS) $(ICU_I18N_LIBS) \
	$(LIBGCRYPT_LIBS) $(CURL_LIBS) $(NICE_LIBS) $(GLIB_LIBS) $(SRTP_LIBS)
librexmpp_la_LDFLAGS = []

if USE_RUST
target_debug_librexmpp_rust_a_SOURCES = \
	rexmpp_rust.rs rexmpp.rs rexmpp_jid.rs rexmpp_dns.rs rexmpp_tcp.rs \
	rexmpp_socks.rs rexmpp_xml.rs rexmpp_xml_parser.rs
noinst_LIBRARIES = target/debug/librexmpp_rust.a
librexmpp_la_LIBADD += target/debug/librexmpp_rust.a
librexmpp_la_LDFLAGS += -L. -lpthread -ldl

target/debug/librexmpp_rust.a: $(target_debug_librexmpp_rust_a_SOURCES)
	$(CARGO) build

else
librexmpp_la_SOURCES += rexmpp_tcp.h rexmpp_tcp.c \
	rexmpp_socks.h rexmpp_socks.c \
	rexmpp_xml_parser.h rexmpp_xml_parser.c
endif
