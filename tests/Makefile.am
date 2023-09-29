AM_CFLAGS = -Werror -Wall -Wextra -pedantic -std=gnu99

COMMON_FLAGS = $(AM_CFLAGS) $(LIBXML_CFLAGS) $(EXPAT_CFLAGS) \
	$(GNUTLS_CFLAGS) $(LIBDANE_CFLAGS) $(OPENSSL_CFLAGS) \
	$(GSASL_CFLAGS) $(UNBOUND_CFLAGS) $(CARES_CFLAGS) $(GPGME_CFLAGS) \
	$(ICU_I18N_CFLAGS) $(LIBGCRYPT_CFLAGS) $(CURL_CFLAGS) \
	$(NICE_CFLAGS) $(GLIB_CFLAGS) $(SRTP_CFLAGS) \
	$(PORTAUDIO_CFLAGS) $(OPUS_CFLAGS) $(NETTLE_CFLAGS)
COMMON_LDADD = -L$(top_builddir)/src -lrexmpp

send_to_self_CFLAGS = $(COMMON_FLAGS)
xml_parse_and_print_CFLAGS = $(COMMON_FLAGS)
xml_print_and_parse_CFLAGS = $(COMMON_FLAGS)
base64_CFLAGS = $(COMMON_FLAGS)

send_to_self_LDADD = $(COMMON_LDADD)
xml_parse_and_print_LDADD = $(COMMON_LDADD)
xml_print_and_parse_LDADD = $(COMMON_LDADD)
base64_LDADD = $(COMMON_LDADD)

check_PROGRAMS = send_to_self \
	xml_parse_and_print xml_print_and_parse base64
TESTS = send_to_self \
	xml_parse_and_print xml_print_and_parse base64
