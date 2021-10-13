/**
   @file rexmpp_tls.c
   @brief TLS abstraction
   @author defanor <defanor@uberspace.net>
   @date 2021
   @copyright MIT license.
*/

#include <syslog.h>
#include <string.h>

#include "config.h"

#if defined(USE_GNUTLS)
#include <gnutls/gnutls.h>
#include <gnutls/crypto.h>
#include <gnutls/x509.h>
#include <gnutls/dane.h>
#elif defined(USE_OPENSSL)
#include <openssl/ssl.h>
#endif

#include "rexmpp.h"
#include "rexmpp_tls.h"

#if defined(USE_OPENSSL)
rexmpp_tls_err_t rexmpp_process_openssl_ret (rexmpp_t *s, int ret) {
  int err = SSL_get_error(s->tls.openssl_conn, ret);
  s->tls.openssl_direction = REXMPP_OPENSSL_NONE;
  if (ret == 1) {
    return REXMPP_TLS_SUCCESS;
  } else if (err == SSL_ERROR_WANT_READ) {
    s->tls.openssl_direction = REXMPP_OPENSSL_READ;
    return REXMPP_TLS_E_AGAIN;
  } else if (err == SSL_ERROR_WANT_WRITE) {
    s->tls.openssl_direction = REXMPP_OPENSSL_WRITE;
    return REXMPP_TLS_E_AGAIN;
  } else {
    rexmpp_log(s, LOG_ERR, "OpenSSL error %d", err);
    return REXMPP_TLS_E_OTHER;
  }
}
#endif

int rexmpp_tls_init (rexmpp_t *s) {
#if defined(USE_GNUTLS)
  int err;
  s->tls.tls_session_data = NULL;
  s->tls.tls_session_data_size = 0;

  err = gnutls_certificate_allocate_credentials(&(s->tls.gnutls_cred));
  if (err) {
    rexmpp_log(s, LOG_CRIT, "gnutls credentials allocation error: %s",
               gnutls_strerror(err));
    return 1;
  }
  err = gnutls_certificate_set_x509_system_trust(s->tls.gnutls_cred);
  if (err < 0) {
    rexmpp_log(s, LOG_CRIT, "Certificates loading error: %s",
               gnutls_strerror(err));
    return 1;
  }
#ifdef ENABLE_CALLS
  err = gnutls_certificate_allocate_credentials(&(s->jingle.dtls_cred));
  if (err) {
    gnutls_certificate_free_credentials(s->tls.gnutls_cred);
    rexmpp_log(s, LOG_CRIT, "gnutls credentials allocation error: %s",
               gnutls_strerror(err));
    return 1;
  }
#endif
  return 0;
#elif defined(USE_OPENSSL)
  SSL_library_init();
  SSL_load_error_strings();
  s->tls.openssl_direction = REXMPP_OPENSSL_NONE;
  s->tls.openssl_conn = NULL;
  s->tls.openssl_ctx = SSL_CTX_new(TLS_client_method());
  if (s->tls.openssl_ctx == NULL) {
    rexmpp_log(s, LOG_CRIT, "OpenSSL context creation error");
    return 1;
  }
  SSL_CTX_set_verify(s->tls.openssl_ctx, SSL_VERIFY_PEER, NULL);
  if (SSL_CTX_set_default_verify_paths(s->tls.openssl_ctx) == 0) {
    rexmpp_log(s, LOG_CRIT, "Failed to set default verify paths for OpenSSL context");
    SSL_CTX_free(s->tls.openssl_ctx);
    s->tls.openssl_ctx = NULL;
    return 1;
  }
  return 0;
#else
  (void)s;
  return 0;
#endif
}


void rexmpp_tls_cleanup (rexmpp_t *s) {
  if (s->tls_state != REXMPP_TLS_INACTIVE &&
      s->tls_state != REXMPP_TLS_AWAITING_DIRECT) {
#if defined(USE_GNUTLS)
    gnutls_deinit(s->tls.gnutls_session);
#elif defined(USE_OPENSSL)
    if (s->tls.openssl_conn != NULL) {
      SSL_free(s->tls.openssl_conn);
      s->tls.openssl_conn = NULL;
    }
    s->tls.openssl_direction = REXMPP_OPENSSL_NONE;
#else
    (void)s;
#endif
  }
}

void rexmpp_tls_deinit (rexmpp_t *s) {
#if defined(USE_GNUTLS)
  gnutls_certificate_free_credentials(s->tls.gnutls_cred);
  if (s->tls.tls_session_data != NULL) {
    free(s->tls.tls_session_data);
    s->tls.tls_session_data = NULL;
  }
#ifdef ENABLE_CALLS
  gnutls_certificate_free_credentials(s->jingle.dtls_cred);
#endif
#elif defined(USE_OPENSSL)
  if (s->tls.openssl_ctx != NULL) {
    SSL_CTX_free(s->tls.openssl_ctx);
  }
  s->tls.openssl_ctx = NULL;
#else
  (void)s;
#endif
}

rexmpp_tls_err_t
rexmpp_tls_connect (rexmpp_t *s) {
#if defined(USE_GNUTLS)
  if (s->tls_state != REXMPP_TLS_HANDSHAKE) {
    gnutls_datum_t xmpp_client_protocol = {"xmpp-client", strlen("xmpp-client")};
    rexmpp_log(s, LOG_DEBUG, "starting TLS");
    gnutls_init(&s->tls.gnutls_session, GNUTLS_CLIENT);
    gnutls_session_set_ptr(s->tls.gnutls_session, s);
    gnutls_alpn_set_protocols(s->tls.gnutls_session, &xmpp_client_protocol, 1, 0);
    gnutls_server_name_set(s->tls.gnutls_session, GNUTLS_NAME_DNS,
                           s->initial_jid.domain,
                           strlen(s->initial_jid.domain));
    gnutls_set_default_priority(s->tls.gnutls_session);
    gnutls_credentials_set(s->tls.gnutls_session, GNUTLS_CRD_CERTIFICATE,
                           s->tls.gnutls_cred);
    gnutls_transport_set_int(s->tls.gnutls_session, s->server_socket);
    gnutls_handshake_set_timeout(s->tls.gnutls_session,
                                 GNUTLS_DEFAULT_HANDSHAKE_TIMEOUT);
    if (s->tls.tls_session_data != NULL) {
      int ret = gnutls_session_set_data(s->tls.gnutls_session,
                                        s->tls.tls_session_data,
                                        s->tls.tls_session_data_size);
      if (ret != GNUTLS_E_SUCCESS) {
        rexmpp_log(s, LOG_WARNING, "Failed to set TLS session data: %s",
                   gnutls_strerror(ret));
        free(s->tls.tls_session_data);
        s->tls.tls_session_data = NULL;
        s->tls.tls_session_data_size = 0;
      }
    }
  }

  int ret = gnutls_handshake(s->tls.gnutls_session);
  if (ret == GNUTLS_E_AGAIN) {
    rexmpp_log(s, LOG_DEBUG, "Waiting for TLS handshake to complete");
    return REXMPP_TLS_E_AGAIN;
  } else if (ret == 0) {
    int status;

    int srv_is_secure = 0;
    if (s->stream_state == REXMPP_STREAM_NONE &&
        s->server_srv_tls != NULL) { /* Direct TLS */
      srv_is_secure = s->server_srv_tls->secure;
    } else if (s->stream_state != REXMPP_STREAM_NONE &&
               s->server_srv != NULL) { /* STARTTLS connection */
      srv_is_secure = s->server_srv->secure;
    }

    /* Check DANE TLSA records; experimental and purely informative
       now, but may be nice to (optionally) rely on it in the
       future. */
    if ((srv_is_secure || s->manual_host != NULL) &&
        s->server_socket_dns_secure) {
      /* Apparently GnuTLS only checks against the target
         server/derived host, while another possibility is a
         service/source host
         (<https://tools.ietf.org/html/rfc7712#section-5.1>,
         <https://tools.ietf.org/html/rfc7673#section-6>). */
      ret = dane_verify_session_crt(NULL, s->tls.gnutls_session, s->server_host,
                                    "tcp", s->server_port, 0, 0, &status);
      if (ret) {
        rexmpp_log(s, LOG_WARNING, "DANE verification error: %s",
                   dane_strerror(ret));
      } else if (status) {
        if (status & DANE_VERIFY_CA_CONSTRAINTS_VIOLATED) {
          rexmpp_log(s, LOG_WARNING, "The CA constraints were violated");
        }
        if (status & DANE_VERIFY_CERT_DIFFERS) {
          rexmpp_log(s, LOG_WARNING, "The certificate obtained via DNS differs");
        }
        if (status & DANE_VERIFY_UNKNOWN_DANE_INFO) {
          rexmpp_log(s, LOG_WARNING,
                     "No known DANE data was found in the DNS record");
        }
      } else {
        rexmpp_log(s, LOG_INFO,
                   "DANE verification did not reject the certificate");
      }
    }

    ret = gnutls_certificate_verify_peers3(s->tls.gnutls_session,
                                           s->initial_jid.domain,
                                           &status);
    if (ret || status) {
      if (ret) {
        rexmpp_log(s, LOG_ERR, "Certificate parsing error: %s",
                   gnutls_strerror(ret));
      } else if (status & GNUTLS_CERT_UNEXPECTED_OWNER) {
        rexmpp_log(s, LOG_ERR, "Unexpected certificate owner");
      } else {
        rexmpp_log(s, LOG_ERR, "Untrusted certificate");
      }
      gnutls_bye(s->tls.gnutls_session, GNUTLS_SHUT_RDWR);
      return REXMPP_TLS_E_OTHER;
    }

    if (gnutls_session_is_resumed(s->tls.gnutls_session)) {
      rexmpp_log(s, LOG_INFO, "TLS session is resumed");
    } else {
      if (s->tls.tls_session_data != NULL) {
        rexmpp_log(s, LOG_DEBUG, "TLS session is not resumed");
        free(s->tls.tls_session_data);
        s->tls.tls_session_data = NULL;
      }
      gnutls_session_get_data(s->tls.gnutls_session, NULL,
                              &s->tls.tls_session_data_size);
      s->tls.tls_session_data = malloc(s->tls.tls_session_data_size);
      ret = gnutls_session_get_data(s->tls.gnutls_session, s->tls.tls_session_data,
                                    &s->tls.tls_session_data_size);
      if (ret != GNUTLS_E_SUCCESS) {
        rexmpp_log(s, LOG_ERR, "Failed to get TLS session data: %s",
                   gnutls_strerror(ret));
        return REXMPP_TLS_E_OTHER;
      }
    }

    return REXMPP_TLS_SUCCESS;
  } else {
    rexmpp_log(s, LOG_ERR, "Unexpected TLS handshake error: %s",
               gnutls_strerror(ret));
    return REXMPP_TLS_E_OTHER;
  }
#elif defined(USE_OPENSSL)
  if (s->tls_state != REXMPP_TLS_HANDSHAKE) {
    s->tls.openssl_conn = SSL_new(s->tls.openssl_ctx);
    if (s->tls.openssl_conn == NULL) {
      rexmpp_log(s, LOG_ERR, "Failed to create an OpenSSL connection object");
      return REXMPP_TLS_E_OTHER;
    }
    if (SSL_set_fd(s->tls.openssl_conn, s->server_socket) == 0) {
      rexmpp_log(s, LOG_ERR, "Failed to set a file descriptor for OpenSSL connection");
      return REXMPP_TLS_E_OTHER;
    }
    if (SSL_set1_host(s->tls.openssl_conn, s->initial_jid.domain) == 0) {
      rexmpp_log(s, LOG_ERR, "Failed to set a hostname for OpenSSL connection");
      return REXMPP_TLS_E_OTHER;
    }
    /* For SNI */
    if (SSL_set_tlsext_host_name(s->tls.openssl_conn, s->initial_jid.domain) == 0) {
      rexmpp_log(s, LOG_ERR, "Failed to set a tlsext hostname for OpenSSL connection");
      return REXMPP_TLS_E_OTHER;
    }
  }
  return rexmpp_process_openssl_ret(s, SSL_connect(s->tls.openssl_conn));
#else
  rexmpp_log(s, LOG_ERR, "rexmpp is compiled without TLS support");
  return REXMPP_TLS_E_OTHER;
#endif
}

rexmpp_tls_err_t
rexmpp_tls_disconnect (rexmpp_t *s) {
#if defined(USE_GNUTLS)
  int ret = gnutls_bye(s->tls.gnutls_session, GNUTLS_SHUT_RDWR);
  if (ret == GNUTLS_E_SUCCESS) {
    return REXMPP_TLS_SUCCESS;
  } else {
    rexmpp_log(s, LOG_WARNING, "Failed to close TLS connection: %s",
               gnutls_strerror(ret));
    return REXMPP_TLS_E_OTHER;
  }
#elif defined(USE_OPENSSL)
  int ret = SSL_shutdown(s->tls.openssl_conn);
  if (ret == 0) {
    s->tls.openssl_direction = REXMPP_OPENSSL_READ;
    return REXMPP_TLS_E_AGAIN;
  } else {
    return rexmpp_process_openssl_ret(s, ret);
  }
#else
  rexmpp_log(s, LOG_ERR, "rexmpp is compiled without TLS support");
  return REXMPP_TLS_E_OTHER;
#endif
}

rexmpp_tls_err_t
rexmpp_tls_send (rexmpp_t *s, void *data, size_t data_size, ssize_t *written)
{
#if defined(USE_GNUTLS)
  *written = -1;
  ssize_t ret = gnutls_record_send(s->tls.gnutls_session,
                                   data,
                                   data_size);
  if (ret >= 0) {
    *written = ret;
    return REXMPP_TLS_SUCCESS;
  } else if (ret == GNUTLS_E_AGAIN) {
    return REXMPP_TLS_E_AGAIN;
  } else {
    rexmpp_log(s, LOG_ERR, "TLS send error: %s", gnutls_strerror(ret));
    return REXMPP_TLS_E_OTHER;
  }
#elif defined(USE_OPENSSL)
  *written = -1;
  int ret = SSL_write_ex(s->tls.openssl_conn, data, data_size, written);
  if (ret > 0) {
    return REXMPP_TLS_SUCCESS;
  } else {
    return rexmpp_process_openssl_ret(s, ret);
  }
#else
  (void)data;
  (void)data_size;
  (void)written;
  rexmpp_log(s, LOG_ERR, "rexmpp is compiled without TLS support");
  return REXMPP_TLS_E_OTHER;
#endif
}

rexmpp_tls_err_t
rexmpp_tls_recv (rexmpp_t *s, void *data, size_t data_size, ssize_t *received) {
#if defined(USE_GNUTLS)
  *received = -1;
  ssize_t ret = gnutls_record_recv(s->tls.gnutls_session, data, data_size);
  if (ret >= 0) {
    *received = ret;
    return REXMPP_TLS_SUCCESS;
  } else if (ret == GNUTLS_E_AGAIN) {
    return REXMPP_TLS_E_AGAIN;
  } else {
    rexmpp_log(s, LOG_ERR, "TLS recv error: %s", gnutls_strerror(ret));
    return REXMPP_TLS_E_OTHER;
  }
#elif defined(USE_OPENSSL)
  *received = -1;
  int ret = SSL_read_ex(s->tls.openssl_conn, data, data_size, received);
  if (ret > 0) {
    return REXMPP_TLS_SUCCESS;
  } else {
    return rexmpp_process_openssl_ret(s, ret);
  }
#else
  (void)data;
  (void)data_size;
  (void)received;
  rexmpp_log(s, LOG_ERR, "rexmpp is compiled without TLS support");
  return REXMPP_TLS_E_OTHER;
#endif
}

int rexmpp_tls_fds (rexmpp_t *s, fd_set *read_fds, fd_set *write_fds) {
#if defined(USE_GNUTLS)
  if (gnutls_record_get_direction(s->tls.gnutls_session) == 0) {
    FD_SET(s->server_socket, read_fds);
  } else {
    FD_SET(s->server_socket, write_fds);
  }
  return s->server_socket + 1;
#elif defined(USE_OPENSSL)
  if (s->tls.openssl_direction == REXMPP_OPENSSL_READ) {
    FD_SET(s->server_socket, read_fds);
    return s->server_socket + 1;
  }
  if (s->tls.openssl_direction == REXMPP_OPENSSL_WRITE) {
    FD_SET(s->server_socket, write_fds);
    return s->server_socket + 1;
  }
  return 0;
#else
  (void)s;
  (void)read_fds;
  (void)write_fds;
  return 0;
#endif
}

rexmpp_tls_err_t
rexmpp_tls_set_x509_key_file (rexmpp_t *s,
                              const char *cert_file,
                              const char *key_file)
{
#if defined(USE_GNUTLS)
  int ret = gnutls_certificate_set_x509_key_file(s->tls.gnutls_cred,
                                                 cert_file,
                                                 key_file,
                                                 GNUTLS_X509_FMT_PEM);
#ifdef ENABLE_CALLS
  gnutls_certificate_set_x509_key_file(s->jingle.dtls_cred,
                                       cert_file,
                                       key_file,
                                       GNUTLS_X509_FMT_PEM);
#endif
  if (ret == 0) {
    return REXMPP_TLS_SUCCESS;
  } else {
    rexmpp_log(s, LOG_ERR,
               "Failed to set a key file: %s", gnutls_strerror(ret));
    return REXMPP_TLS_E_OTHER;
  }
#elif defined(USE_OPENSSL)
  if (SSL_CTX_use_certificate_file(s->tls.openssl_ctx,
                                   cert_file,
                                   SSL_FILETYPE_PEM) != 1) {
    rexmpp_log(s, LOG_ERR, "Failed to set a certificate file");
    return REXMPP_TLS_E_OTHER;
  }
  if (SSL_CTX_use_PrivateKey_file(s->tls.openssl_ctx,
                                  key_file,
                                  SSL_FILETYPE_PEM) != 1) {
    rexmpp_log(s, LOG_ERR, "Failed to set a key file");
    return REXMPP_TLS_E_OTHER;
  }
  return REXMPP_TLS_SUCCESS;
#else
  (void)cert_file;
  (void)key_file;
  rexmpp_log(s, LOG_ERR, "rexmpp is compiled without TLS support");
  return REXMPP_TLS_E_OTHER;
#endif
}

rexmpp_tls_err_t
rexmpp_tls_set_x509_trust_file (rexmpp_t *s,
                                const char *cert_file)
{
#if defined(USE_GNUTLS)
  gnutls_certificate_set_x509_trust_file(s->tls.gnutls_cred,
                                         cert_file,
                                         GNUTLS_X509_FMT_PEM);
  return REXMPP_TLS_SUCCESS;
#elif defined(USE_OPENSSL)
  if (SSL_CTX_load_verify_locations(s->tls.openssl_ctx, cert_file, NULL) != 1) {
    rexmpp_log(s, LOG_ERR, "Failed to set a trusted certificate file");
    return REXMPP_TLS_E_OTHER;
  }
  return REXMPP_TLS_SUCCESS;
#else
  (void)cert_file;
  rexmpp_log(s, LOG_ERR, "rexmpp is compiled without TLS support");
  return REXMPP_TLS_E_OTHER;
#endif
}
