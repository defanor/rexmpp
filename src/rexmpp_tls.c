/**
   @file rexmpp_tls.c
   @brief TLS abstraction
   @author defanor <defanor@uberspace.net>
   @date 2021
   @copyright MIT license.
*/

#include <syslog.h>
#include <string.h>
#include <stdlib.h>

#include "config.h"

#if defined(USE_GNUTLS)
#include <gnutls/gnutls.h>
#include <gnutls/crypto.h>
#include <gnutls/x509.h>
#include <gnutls/dane.h>
#include <gnutls/dtls.h>
#elif defined(USE_OPENSSL)
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/err.h>
#endif

#include "rexmpp.h"
#include "rexmpp_digest.h"
#include "rexmpp_tls.h"

rexmpp_tls_t *rexmpp_jingle_component_dtls(void *p);
ssize_t
rexmpp_jingle_dtls_push_func (void *p, const void *data, size_t size);
int rexmpp_jingle_dtls_pull_timeout_func (void *p,
                                          unsigned int ms);

#if defined(USE_OPENSSL)
rexmpp_tls_err_t rexmpp_process_openssl_ret (rexmpp_t *s,
                                             rexmpp_tls_t *tls_ctx,
                                             const char *func,
                                             int ret)
{
  int err = SSL_get_error(tls_ctx->openssl_conn, ret);
  tls_ctx->openssl_direction = REXMPP_OPENSSL_NONE;
  if (ret == 1) {
    return REXMPP_TLS_SUCCESS;
  } else if (err == SSL_ERROR_WANT_READ) {
    tls_ctx->openssl_direction = REXMPP_OPENSSL_READ;
    return REXMPP_TLS_E_AGAIN;
  } else if (err == SSL_ERROR_WANT_WRITE) {
    tls_ctx->openssl_direction = REXMPP_OPENSSL_WRITE;
    return REXMPP_TLS_E_AGAIN;
  } else {
    rexmpp_log(s, LOG_ERR, "OpenSSL error %d (ret %d) in %s",
               err, ret, func);
    ERR_print_errors_fp(stderr);
    return REXMPP_TLS_E_OTHER;
  }
}
#endif

rexmpp_tls_t *rexmpp_tls_ctx_new (rexmpp_t *s, int dtls) {
  rexmpp_tls_t *tls_ctx = malloc(sizeof(rexmpp_tls_t));
#if defined(USE_GNUTLS)
  (void)dtls;
  int err;
  tls_ctx->tls_session_data = NULL;
  tls_ctx->tls_session_data_size = 0;

  err = gnutls_certificate_allocate_credentials(&(tls_ctx->gnutls_cred));
  if (err) {
    rexmpp_log(s, LOG_CRIT, "gnutls credentials allocation error: %s",
               gnutls_strerror(err));
    return NULL;
  }
  if (! dtls) {
    err = gnutls_certificate_set_x509_system_trust(tls_ctx->gnutls_cred);
  }
  if (err < 0) {
    rexmpp_log(s, LOG_CRIT, "Certificates loading error: %s",
               gnutls_strerror(err));
    return NULL;
  }

  tls_ctx->dtls_buf_len = 0;
#elif defined(USE_OPENSSL)
  tls_ctx->openssl_direction = REXMPP_OPENSSL_NONE;
  tls_ctx->openssl_conn = NULL;
  tls_ctx->openssl_ctx = SSL_CTX_new(dtls
                                     ? DTLS_method()
                                     : TLS_method());
  if (tls_ctx->openssl_ctx == NULL) {
    rexmpp_log(s, LOG_CRIT, "OpenSSL context creation error");
    return NULL;
  }
  SSL_CTX_set_verify(tls_ctx->openssl_ctx, SSL_VERIFY_PEER, NULL);
  if (SSL_CTX_set_default_verify_paths(tls_ctx->openssl_ctx) == 0) {
    rexmpp_log(s, LOG_CRIT,
               "Failed to set default verify paths for OpenSSL context");
    SSL_CTX_free(tls_ctx->openssl_ctx);
    tls_ctx->openssl_ctx = NULL;
    return NULL;
  }
#else
  (void)s;
  (void)dtls;
#endif
  return tls_ctx;
}

void rexmpp_tls_ctx_free (rexmpp_tls_t *tls_ctx) {
#if defined(USE_GNUTLS)
  gnutls_certificate_free_credentials(tls_ctx->gnutls_cred);
  if (tls_ctx->tls_session_data != NULL) {
    free(tls_ctx->tls_session_data);
    tls_ctx->tls_session_data = NULL;
  }
#elif defined(USE_OPENSSL)
  if (tls_ctx->openssl_ctx != NULL) {
    SSL_CTX_free(tls_ctx->openssl_ctx);
  }
  tls_ctx->openssl_ctx = NULL;
#endif
  free(tls_ctx);
}

int rexmpp_tls_init (rexmpp_t *s) {
#if defined(USE_OPENSSL)
  SSL_library_init();
  SSL_load_error_strings();
#endif
  s->tls = rexmpp_tls_ctx_new(s, 0);
  return (s->tls == NULL);
}

void rexmpp_tls_session_free (rexmpp_tls_t *tls_ctx) {
#if defined(USE_GNUTLS)
    gnutls_deinit(tls_ctx->gnutls_session);
#elif defined(USE_OPENSSL)
    if (tls_ctx->openssl_conn != NULL) {
      SSL_free(tls_ctx->openssl_conn);
      tls_ctx->openssl_conn = NULL;
      /* bio_conn is freed implicitly by SSL_free. */
      tls_ctx->bio_conn = NULL;
    }
    if (tls_ctx->bio_io != NULL) {
      BIO_free(tls_ctx->bio_io);
      tls_ctx->bio_io = NULL;
    }
    tls_ctx->openssl_direction = REXMPP_OPENSSL_NONE;
#else
    (void)s;
#endif
}

void rexmpp_tls_cleanup (rexmpp_t *s) {
  if (s->tls_state != REXMPP_TLS_INACTIVE &&
      s->tls_state != REXMPP_TLS_AWAITING_DIRECT) {
    rexmpp_tls_session_free(s->tls);
  }
}

void rexmpp_tls_deinit (rexmpp_t *s) {
  if (s->tls != NULL) {
    rexmpp_tls_ctx_free(s->tls);
    s->tls = NULL;
  }
}

#if defined(USE_GNUTLS)
ssize_t
rexmpp_dtls_jingle_pull_func_gnutls (gnutls_transport_ptr_t p,
                                     void *data,
                                     size_t size)
{
  rexmpp_tls_t *tls_ctx = rexmpp_jingle_component_dtls(p);
  ssize_t received;

  char *tls_buf = tls_ctx->dtls_buf;
  size_t *tls_buf_len = &(tls_ctx->dtls_buf_len);

  rexmpp_tls_err_t ret = REXMPP_TLS_SUCCESS;
  if (*tls_buf_len > 0) {
    if (size >= *tls_buf_len) {
      memcpy(data, tls_buf, *tls_buf_len);
      received = *tls_buf_len;
      *tls_buf_len = 0;
    } else {
      if (size > DTLS_SRTP_BUF_SIZE) {
        size = DTLS_SRTP_BUF_SIZE;
      }
      memcpy(data, tls_buf, size);
      memmove(tls_buf, tls_buf + size, DTLS_SRTP_BUF_SIZE - size);
      received = size;
      *tls_buf_len = *tls_buf_len - size;
    }
  } else {
    ret = REXMPP_TLS_E_AGAIN;
  }

  if (ret == REXMPP_TLS_SUCCESS) {
    return received;
  } else if (ret == REXMPP_TLS_E_AGAIN) {
    gnutls_transport_set_errno(tls_ctx->gnutls_session, EAGAIN);
  }
  return -1;
}
#endif

#if defined(USE_OPENSSL)
long rexmpp_dtls_openssl_bio_cb(BIO *b, int oper, const char *argp,
                                size_t len, int argi,
                                long argl, int ret, size_t *processed) {
  (void)argi;
  (void)argl;
  (void)processed;
  if (oper == BIO_CB_WRITE) {
    rexmpp_jingle_dtls_push_func(BIO_get_callback_arg(b), argp, len);
  }
  return ret;
}
#endif

#if defined(USE_OPENSSL)
int rexmpp_openssl_verify_accept_all (int preverify_ok,
                                      X509_STORE_CTX *x509_ctx)
{
  (void)preverify_ok;
  (void)x509_ctx;
  return 1;
}
#endif

rexmpp_tls_err_t
rexmpp_dtls_connect (rexmpp_t *s,
                     rexmpp_tls_t *tls_ctx,
                     void *user_data,
                     int client) {
#if defined(USE_GNUTLS)
  gnutls_session_t *tls_session = &(tls_ctx->gnutls_session);
  gnutls_init(tls_session,
              (client ? GNUTLS_CLIENT : GNUTLS_SERVER) |
              GNUTLS_DATAGRAM |
              GNUTLS_NONBLOCK);
  if (! client) {
    gnutls_certificate_server_set_request(*tls_session, GNUTLS_CERT_REQUIRE);
  }
  gnutls_set_default_priority(*tls_session);
  rexmpp_tls_set_x509_key_file(s, tls_ctx, NULL, NULL);
  gnutls_credentials_set(*tls_session, GNUTLS_CRD_CERTIFICATE,
                         tls_ctx->gnutls_cred);

  gnutls_transport_set_ptr(*tls_session, user_data);
  gnutls_transport_set_push_function
    (*tls_session, rexmpp_jingle_dtls_push_func);
  gnutls_transport_set_pull_function
    (*tls_session, rexmpp_dtls_jingle_pull_func_gnutls);
  gnutls_transport_set_pull_timeout_function
    (*tls_session, rexmpp_jingle_dtls_pull_timeout_func);
  /* todo: use the profile/crypto-suite from <crypto/> element */
  gnutls_srtp_set_profile(*tls_session, GNUTLS_SRTP_AES128_CM_HMAC_SHA1_80);
  return REXMPP_TLS_SUCCESS;
#elif defined(USE_OPENSSL)
  (void)client;
  int err;
  /* Setup credentials */
  rexmpp_tls_set_x509_key_file(s, tls_ctx, NULL, NULL);
  /* Create a connection. */
  tls_ctx->openssl_conn = SSL_new(tls_ctx->openssl_ctx);
  SSL_set_verify(tls_ctx->openssl_conn,
                 SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT,
                 rexmpp_openssl_verify_accept_all);
  /* Set a BIO */
  BIO_new_bio_pair(&(tls_ctx->bio_conn), 4096, &(tls_ctx->bio_io), 4096);
  BIO_up_ref(tls_ctx->bio_conn);
  SSL_set0_rbio(tls_ctx->openssl_conn, tls_ctx->bio_conn);
  SSL_set0_wbio(tls_ctx->openssl_conn, tls_ctx->bio_conn);
  /* Set a callback to track writes */
  BIO_set_callback_ex(tls_ctx->bio_conn, rexmpp_dtls_openssl_bio_cb);
  BIO_set_callback_arg(tls_ctx->bio_conn, user_data);
  BIO_set_ssl(tls_ctx->bio_conn, tls_ctx->openssl_conn, BIO_NOCLOSE);
  /* Enable SRTP (TODO: support different profiles) */
  err = SSL_set_tlsext_use_srtp(tls_ctx->openssl_conn,
                                "SRTP_AES128_CM_SHA1_80");
  if (err) {
    rexmpp_log(s, LOG_ERR, "Failed to setup SRTP for the DTLS connection");
    return REXMPP_TLS_E_OTHER;
  }
  if (client) {
    err = SSL_connect(tls_ctx->openssl_conn);
  } else {
    err = SSL_accept(tls_ctx->openssl_conn);
  }
  return rexmpp_process_openssl_ret(s, tls_ctx, "rexmpp_dtls_connect", err);
#else
  (void)s;
  (void)tls_ctx;
  (void)user_data;
  (void)client;
  return REXMPP_TLS_E_OTHER;
#endif
}

void rexmpp_dtls_feed(rexmpp_t *s, rexmpp_tls_t *tls_ctx, uint8_t *buf, size_t len) {
#if defined(USE_GNUTLS)
  if (tls_ctx->dtls_buf_len + len < DTLS_SRTP_BUF_SIZE) {
    memcpy(tls_ctx->dtls_buf + tls_ctx->dtls_buf_len, buf, len);
    tls_ctx->dtls_buf_len += len;
  } else {
    rexmpp_log(s, LOG_WARNING, "Dropping a DTLS packet");
  }
#elif defined(USE_OPENSSL)
  (void)s;
  BIO_write(tls_ctx->bio_io, buf, len);
#else
  (void)s;
  (void)tls_ctx;
  (void)buf;
  (void)len;
#endif
}

rexmpp_tls_err_t rexmpp_tls_handshake (rexmpp_t *s, rexmpp_tls_t *tls_ctx) {
#if defined(USE_GNUTLS)
  int ret = gnutls_handshake(tls_ctx->gnutls_session);
  if (ret == 0) {
    return REXMPP_TLS_SUCCESS;
  } else if (ret == GNUTLS_E_AGAIN) {
    return REXMPP_TLS_E_AGAIN;
  } else {
    rexmpp_log(s, LOG_ERR, "Error during a TLS handshake: %s",
               gnutls_strerror(ret));
    return REXMPP_TLS_E_OTHER;
  }
#elif defined(USE_OPENSSL)
  return rexmpp_process_openssl_ret(s, tls_ctx, "rexmpp_tls_handshake",
                                    SSL_do_handshake(tls_ctx->openssl_conn));
#else
  (void)s;
  (void)tls_ctx;
  return REXMPP_TLS_E_OTHER;
#endif
}

rexmpp_tls_err_t
rexmpp_tls_connect (rexmpp_t *s) {
  if (s->x509_key_file != NULL && s->x509_cert_file != NULL) {
    rexmpp_tls_set_x509_key_file(s, s->tls, NULL, NULL);
  }

#if defined(USE_GNUTLS)
  if (s->tls_state != REXMPP_TLS_HANDSHAKE) {
    gnutls_datum_t xmpp_client_protocol =
      {(unsigned char*)"xmpp-client", strlen("xmpp-client")};
    rexmpp_log(s, LOG_DEBUG, "starting TLS");
    gnutls_init(&s->tls->gnutls_session, GNUTLS_CLIENT);
    gnutls_session_set_ptr(s->tls->gnutls_session, s);
    gnutls_alpn_set_protocols(s->tls->gnutls_session, &xmpp_client_protocol, 1, 0);
    gnutls_server_name_set(s->tls->gnutls_session, GNUTLS_NAME_DNS,
                           s->initial_jid.domain,
                           strlen(s->initial_jid.domain));
    gnutls_set_default_priority(s->tls->gnutls_session);
    gnutls_credentials_set(s->tls->gnutls_session, GNUTLS_CRD_CERTIFICATE,
                           s->tls->gnutls_cred);
    gnutls_transport_set_int(s->tls->gnutls_session, s->server_socket);
    gnutls_handshake_set_timeout(s->tls->gnutls_session,
                                 GNUTLS_DEFAULT_HANDSHAKE_TIMEOUT);
    if (s->tls->tls_session_data != NULL) {
      int ret = gnutls_session_set_data(s->tls->gnutls_session,
                                        s->tls->tls_session_data,
                                        s->tls->tls_session_data_size);
      if (ret != GNUTLS_E_SUCCESS) {
        rexmpp_log(s, LOG_WARNING, "Failed to set TLS session data: %s",
                   gnutls_strerror(ret));
        free(s->tls->tls_session_data);
        s->tls->tls_session_data = NULL;
        s->tls->tls_session_data_size = 0;
      }
    }
  }

  int ret = gnutls_handshake(s->tls->gnutls_session);
  if (ret == GNUTLS_E_AGAIN) {
    rexmpp_log(s, LOG_DEBUG, "Waiting for TLS handshake to complete");
    return REXMPP_TLS_E_AGAIN;
  } else if (ret == 0) {
    unsigned int status;

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
      ret = dane_verify_session_crt(NULL, s->tls->gnutls_session, s->server_host,
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

    ret = gnutls_certificate_verify_peers3(s->tls->gnutls_session,
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
      gnutls_bye(s->tls->gnutls_session, GNUTLS_SHUT_RDWR);
      return REXMPP_TLS_E_OTHER;
    }

    if (gnutls_session_is_resumed(s->tls->gnutls_session)) {
      rexmpp_log(s, LOG_INFO, "TLS session is resumed");
    } else {
      if (s->tls->tls_session_data != NULL) {
        rexmpp_log(s, LOG_DEBUG, "TLS session is not resumed");
        free(s->tls->tls_session_data);
        s->tls->tls_session_data = NULL;
      }
      gnutls_session_get_data(s->tls->gnutls_session, NULL,
                              &s->tls->tls_session_data_size);
      s->tls->tls_session_data = malloc(s->tls->tls_session_data_size);
      ret = gnutls_session_get_data(s->tls->gnutls_session, s->tls->tls_session_data,
                                    &s->tls->tls_session_data_size);
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
    s->tls->openssl_conn = SSL_new(s->tls->openssl_ctx);
    if (s->tls->openssl_conn == NULL) {
      rexmpp_log(s, LOG_ERR, "Failed to create an OpenSSL connection object");
      return REXMPP_TLS_E_OTHER;
    }
    if (SSL_set_fd(s->tls->openssl_conn, s->server_socket) == 0) {
      rexmpp_log(s, LOG_ERR, "Failed to set a file descriptor for OpenSSL connection");
      return REXMPP_TLS_E_OTHER;
    }
    if (SSL_set1_host(s->tls->openssl_conn, s->initial_jid.domain) == 0) {
      rexmpp_log(s, LOG_ERR, "Failed to set a hostname for OpenSSL connection");
      return REXMPP_TLS_E_OTHER;
    }
    /* For SNI */
    if (SSL_set_tlsext_host_name(s->tls->openssl_conn, s->initial_jid.domain) == 0) {
      rexmpp_log(s, LOG_ERR, "Failed to set a tlsext hostname for OpenSSL connection");
      return REXMPP_TLS_E_OTHER;
    }
  }
  return rexmpp_process_openssl_ret(s, s->tls, "rexmpp_tls_connect",
                                    SSL_connect(s->tls->openssl_conn));
#else
  rexmpp_log(s, LOG_ERR, "rexmpp is compiled without TLS support");
  return REXMPP_TLS_E_OTHER;
#endif
}

rexmpp_tls_err_t
rexmpp_tls_disconnect (rexmpp_t *s, rexmpp_tls_t *tls_ctx) {
#if defined(USE_GNUTLS)
  int ret = gnutls_bye(tls_ctx->gnutls_session, GNUTLS_SHUT_RDWR);
  if (ret == GNUTLS_E_SUCCESS) {
    return REXMPP_TLS_SUCCESS;
  } else {
    rexmpp_log(s, LOG_WARNING, "Failed to close TLS connection: %s",
               gnutls_strerror(ret));
    return REXMPP_TLS_E_OTHER;
  }
#elif defined(USE_OPENSSL)
  int ret = SSL_shutdown(tls_ctx->openssl_conn);
  if (ret == 0) {
    tls_ctx->openssl_direction = REXMPP_OPENSSL_READ;
    return REXMPP_TLS_E_AGAIN;
  } else {
    return rexmpp_process_openssl_ret(s, tls_ctx,
                                      "rexmpp_tls_disconnect", ret);
  }
#else
  rexmpp_log(s, LOG_ERR, "rexmpp is compiled without TLS support");
  return REXMPP_TLS_E_OTHER;
#endif
}

int
rexmpp_tls_srtp_get_keys (rexmpp_t *s,
                          rexmpp_tls_t *tls_ctx,
                          size_t key_len,
                          size_t salt_len,
                          unsigned char *key_mat)
{
#if defined(USE_GNUTLS)
  int key_mat_size;
  key_mat_size =
    gnutls_srtp_get_keys(tls_ctx->gnutls_session, 
                         key_mat, (key_len + salt_len) * 2,
                         NULL, NULL, NULL, NULL);
  if (key_mat_size == GNUTLS_E_SHORT_MEMORY_BUFFER ||
      key_mat_size < 0) {
    rexmpp_log(s, LOG_ERR,
               "Failed to retrieve DTLS key material for SRTP: %s",
               gnutls_strerror(key_mat_size));
  }
  return 0;
#elif defined(USE_OPENSSL)
  /* https://www.rfc-editor.org/rfc/rfc5764.html */
  const char *extractor = "EXTRACTOR-dtls_srtp";
  int err = SSL_export_keying_material(tls_ctx->openssl_conn,
                                       key_mat, 2 * (key_len + salt_len),
                                       extractor, strlen(extractor),
                                       NULL, 0, 0);
  return rexmpp_process_openssl_ret(s, tls_ctx,
                                    "rexmpp_tls_srtp_get_keys", err);
#else
  (void)s;
  (void)tls_ctx;
  (void)key_len;
  (void)salt_len;
  (void)client_key_wsalt;
  (void)server_key_wsalt;
  return -1;
#endif
}

rexmpp_tls_err_t
rexmpp_tls_send (rexmpp_t *s,
                 rexmpp_tls_t *tls_ctx,
                 void *data,
                 size_t data_size,
                 ssize_t *written)
{
#if defined(USE_GNUTLS)
  *written = -1;
  ssize_t ret = gnutls_record_send(tls_ctx->gnutls_session,
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
  int ret = SSL_write_ex(tls_ctx->openssl_conn, data, data_size,
                         (size_t*)written);
  if (ret > 0) {
    return REXMPP_TLS_SUCCESS;
  } else {
    return rexmpp_process_openssl_ret(s, tls_ctx, "rexmpp_tls_send", ret);
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
rexmpp_tls_recv (rexmpp_t *s,
                 rexmpp_tls_t *tls_ctx,
                 void *data,
                 size_t data_size,
                 ssize_t *received)
{
#if defined(USE_GNUTLS)
  *received = -1;
  ssize_t ret = gnutls_record_recv(tls_ctx->gnutls_session, data, data_size);
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
  int ret = SSL_read_ex(tls_ctx->openssl_conn, data, data_size,
                        (size_t*)received);
  if (ret > 0) {
    return REXMPP_TLS_SUCCESS;
  } else {
    return rexmpp_process_openssl_ret(s, tls_ctx, "rexmpp_tls_recv", ret);
  }
#else
  (void)data;
  (void)data_size;
  (void)received;
  rexmpp_log(s, LOG_ERR, "rexmpp is compiled without TLS support");
  return REXMPP_TLS_E_OTHER;
#endif
}

unsigned int rexmpp_dtls_timeout (rexmpp_t *s, rexmpp_tls_t *tls_ctx) {
  (void)s;
#if defined(USE_GNUTLS)
  return gnutls_dtls_get_timeout(tls_ctx->gnutls_session);
#else
  (void)tls_ctx;
  return -1;
#endif
}

int rexmpp_tls_fds (rexmpp_t *s, fd_set *read_fds, fd_set *write_fds) {
#if defined(USE_GNUTLS)
  if (gnutls_record_get_direction(s->tls->gnutls_session) == 0) {
    FD_SET(s->server_socket, read_fds);
  } else {
    FD_SET(s->server_socket, write_fds);
  }
  return s->server_socket + 1;
#elif defined(USE_OPENSSL)
  if (s->tls->openssl_direction == REXMPP_OPENSSL_READ) {
    FD_SET(s->server_socket, read_fds);
    return s->server_socket + 1;
  }
  if (s->tls->openssl_direction == REXMPP_OPENSSL_WRITE) {
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
                              rexmpp_tls_t *tls_ctx,
                              const char *cert_file,
                              const char *key_file)
{
  if (cert_file == NULL) {
    cert_file = s->x509_cert_file;
  }
  if (key_file == NULL) {
    key_file = s->x509_key_file;
  }
  if (cert_file == NULL || key_file == NULL) {
    rexmpp_log(s, LOG_ERR, "No certificate or key file defined");
    return REXMPP_TLS_E_OTHER;
  }
#if defined(USE_GNUTLS)
  int ret = gnutls_certificate_set_x509_key_file(tls_ctx->gnutls_cred,
                                                 cert_file,
                                                 key_file,
                                                 GNUTLS_X509_FMT_DER);
  if (ret == 0) {
    return REXMPP_TLS_SUCCESS;
  } else {
    rexmpp_log(s, LOG_ERR,
               "Failed to set a key file: %s", gnutls_strerror(ret));
    return REXMPP_TLS_E_OTHER;
  }
#elif defined(USE_OPENSSL)
  if (SSL_CTX_use_certificate_file(tls_ctx->openssl_ctx,
                                   cert_file,
                                   SSL_FILETYPE_ASN1) != 1) {
    rexmpp_log(s, LOG_ERR, "Failed to set a certificate file");
    return REXMPP_TLS_E_OTHER;
  }
  if (SSL_CTX_use_PrivateKey_file(tls_ctx->openssl_ctx,
                                  key_file,
                                  SSL_FILETYPE_ASN1) != 1) {
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
                                rexmpp_tls_t *tls_ctx,
                                const char *trust_file)
{
  if (trust_file == NULL) {
    trust_file = s->x509_trust_file;
  }
  if (trust_file == NULL) {
    rexmpp_log(s, LOG_ERR, "No trust file is defined");
    return REXMPP_TLS_E_OTHER;
  }
#if defined(USE_GNUTLS)
  gnutls_certificate_set_x509_trust_file(tls_ctx->gnutls_cred,
                                         trust_file,
                                         GNUTLS_X509_FMT_DER);
  return REXMPP_TLS_SUCCESS;
#elif defined(USE_OPENSSL)
  if (SSL_CTX_load_verify_locations(tls_ctx->openssl_ctx, trust_file, NULL) != 1) {
    rexmpp_log(s, LOG_ERR, "Failed to set a trusted certificate file");
    return REXMPP_TLS_E_OTHER;
  }
  return REXMPP_TLS_SUCCESS;
#else
  (void)trust_file;
  rexmpp_log(s, LOG_ERR, "rexmpp is compiled without TLS support");
  return REXMPP_TLS_E_OTHER;
#endif
}


int rexmpp_tls_peer_fp (rexmpp_t *s,
                        rexmpp_tls_t *tls_ctx,
                        const char *algo_str,
                        char *raw_fp,
                        char *fp_str,
                        size_t *fp_size)
{
#if defined(USE_GNUTLS)
  unsigned int cert_list_size = 0;
  const gnutls_datum_t *cert_list;
  cert_list =
    gnutls_certificate_get_peers(tls_ctx->gnutls_session, &cert_list_size);
  if (cert_list_size != 1) {
    rexmpp_log(s, LOG_ERR,
               "Unexpected peer certificate list size: %d",
               cert_list_size);
    return -1;
  }
  return rexmpp_x509_raw_cert_fp(s, algo_str, cert_list,
                                 raw_fp, fp_str, fp_size);
#elif defined(USE_OPENSSL)
  if (strcmp(algo_str, "sha-256") != 0) {
    rexmpp_log(s, LOG_ERR,
               "Unsupported hash function algorithm: %s", algo_str);
    return -1;
  }
  X509 *peer_cert = SSL_get0_peer_certificate(tls_ctx->openssl_conn);
  if (peer_cert == NULL) {
    rexmpp_log(s, LOG_ERR, "No peer certificate found");
    return -1;
  }
  unsigned int len;
  X509_digest(peer_cert, EVP_sha256(), (unsigned char*)raw_fp, &len);
  *fp_size = len;
  size_t i;
  for (i = 0; i < *fp_size; i++) {
    snprintf(fp_str + i * 3, 4, "%02X:", raw_fp[i] & 0xFF);
  }
  fp_str[*fp_size * 3 - 1] = 0;
  return 0;
#else
  (void)s;
  (void)tls_ctx;
  (void)algo_str;
  (void)raw_fp;
  (void)fp_str;
  (void)fp_size;
#endif
}

/* TODO: handle different algorithms, and maybe apply this to
   arbitrary files. */
int rexmpp_tls_my_fp (rexmpp_t *s,
                      char *raw_fp,
                      char *fp_str,
                      size_t *fp_size)
{
  rexmpp_digest_t digest_ctx;
  if (rexmpp_digest_init(&digest_ctx, REXMPP_DIGEST_SHA256)) {
    rexmpp_log(s, LOG_ERR, "Failed to initialize a digest object");
    return -1;
  }

  if (s->x509_cert_file == NULL) {
    rexmpp_log(s, LOG_WARNING, "No X.509 certificate file defined");
    return -1;
  }
  FILE *fh = fopen(s->x509_cert_file, "r");
  if (fh == NULL) {
    rexmpp_log(s, LOG_ERR, "Failed to open the X.509 certificate file");
    return -1;
  }
  unsigned char *buf[4096];
  size_t len = fread(buf, 1, 4096, fh);
  while (len > 0) {
    rexmpp_digest_update(&digest_ctx, buf, len);
    len = fread(buf, 1, 4096, fh);
  }
  fclose(fh);

  *fp_size = rexmpp_digest_len(REXMPP_DIGEST_SHA256);
  rexmpp_digest_finish(&digest_ctx, raw_fp, *fp_size);

  size_t i;
  for (i = 0; i < (*fp_size); i++) {
    snprintf(fp_str + i * 3, 4, "%02X:", raw_fp[i] & 0xFF);
  }
  fp_str[(*fp_size) * 3 - 1] = 0;
  return 0;
}

int rexmpp_tls_session_fp (rexmpp_t *s,
                           rexmpp_tls_t *tls_ctx,
                           const char *algo_str,
                           char *raw_fp,
                           char *fp_str,
                           size_t *fp_size)
{
#if defined(USE_GNUTLS)
  gnutls_x509_crt_t *cert_list;
  unsigned int cert_list_size = 0;
  int err =
    gnutls_certificate_get_x509_crt(tls_ctx->gnutls_cred,
                                    0, &cert_list, &cert_list_size);
  if (err) {
    rexmpp_log(s, LOG_ERR,
               "Failed to read own certificate list: %s",
               gnutls_strerror(err));
    return -1;
  }

  err = rexmpp_x509_cert_fp(s, algo_str, cert_list[0], raw_fp, fp_str, fp_size);

  size_t i;
  for (i = 0; i < cert_list_size; i++) {
    gnutls_x509_crt_deinit(cert_list[i]);
  }
  gnutls_free(cert_list);
  return err;
#else
  (void)s;
  (void)tls_ctx;
  (void)algo_str;
  (void)raw_fp;
  (void)fp_str;
  (void)fp_size;
  return -1;
#endif
}

int rexmpp_x509_cert_fp (rexmpp_t *s,
                         const char *algo_str,
                         void *cert,
                         char *raw_fp,
                         char *fp_str,
                         size_t *fp_size)
{
#if defined(USE_GNUTLS)
  gnutls_datum_t raw_cert;
  int err = gnutls_x509_crt_export2(cert, GNUTLS_X509_FMT_DER, &raw_cert);
  if (err != GNUTLS_E_SUCCESS) {
    rexmpp_log(s, LOG_ERR, "Failed to export a certificate: %s",
               gnutls_strerror(err));
    return err;
  }
  err = rexmpp_x509_raw_cert_fp(s, algo_str, &raw_cert, raw_fp, fp_str, fp_size);
  gnutls_free(raw_cert.data);
  return err;
#else
  (void)s;
  (void)algo_str;
  (void)cert;
  (void)raw_fp;
  (void)fp_str;
  (void)fp_size;
  return -1;
#endif
}

int rexmpp_x509_raw_cert_fp (rexmpp_t *s,
                             const char *algo_str,
                             const void *raw_cert,
                             char *raw_fp,
                             char *fp_str,
                             size_t *fp_size)
{
#if defined(USE_GNUTLS)
  const gnutls_datum_t *cert = (const gnutls_datum_t*)raw_cert;
  gnutls_digest_algorithm_t algo = GNUTLS_DIG_UNKNOWN;
  /* gnutls_digest_get_id uses different names, so
     checking manually here. These are SDP options,
     <https://datatracker.ietf.org/doc/html/rfc4572#page-8>. */
  if (strcmp(algo_str, "sha-1") == 0) {
    algo = GNUTLS_DIG_SHA1;
  } else if (strcmp(algo_str, "sha-224") == 0) {
    algo = GNUTLS_DIG_SHA224;
  } else if (strcmp(algo_str, "sha-256") == 0) {
    algo = GNUTLS_DIG_SHA256;
  } else if (strcmp(algo_str, "sha-384") == 0) {
    algo = GNUTLS_DIG_SHA384;
  } else if (strcmp(algo_str, "sha-512") == 0) {
    algo = GNUTLS_DIG_SHA512;
  } else if (strcmp(algo_str, "md5") == 0) {
    algo = GNUTLS_DIG_MD5;
  }
  if (algo == GNUTLS_DIG_UNKNOWN) {
    rexmpp_log(s, LOG_ERR, "Unknown hash algorithm: %s", algo_str);
    return -1;
  }

  int err = gnutls_fingerprint(algo, cert, raw_fp, fp_size);
  if (err != GNUTLS_E_SUCCESS) {
    rexmpp_log(s, LOG_ERR, "Failed to calculate a fingerprint: %s",
               gnutls_strerror(err));
    return -1;
  }
  if (fp_str != NULL) {
    size_t i;
    for (i = 0; i < (*fp_size); i++) {
      snprintf(fp_str + i * 3, 4, "%02X:", raw_fp[i] & 0xFF);
    }
    fp_str[(*fp_size) * 3 - 1] = 0;
  }
  return 0;
#else
  (void)s;
  (void)algo_str;
  (void)raw_cert;
  (void)raw_fp;
  (void)fp_str;
  (void)fp_size;
  return -1;
#endif
}
