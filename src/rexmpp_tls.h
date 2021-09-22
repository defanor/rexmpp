/**
   @file rexmpp_tls.h
   @brief TLS abstraction
   @author defanor <defanor@uberspace.net>
   @date 2021
   @copyright MIT license.

These functions only alter the rexmpp structure's tls member (in
particular, they don't change other state variables), but use rexmpp_t
to write logs and read other values (including server socket).

*/


#ifndef REXMPP_TLS_H
#define REXMPP_TLS_H

#include <stdint.h>

#include "rexmpp.h"
#include "config.h"

typedef struct rexmpp_tls rexmpp_tls_t;

/**
   @brief TLS operation results.
*/
enum rexmpp_tls_err {
  REXMPP_TLS_SUCCESS,
  REXMPP_TLS_E_AGAIN,
  REXMPP_TLS_E_OTHER
};

typedef enum rexmpp_tls_err rexmpp_tls_err_t;

/**
   @brief TLS context.
*/
#if defined(USE_GNUTLS)
#include <gnutls/gnutls.h>
struct rexmpp_tls {
  void *tls_session_data;
  size_t tls_session_data_size;
  gnutls_session_t gnutls_session;
  gnutls_certificate_credentials_t gnutls_cred;
};
#elif defined(USE_OPENSSL)
#include <openssl/ssl.h>
enum rexmpp_openssl_direction {
  REXMPP_OPENSSL_NONE,
  REXMPP_OPENSSL_READ,
  REXMPP_OPENSSL_WRITE
};
struct rexmpp_tls {
  SSL_CTX *openssl_ctx;
  SSL *openssl_conn;
  enum rexmpp_openssl_direction openssl_direction;
};
#else
struct rexmpp_tls {
  int dummy;
};
#endif

int rexmpp_tls_init(rexmpp_t *s);
void rexmpp_tls_cleanup(rexmpp_t *s);
void rexmpp_tls_deinit(rexmpp_t *s);

rexmpp_tls_err_t rexmpp_tls_connect(rexmpp_t *s);
rexmpp_tls_err_t rexmpp_tls_disconnect(rexmpp_t *s);

rexmpp_tls_err_t rexmpp_tls_send(rexmpp_t *s, void *data, size_t data_size, ssize_t *written);
rexmpp_tls_err_t rexmpp_tls_recv(rexmpp_t *s, void *data, size_t data_size, ssize_t *received);

int rexmpp_tls_fds(rexmpp_t *s, fd_set *read_fds, fd_set *write_fds);

rexmpp_tls_err_t
rexmpp_tls_set_x509_key_file (rexmpp_t *s,
                              const char *cert_file,
                              const char *key_file);

rexmpp_tls_err_t
rexmpp_tls_set_x509_trust_file (rexmpp_t *s,
                                const char *cert_file);


#endif
