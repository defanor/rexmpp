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

#define DTLS_SRTP_BUF_SIZE 0x4000

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
   @brief Channel binding type
*/
enum rexmpp_tls_cb {
  REXMPP_TLS_CB_UNIQUE,
  REXMPP_TLS_CB_SERVER_END_POINT,
  REXMPP_TLS_CB_EXPORTER
};

typedef enum rexmpp_tls_cb rexmpp_tls_cb_t;

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
  char dtls_buf[DTLS_SRTP_BUF_SIZE];
  size_t dtls_buf_len;
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
  BIO *bio_conn;
  BIO *bio_io;
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

rexmpp_tls_t *rexmpp_tls_ctx_new (rexmpp_t *s, int dtls);
void rexmpp_tls_ctx_free (rexmpp_tls_t *tls_ctx);

void rexmpp_tls_session_free (rexmpp_tls_t *tls_ctx);

rexmpp_tls_err_t rexmpp_tls_connect (rexmpp_t *s);
rexmpp_tls_err_t rexmpp_tls_handshake (rexmpp_t *s, rexmpp_tls_t *tls_ctx);
rexmpp_tls_err_t rexmpp_tls_disconnect (rexmpp_t *s, rexmpp_tls_t *tls_ctx);
#ifdef ENABLE_CALLS
rexmpp_tls_err_t
rexmpp_dtls_connect (rexmpp_t *s,
                     rexmpp_tls_t *tls_ctx,
                     void *user_data,
                     int client);
void rexmpp_dtls_feed(rexmpp_t *s, rexmpp_tls_t *tls_ctx, uint8_t *buf, size_t len);

int
rexmpp_tls_srtp_get_keys (rexmpp_t *s,
                          rexmpp_tls_t *tls_ctx,
                          size_t key_len,
                          size_t salt_len,
                          unsigned char *key_mat);
#endif

int rexmpp_tls_get_channel_binding_data
  (rexmpp_t *s,
   rexmpp_tls_t *tls_ctx,
   rexmpp_tls_cb_t cb_type,
   unsigned char *cb_data);

rexmpp_tls_err_t
rexmpp_tls_send (rexmpp_t *s,
                 rexmpp_tls_t *tls_ctx,
                 void *data,
                 size_t data_size,
                 ssize_t *written);
rexmpp_tls_err_t
rexmpp_tls_recv (rexmpp_t *s,
                 rexmpp_tls_t *tls_ctx,
                 void *data,
                 size_t data_size,
                 ssize_t *received);
#ifdef ENABLE_CALLS
unsigned  int rexmpp_dtls_timeout (rexmpp_t *s, rexmpp_tls_t *tls_ctx);
#endif
int rexmpp_tls_fds(rexmpp_t *s, fd_set *read_fds, fd_set *write_fds);

/**
   @brief Sets credentials for a given TLS context: either provided
   ones or defined for the whole ::rexmpp structure.
*/
rexmpp_tls_err_t
rexmpp_tls_set_x509_key_file (rexmpp_t *s,
                              rexmpp_tls_t *tls_ctx,
                              const char *cert_file,
                              const char *key_file);

rexmpp_tls_err_t
rexmpp_tls_set_x509_trust_file (rexmpp_t *s,
                                rexmpp_tls_t *tls_ctx,
                                const char *cert_file);

int rexmpp_tls_peer_fp (rexmpp_t *s,
                        rexmpp_tls_t *tls_ctx,
                        const char *algo_str,
                        char *raw_fp,
                        char *fp_str,
                        size_t *fp_size);

int rexmpp_tls_my_fp (rexmpp_t *s,
                      char *raw_fp,
                      char *fp_str,
                      size_t *fp_size);

int rexmpp_tls_session_fp (rexmpp_t *s,
                           rexmpp_tls_t *tls_ctx,
                           const char *algo_str,
                           char *raw_fp,
                           char *fp_str,
                           size_t *fp_size);

int rexmpp_x509_cert_fp (rexmpp_t *s,
                         const char *algo_str,
                         void *cert,
                         char *raw_fp,
                         char *fp_str,
                         size_t *fp_size);

int rexmpp_x509_raw_cert_fp (rexmpp_t *s,
                             const char *algo_str,
                             const void *raw_cert,
                             char *raw_fp,
                             char *fp_str,
                             size_t *fp_size);

#endif
