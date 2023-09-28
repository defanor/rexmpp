/**
   @file rexmpp_digest.h
   @brief Cryptographic functions
   @author defanor <defanor@uberspace.net>
   @date 2023
   @copyright MIT license.
*/

#ifndef REXMPP_DIGEST_H
#define REXMPP_DIGEST_H

typedef enum {
  REXMPP_DIGEST_SHA1,
  REXMPP_DIGEST_SHA256,
  REXMPP_DIGEST_SHA3_256
} rexmpp_digest_algorithm;


#if defined(HAVE_GCRYPT)
#include <gcrypt.h>
typedef gcry_md_hd_t rexmpp_digest_t;
#elif defined(HAVE_NETTLE)
#include <nettle/nettle-meta.h>
struct rexmpp_digest {
  const struct nettle_hash *nh;
  void *nh_ctx;
};
typedef struct rexmpp_digest rexmpp_digest_t;
#elif defined(HAVE_OPENSSL)
#include <openssl/evp.h>
typedef EVP_MD_CTX* rexmpp_digest_t;
#endif

size_t rexmpp_digest_len (rexmpp_digest_algorithm algo);
int rexmpp_digest_buffer (rexmpp_digest_algorithm algo,
                          const void *in,
                          size_t in_len,
                          void *out,
                          size_t out_len);
int rexmpp_digest_init (rexmpp_digest_t *ctx, rexmpp_digest_algorithm algo);
int rexmpp_digest_update (rexmpp_digest_t *ctx, const void *in, size_t len);
int rexmpp_digest_finish (rexmpp_digest_t *ctx, void *out, size_t len);

#endif
