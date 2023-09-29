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

/**
   @brief Finds the digest length for a given algorithm.
   @param[in] algo An algorithm.
   @returns Digest length in bytes.
*/
size_t rexmpp_digest_len (rexmpp_digest_algorithm algo);

/**
   @brief Computes a digest for a buffer.
   @param[in] algo An algorithm.
   @param[in] in Input data.
   @param[in] in_len Input data length.
   @param[out] out Output buffer.
   @param[in] out_len Output buffer length.
   @returns 0 on success, non-zero on failure.
*/
int rexmpp_digest_buffer (rexmpp_digest_algorithm algo,
                          const void *in,
                          size_t in_len,
                          void *out,
                          size_t out_len);

/**
   @brief Initializes a digest context.
   @param[out] ctx Pointer to an allocated ::rexmpp_digest_t context
   to initialize.
   @param[in] algo An algorithm to use.
   @returns 0 on success, non-zero on failure.
*/
int rexmpp_digest_init (rexmpp_digest_t *ctx, rexmpp_digest_algorithm algo);

/**
   @brief Updates a digest computation.
   @param[in,out] ctx Context pointer.
   @param[in] in Input data.
   @param[in] len Length of the input buffer.
   @returns 0 on success, non-zero on failure.
*/
int rexmpp_digest_update (rexmpp_digest_t *ctx, const void *in, size_t len);

/**
   @brief Finishes a digest computation, freeing the context and
   providing the output.
   @param[in,out] ctx Context pointer.
   @param[out] out A place to write the computed digest into, can be
   NULL to just free the context.
   @param[in] len Length of the allocated output buffer.
   @returns 0 on success, non-zero on failure.
*/
int rexmpp_digest_finish (rexmpp_digest_t *ctx, void *out, size_t len);

#endif
