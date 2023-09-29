/**
   @file rexmpp_digest.c
   @brief Cryptographic functions
   @author defanor <defanor@uberspace.net>
   @date 2023
   @copyright MIT license.
*/

#include "config.h"
#include "rexmpp_digest.h"

#if defined(HAVE_GCRYPT)
#include <gcrypt.h>
#elif defined(HAVE_NETTLE)
#include <nettle/nettle-meta.h>
#include <stdlib.h>
#elif defined(HAVE_OPENSSL)
#include <openssl/evp.h>
#endif

size_t rexmpp_digest_len (rexmpp_digest_algorithm algo) {
  switch (algo) {
  case REXMPP_DIGEST_SHA1: return 20;
  case REXMPP_DIGEST_SHA256: return 32;
  case REXMPP_DIGEST_SHA3_256: return 32;
  default: return 0;
  }
}

int rexmpp_digest_buffer (rexmpp_digest_algorithm algo,
                          const void *in,
                          size_t in_len,
                          void *out,
                          size_t out_len)
{
  rexmpp_digest_t ctx;
  int err = rexmpp_digest_init(&ctx, algo);
  if (err) {
    return err;
  }
  err = rexmpp_digest_update(&ctx, in, in_len);
  if (err) {
    return err;
  }
  return rexmpp_digest_finish(&ctx, out, out_len);
}

int rexmpp_digest_init (rexmpp_digest_t *ctx, rexmpp_digest_algorithm algo) {
#if defined(HAVE_GCRYPT)
  int gcry_algo = GCRY_MD_NONE;
  switch (algo) {
  case REXMPP_DIGEST_SHA1: gcry_algo = GCRY_MD_SHA1; break;
  case REXMPP_DIGEST_SHA256: gcry_algo = GCRY_MD_SHA256; break;
  case REXMPP_DIGEST_SHA3_256: gcry_algo = GCRY_MD_SHA3_256; break;
  default: return -1;
  }
  gcry_error_t err = gcry_md_open(ctx, gcry_algo, 0);
  if (err != GPG_ERR_NO_ERROR) {
    return -1;
  }
#elif defined(HAVE_NETTLE)
  ctx->nh = NULL;
  switch (algo) {
  case REXMPP_DIGEST_SHA1: ctx->nh = &nettle_sha1; break;
  case REXMPP_DIGEST_SHA256: ctx->nh = &nettle_sha256; break;
  case REXMPP_DIGEST_SHA3_256: ctx->nh = &nettle_sha3_256; break;
  default: return -1;
  }
  ctx->nh_ctx = malloc(ctx->nh->context_size);
  ctx->nh->init(ctx->nh_ctx);
#elif defined(HAVE_OPENSSL)
  const EVP_MD *md = NULL;
  switch (algo) {
  case REXMPP_DIGEST_SHA1: md = EVP_sha1(); break;
  case REXMPP_DIGEST_SHA256: md = EVP_sha256(); break;
  case REXMPP_DIGEST_SHA3_256: md = EVP_sha3_256(); break;
  default: return -1;
  }
  *ctx = EVP_MD_CTX_new();
  if (! EVP_DigestInit(*ctx, md)) {
    EVP_MD_CTX_free(*ctx);
    return -1;
  }
#endif
  return 0;
}

int rexmpp_digest_update (rexmpp_digest_t *ctx, const void *in, size_t len) {
#if defined(HAVE_GCRYPT)
  gcry_md_write(*ctx, in, len);
#elif defined(HAVE_NETTLE)
  ctx->nh->update(ctx->nh_ctx, len, in);
#elif defined(HAVE_OPENSSL)
  if (! EVP_DigestUpdate(*ctx, in, len)) {
    return -1;
  }
#endif
  return 0;
}

int rexmpp_digest_finish (rexmpp_digest_t *ctx, void *out, size_t len) {
  int ret = 0;
#if defined(HAVE_GCRYPT)
  if (out != NULL) {
    unsigned char *result = gcry_md_read(*ctx, 0);
    if (result != NULL) {
      memcpy(out, result, len);
    } else {
      ret = -1;
    }
  }
  gcry_md_close(*ctx);
#elif defined(HAVE_NETTLE)
  ctx->nh->digest(ctx->nh_ctx, len, out);
  free(ctx->nh_ctx);
#elif defined(HAVE_OPENSSL)
  (void)len;
  if (! EVP_DigestFinal_ex(*ctx, out, NULL)) {
    ret = -1;
  }
  EVP_MD_CTX_free(*ctx);
  *ctx = NULL;
#endif
  return ret;
}
