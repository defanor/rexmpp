/**
   @file rexmpp_random.c
   @brief Random generation
   @author defanor <defanor@uberspace.net>
   @date 2023
   @copyright MIT license.
*/

#include "config.h"
#include "rexmpp_base64.h"

#ifdef HAVE_GCRYPT
#include <gcrypt.h>
#else
#define _GNU_SOURCE
#include <stdlib.h>
#endif


void rexmpp_random_buf (void *buf, size_t len) {
#ifdef HAVE_GCRYPT
  gcry_create_nonce(buf, len);
#else
  arc4random_buf(buf, len);
#endif
}

char *rexmpp_random_id () {
  char buf_raw[18], *buf_base64 = NULL;
  size_t buf_base64_len = 0;
  rexmpp_random_buf(buf_raw, 18);
  rexmpp_base64_to(buf_raw, 18, &buf_base64, &buf_base64_len);
  return buf_base64;
}
