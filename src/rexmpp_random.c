/**
   @file rexmpp_random.c
   @brief Random generation
   @author defanor <defanor@uberspace.net>
   @date 2023
   @copyright MIT license.
*/

#include "config.h"

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
