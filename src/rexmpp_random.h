/**
   @file rexmpp_random.h
   @brief Random generation
   @author defanor <defanor@uberspace.net>
   @date 2023
   @copyright MIT license.
*/

#ifndef REXMPP_RANDOM_H
#define REXMPP_RANDOM_H

/**
   @brief Fills a buffer with cryptographically-secure random data.
   @param[out] buf A buffer to write into.
   @param[in] len The number of bytes to fill.

   Uses arc4random_buf or gcry_create_nonce, depending on what is
   available.
*/
void rexmpp_random_buf (void *buf, size_t len);

/**
   @brief Generates a random ASCII identifier.
   @returns A null-terminated string, which must be freed by the
   caller.
*/
char *rexmpp_random_id ();

#endif
