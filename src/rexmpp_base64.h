/**
   @file rexmpp_base64.h
   @brief Base64 implementation
   @author defanor <defanor@uberspace.net>
   @date 2021
   @copyright MIT license.

   Implements RFC 4648, with API similar to gsasl's.
*/

#include <stddef.h>

int rexmpp_base64_to (const char *in, size_t in_len, char **out, size_t *out_len);
int rexmpp_base64_from (const char *in, size_t in_len, char **out, size_t *out_len);
