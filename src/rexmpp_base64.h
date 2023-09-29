/**
   @file rexmpp_base64.h
   @brief Base64 implementation
   @author defanor <defanor@uberspace.net>
   @date 2021
   @copyright MIT license.

   Implements RFC 4648, with API similar to gsasl's.
*/

#include <stddef.h>

/**
   @brief Encodes data in Base64
   @param[in] in Data to encode
   @param[in] in_len Length of the input data
   @param[out] out A pointer to the output buffer; its memory will be
   allocated by the function, the caller receives ownership over it
   @param[out] out_len Length of the produced Base64-encoded string
   @returns 0 on success, a non-zero value otherwise
*/
int rexmpp_base64_to (const char *in, size_t in_len,
                      char **out, size_t *out_len);

/**
   @brief Decodes data from Base64
   @param[in] in Data to decode
   @param[in] in_len Length of the input data
   @param[out] out A pointer to the output buffer; its memory will be
   allocated by the function, the caller receives ownership over it
   @param[out] out_len Length of the decoded string
   @returns 0 on success, a non-zero value otherwise
*/
int rexmpp_base64_from (const char *in, size_t in_len,
                        char **out, size_t *out_len);
