/**
   @file rexmpp_utf8.h
   @brief UTF-8 helper functions
   @author defanor <defanor@uberspace.net>
   @date 2023
   @copyright MIT license.
*/

#ifndef REXMPP_UTF8_H
#define REXMPP_UTF8_H

#include <stddef.h>
#include <stdint.h>

#ifdef HAVE_ICU

#include <unicode/utf8.h>
#define REXMPP_U8_NEXT U8_NEXT

#else

#define REXMPP_U8_NEXT(str, pos, len, out) \
  rexmpp_utf8_next(str, &pos, len, &out);

/**
   @brief Similar to libicu's U8_NEXT macros: reads a single UTF-8
   code point, advances the position.
   @param[in] str A string to read.
   @param[in,out] pos Byte position within the string. Advanced by the
   number of bytes read to produce a code point, not advanced on
   failure.
   @param[in] len String length.
   @param[in,out] out A pointer to the location for writing the code
   point.
   @returns 0 on failure, 1 on success.
*/
inline static
void rexmpp_utf8_next (const uint8_t *str,
                       size_t *pos,
                       size_t len,
                       int32_t *out)
{
  if (*pos >= len) {
    *out = -1;
    return;
  }

  if ((str[*pos] & 0x80) == 0
      && *pos + 1 <= len)
    /* U+0000 to U+007F: 0xxxxxxx */
    {
      *out = str[*pos];
      *pos = *pos + 1;
    } else if ((str[*pos] & 0xe0) == 0xc0
               && *pos + 2 <= len
               && (str[*pos + 1] & 0xc0) == 0x80)
    /* U+0080 to U+07FF: 110xxxxx 10xxxxxx */
    {
      *out = (((int32_t)(str[*pos] & 0x1f) << 6)
              | ((int32_t)str[*pos + 1] & 0x3f));
      *pos = *pos + 2;
    } else if ((str[*pos] & 0xf0) == 0xe0
               && *pos + 3 <= len
               && (str[*pos + 1] & 0xc0) == 0x80
               && (str[*pos + 2] & 0xc0) == 0x80)
    /* U+0800 to U+FFFF: 1110xxxx 10xxxxxx 10xxxxxx */
    {
      *out = (((((int32_t)(str[*pos] & 0xf) << 6)
                | ((int32_t)str[*pos + 1] & 0x3f)) << 6)
              | ((int32_t)str[*pos + 2] & 0x3f));
      *pos = *pos + 3;
    } else if ((str[*pos] & 0xf8) == 0xf0
               && *pos + 4 <= len
               && (str[*pos + 1] & 0xc0) == 0x80
               && (str[*pos + 2] & 0xc0) == 0x80
               && (str[*pos + 3] & 0xc0) == 0x80)
    /* U+10000 to U+10FFFF: 11110xxx 10xxxxxx 10xxxxxx 10xxxxxx */
    {
      *out = (((((((int32_t)(str[*pos] & 7) << 6)
                  | ((int32_t)str[*pos + 1] & 0x3f)) << 6)
                | (((int32_t)str[*pos + 2] & 0x3f))) << 6)
              | ((int32_t)str[*pos + 3] & 0x3f));
      *pos = *pos + 4;
    } else
    /* Invalid UTF-8 */
    {
      *out = -1;
    }
}

#endif  /* HAVE_ICU */

#endif  /* REXMPP_UTF8_H */
