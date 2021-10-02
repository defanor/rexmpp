/**
   @file rexmpp_base64.c
   @brief Base64 implementation
   @author defanor <defanor@uberspace.net>
   @date 2021
   @copyright MIT license.

   Implements RFC 4648.
*/

#include <stdlib.h>
#include <stddef.h>

#include "rexmpp_base64.h"


char map_range (char x, char from_start, char from_end, char to_start, char otherwise) {
  if (x >= from_start && x <= from_end) {
    return (to_start + x - from_start);
  } else {
    return otherwise;
  }
}

char to_b64 (char x) {
  return map_range(x, 0, 25, 'A',
                   map_range(x, 26, 51, 'a',
                             map_range(x, 52, 61, '0',
                                       map_range(x, 62, 62, '+',
                                                 map_range(x, 63, 63, '/',
                                                           '=')))));
}

char from_b64 (char x) {
  return map_range(x, 'A', 'Z', 0,
                   map_range(x, 'a', 'z', 26,
                             map_range(x, '0', '9', 52,
                                       map_range(x, '+', '+', 62,
                                                 map_range(x, '/', '/', 63,
                                                           64)))));
}


int rexmpp_base64_to (const char *in, size_t in_len, char **out, size_t *out_len) {
  if (in_len == 0) {
    return -1;
  }
  if (in == NULL) {
    return -1;
  }
  *out_len = (in_len + 2) / 3 * 4;
  char *res = malloc(*out_len + 1);
  if (res == NULL) {
    return -1;
  }
  res[*out_len] = '\0';
  *out = res;
  while (res < *out + *out_len) {
    char a = in[0];
    char b = in_len > 1 ? in[1] : 0;
    char c = in_len > 2 ? in[2] : 0;
    res[0] = to_b64((a & 0xFC) >> 2);
    res[1] = to_b64(((a & 0x03) << 4) | ((b & 0xF0) >> 4));
    res[2] = in_len > 1 ? to_b64((((b & 0x0F) << 2) | ((c & 0xC0) >> 6))) : '=';
    res[3] = in_len > 2 ? to_b64((c & 0x3F)) : '=';
    in_len -= 3;
    in += 3;
    res += 4;
  }
  return 0;
}

int rexmpp_base64_from (const char *in, size_t in_len, char **out, size_t *out_len) {
  if (in_len == 0) {
    return -1;
  }
  if (in == NULL) {
    return -1;
  }
  if (in_len % 4) {
    return -1;
  }
  *out_len = in_len / 4 * 3;
  char *res = malloc(*out_len);
  if (res == NULL) {
    return -1;
  }
  *out = res;
  while (res < *out + *out_len) {
    char a = from_b64(in[0]);
    char b = from_b64(in[1]);
    char c = in[2] == '=' ? 0 : from_b64(in[2]);
    char d = in[3] == '=' ? 0 : from_b64(in[3]);
    if ((a | b | c | d) & 0xC0) {
      free(*out);
      *out = NULL;
      *out_len = 0;
      return -1;
    }
    res[0] = (a << 2) | ((b & 0x30) >> 4);
    res[1] = ((b & 0x0F) << 4) | ((c & 0x3C) >> 2);
    res[2] = ((c & 0x03) << 6) | d;

    if (in[2] == '=') {
      if (in[3] != '=') {
        free(*out);
        *out = NULL;
        *out_len = 0;
        return -1;
      }
      *out_len = *out_len - 1;
    }
    if (in[3] == '=') {
      if (res + 3 < *out + *out_len) {
        free(*out);
        *out = NULL;
        *out_len = 0;
        return -1;
      }
      *out_len = *out_len - 1;
    }

    in += 4;
    res += 3;
  }
  return 0;
}
