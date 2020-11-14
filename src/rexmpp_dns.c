/**
   @file rexmpp_dns.c
   @brief DNS helper functions
   @author defanor <defanor@uberspace.net>
   @date 2020
   @copyright MIT license.
*/

#include "rexmpp_dns.h"
#include <memory.h>

/* https://tools.ietf.org/html/rfc1035#section-3.1 */
int rexmpp_parse_srv (char *in, int in_len, struct rexmpp_dns_srv *out) {
  int i;
  char *name;
  if (in_len < 7 || in_len > 255 + 6) {
    return -1;
  }
  out->priority = in[0] * 0x100 + in[1];
  out->weight = in[2] * 0x100 + in[3];
  out->port = in[4] * 0x100 + in[5];
  name = in + 6;
  i = 0;
  while (name[i]) {
    if (i + name[i] < 255) {
      memcpy(out->target + i, name + i + 1, name[i]);
      i += name[i];
      out->target[i] = '.';
      i++;
      out->target[i] = '\0';
    } else {
      return -1;
    }
  }
  return 0;
}
